// Fetch a skill's files from a public GitHub URL for check_skill (SPEC §7).
// Resolves the ref to a commit SHA first so the scan is pinned to exact bytes —
// a branch name would let the content change under the verdict.
//
// This is the one place the Worker GETs file BODIES. That's allowed because it's
// the skill's source text, fetched from GitHub's own hosts only (api.github.com,
// raw.githubusercontent.com) and never executed — not an arbitrary target URL,
// which stays HEAD-only per the §11 posture.

import { MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, type SkillFile } from "./skillscan.ts";

export interface GithubTarget {
  owner: string;
  repo: string;
  ref: string | null;
  path: string;
}

export interface GithubFetch {
  files: SkillFile[];
  source: { owner: string; repo: string; commit: string; path: string };
  degraded: string[];
}

/** github.com/{o}/{r}[/tree|blob/{ref}/{path}] → target. Refs containing "/" are
 *  ambiguous in this URL shape; we take the first segment and say so upstream if
 *  the tree lookup then fails. */
export function parseGithubUrl(input: string): GithubTarget | null {
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    return null;
  }
  if (u.hostname !== "github.com" && u.hostname !== "www.github.com") return null;
  const parts = u.pathname.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  const [owner, rawRepo, kind, ref, ...rest] = parts;
  const repo = rawRepo.replace(/\.git$/, "");
  if (!kind) return { owner, repo, ref: null, path: "" };
  if ((kind !== "tree" && kind !== "blob") || !ref) return null;
  let path = rest.join("/");
  // A blob URL pointing at SKILL.md means "this skill's folder".
  if (kind === "blob") path = path.replace(/\/?SKILL\.md$/, "");
  return { owner, repo, ref, path };
}

type Fetcher = typeof fetch;

const API_HEADERS = { "user-agent": "linkcheck-mcp", accept: "application/vnd.github+json" };

export async function fetchSkillFromGithub(target: GithubTarget, doFetch: Fetcher = fetch): Promise<GithubFetch> {
  const { owner, repo, path } = target;
  const base = `https://api.github.com/repos/${owner}/${repo}`;
  const degraded: string[] = [];

  let ref = target.ref;
  if (!ref) {
    const r = await doFetch(base, { headers: API_HEADERS });
    if (!r.ok) throw new Error(githubError(r.status, `${owner}/${repo}`));
    ref = ((await r.json()) as { default_branch: string }).default_branch;
  }

  const c = await doFetch(`${base}/commits/${encodeURIComponent(ref)}`, {
    headers: { ...API_HEADERS, accept: "application/vnd.github.sha" },
  });
  if (!c.ok) throw new Error(githubError(c.status, `${owner}/${repo}@${ref}`));
  const commit = (await c.text()).trim();

  const t = await doFetch(`${base}/git/trees/${commit}?recursive=1`, { headers: API_HEADERS });
  if (!t.ok) throw new Error(githubError(t.status, `tree ${commit}`));
  const tree = (await t.json()) as { tree: Array<{ path: string; type: string; size?: number }>; truncated?: boolean };
  if (tree.truncated) degraded.push("GitHub tree listing truncated — repo too large; some files may be missing");

  const prefix = path ? path.replace(/\/$/, "") + "/" : "";
  let blobs = tree.tree.filter((e) => e.type === "blob" && (prefix === "" || e.path.startsWith(prefix)));
  if (blobs.length === 0) throw new Error(`no files under '${path || "/"}' at ${commit.slice(0, 7)}`);
  if (blobs.length > MAX_FILES) {
    degraded.push(`truncated: ${blobs.length} files, fetched first ${MAX_FILES}`);
    blobs = blobs.slice(0, MAX_FILES);
  }

  const files: SkillFile[] = [];
  let total = 0;
  for (const b of blobs) {
    const rel = b.path.slice(prefix.length);
    if ((b.size ?? 0) > MAX_FILE_BYTES || total + (b.size ?? 0) > MAX_TOTAL_BYTES) {
      degraded.push(`not fetched (size limit): ${rel}`);
      continue;
    }
    const raw = await doFetch(
      `https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${b.path.split("/").map(encodeURIComponent).join("/")}`,
      { headers: { "user-agent": "linkcheck-mcp" } },
    );
    if (!raw.ok) {
      degraded.push(`fetch failed (${raw.status}): ${rel}`);
      continue;
    }
    const bytes = new Uint8Array(await raw.arrayBuffer());
    total += bytes.length;
    files.push({ path: rel, content: new TextDecoder().decode(bytes), bytes });
  }

  return { files, source: { owner, repo, commit, path }, degraded };
}

function githubError(status: number, what: string): string {
  if (status === 403 || status === 429) return `GitHub rate limit or access denied (${status}) for ${what} — retry later or pass files directly`;
  if (status === 404) return `not found on GitHub (404): ${what} — private repos are not supported`;
  return `GitHub API error ${status} for ${what}`;
}
