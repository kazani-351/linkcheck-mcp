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

/** github.com/{o}/{r}[/tree|blob/{ref}/{path}] → target. A ref containing "/"
 *  is ambiguous in this URL shape; we take the first segment, and the 404 message
 *  tells the caller to pass files directly if that guess was wrong. */
export function parseGithubUrl(input: string): GithubTarget | null {
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    return null;
  }
  if (u.hostname !== "github.com" && u.hostname !== "www.github.com") return null;
  let parts: string[];
  try {
    // URL.pathname keeps percent-escapes; decode once here so later encoding
    // isn't applied twice and "my%20skill" matches the tree's "my skill/".
    parts = u.pathname.split("/").filter(Boolean).map(decodeURIComponent);
  } catch {
    return null;
  }
  if (parts.length < 2) return null;
  const [owner, rawRepo, kind, ref, ...rest] = parts;
  const repo = rawRepo.replace(/\.git$/, "");
  if (!kind) return { owner, repo, ref: null, path: "" };
  if ((kind !== "tree" && kind !== "blob") || !ref) return null;
  let path = rest.join("/");
  // A blob URL points at a file; the skill is the folder that holds it.
  if (kind === "blob") path = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
  return { owner, repo, ref, path };
}

type Fetcher = typeof fetch;

const API_HEADERS = { "user-agent": "linkcheck-mcp", accept: "application/vnd.github+json" };
const GITHUB_HOSTS = new Set(["api.github.com", "raw.githubusercontent.com"]);

// Subrequest budget: a Worker invocation on the free plan gets ~50 outbound
// fetches. Up to 3 API calls + GITHUB_MAX_FILES raw fetches + check_skill's URL
// checks (each HEAD hops + DoH) must fit, so the GitHub path fetches far fewer
// files than skillscan's own MAX_FILES. Over budget → degraded, never silent.
export const GITHUB_MAX_FILES = 20;

/** fetch that refuses to have followed a redirect off GitHub's own hosts —
 *  the body-GET exception (SPEC §11) holds only for these hosts. */
async function githubFetch(doFetch: Fetcher, url: string, init: RequestInit): Promise<Response> {
  const r = await doFetch(url, init);
  const finalHost = r.url ? new URL(r.url).hostname : new URL(url).hostname;
  if (!GITHUB_HOSTS.has(finalHost)) throw new Error(`GitHub response redirected off GitHub hosts (${finalHost}) — refusing`);
  return r;
}

export async function fetchSkillFromGithub(target: GithubTarget, doFetch: Fetcher = fetch): Promise<GithubFetch> {
  const { owner, repo, path } = target;
  const base = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const degraded: string[] = [];

  let ref = target.ref;
  if (!ref) {
    const r = await githubFetch(doFetch, base, { headers: API_HEADERS });
    if (!r.ok) throw new Error(githubError(r.status, `${owner}/${repo}`));
    ref = ((await r.json()) as { default_branch: string }).default_branch;
  }

  const c = await githubFetch(doFetch, `${base}/commits/${encodeURIComponent(ref)}`, {
    headers: { ...API_HEADERS, accept: "application/vnd.github.sha" },
  });
  if (!c.ok) throw new Error(githubError(c.status, `${owner}/${repo}@${ref}`));
  const commit = (await c.text()).trim();
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error(`GitHub returned an unexpected commit id for ${owner}/${repo}@${ref}`);

  const t = await githubFetch(doFetch, `${base}/git/trees/${commit}?recursive=1`, { headers: API_HEADERS });
  if (!t.ok) throw new Error(githubError(t.status, `tree ${commit}`));
  const tree = (await t.json()) as { tree: Array<{ path: string; type: string; size?: number }>; truncated?: boolean };
  if (tree.truncated) degraded.push("GitHub tree listing truncated — repo too large; some files may be missing");

  const prefix = path ? path.replace(/\/$/, "") + "/" : "";
  let blobs = tree.tree.filter((e) => e.type === "blob" && (prefix === "" || e.path.startsWith(prefix)));
  if (blobs.length === 0) throw new Error(`no files under '${path || "/"}' at ${commit.slice(0, 7)}`);
  const limit = Math.min(MAX_FILES, GITHUB_MAX_FILES);
  if (blobs.length > limit) {
    degraded.push(`truncated: ${blobs.length} files, fetched first ${limit} (pass files directly to scan all)`);
    blobs = blobs.slice(0, limit);
  }

  const files: SkillFile[] = [];
  let total = 0;
  for (const b of blobs) {
    const rel = b.path.slice(prefix.length);
    if ((b.size ?? 0) > MAX_FILE_BYTES || total + (b.size ?? 0) > MAX_TOTAL_BYTES) {
      degraded.push(`not fetched (size limit): ${rel}`);
      continue;
    }
    try {
      const raw = await githubFetch(
        doFetch,
        `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${commit}/${b.path.split("/").map(encodeURIComponent).join("/")}`,
        { headers: { "user-agent": "linkcheck-mcp" } },
      );
      if (!raw.ok) {
        degraded.push(`fetch failed (${raw.status}): ${rel}`);
        continue;
      }
      const bytes = new Uint8Array(await raw.arrayBuffer());
      total += bytes.length;
      files.push({ path: rel, content: new TextDecoder().decode(bytes), bytes });
    } catch (e) {
      // e.g. the Workers subrequest cap — record it and keep going; a partial
      // fetch makes the result SUSPICIOUS upstream, never NO_FLAGS.
      degraded.push(`fetch failed (${(e as Error).message}): ${rel}`);
    }
  }

  return { files, source: { owner, repo, commit, path }, degraded };
}

function githubError(status: number, what: string): string {
  if (status === 403 || status === 429) return `GitHub rate limit or access denied (${status}) for ${what} — retry later or pass files directly`;
  if (status === 404) return `not found on GitHub (404): ${what} — private repos aren't supported, and a branch name containing "/" can't be read from the URL; pass files directly in either case`;
  return `GitHub API error ${status} for ${what}`;
}
