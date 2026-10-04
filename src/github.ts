// Fetch a skill's files from a public GitHub URL for check_skill (SPEC §7).
// Resolves the ref to a commit SHA first so the scan is pinned to exact bytes —
// a branch name would let the content change under the verdict.
//
// This is the one place the Worker GETs file BODIES. That's allowed because it's
// the skill's source text, fetched from GitHub's own hosts only (api.github.com,
// raw.githubusercontent.com) and never executed — not an arbitrary target URL,
// which stays HEAD-only per the §11 posture.

import { MAX_FILE_BYTES, MAX_TOTAL_BYTES, type SkillFile } from "./skillscan.ts";

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
  // A blob URL points at a file; the skill is the folder that holds it.
  const path = (kind === "blob" ? rest.slice(0, -1) : rest).join("/");
  return { owner, repo, ref, path };
}

type Fetcher = typeof fetch;

const UA = "linkcheck-mcp/0.1 (+https://linkcheck-mcp.kazani.workers.dev)";
const API_HEADERS = { "user-agent": UA, accept: "application/vnd.github+json" };

// Subrequest budget: a Worker invocation on the free plan gets ~50 outbound
// fetches. 2 API calls + GITHUB_MAX_FILES raw fetches + check_skill's URL checks
// (each HEAD hops + DoH) must fit. Over budget → degraded, never silent.
export const GITHUB_MAX_FILES = 20;
// Workers allow 6 simultaneous open connections per invocation.
const RAW_CONCURRENCY = 6;

const decoder = new TextDecoder();

/** Every GitHub request refuses redirects outright, so the body-GET exception
 *  (SPEC §11) can't be walked off api.github.com / raw.githubusercontent.com —
 *  a 3xx comes back as a non-ok response and fails loud. */
function githubFetch(doFetch: Fetcher, url: string, headers: Record<string, string>): Promise<Response> {
  return doFetch(url, { headers, redirect: "manual" });
}

export async function fetchSkillFromGithub(target: GithubTarget, doFetch: Fetcher = fetch): Promise<GithubFetch> {
  const { owner, repo, path } = target;
  const base = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const degraded: string[] = [];

  async function api(route: string, what: string, accept = API_HEADERS.accept): Promise<Response> {
    const r = await githubFetch(doFetch, base + route, { ...API_HEADERS, accept });
    if (!r.ok) throw new Error(githubError(r.status, what));
    return r;
  }

  // "HEAD" resolves the default branch in the same call (verified 2026-09-27).
  const ref = target.ref ?? "HEAD";
  const c = await api(`/commits/${encodeURIComponent(ref)}`, `${owner}/${repo}@${ref}`, "application/vnd.github.sha");
  const commit = (await c.text()).trim();
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error(`GitHub returned an unexpected commit id for ${owner}/${repo}@${ref}`);

  const t = await api(`/git/trees/${commit}?recursive=1`, `tree ${commit}`);
  const tree = (await t.json()) as { tree: Array<{ path: string; type: string; size?: number }>; truncated?: boolean };
  if (tree.truncated) degraded.push("GitHub tree listing truncated — repo too large; some files may be missing");

  const prefix = path ? path.replace(/\/$/, "") + "/" : "";
  let blobs = tree.tree.filter((e) => e.type === "blob" && (prefix === "" || e.path.startsWith(prefix)));
  if (blobs.length === 0) throw new Error(`no files under '${path || "/"}' at ${commit.slice(0, 7)}`);
  if (blobs.length > GITHUB_MAX_FILES) {
    degraded.push(`truncated: ${blobs.length} files, fetched first ${GITHUB_MAX_FILES} (pass files directly to scan all)`);
    blobs = blobs.slice(0, GITHUB_MAX_FILES);
  }

  // Choose what to fetch from the tree's sizes first, so the size budget is
  // deterministic, then fetch in a small pool instead of one at a time.
  const wanted: typeof blobs = [];
  let total = 0;
  for (const b of blobs) {
    const size = b.size ?? 0;
    if (size > MAX_FILE_BYTES || total + size > MAX_TOTAL_BYTES) {
      degraded.push(`not fetched (size limit): ${b.path.slice(prefix.length)}`);
      continue;
    }
    total += size;
    wanted.push(b);
  }

  const results: Array<SkillFile | string> = new Array(wanted.length);
  let next = 0;
  async function worker() {
    while (next < wanted.length) {
      const i = next++;
      const b = wanted[i];
      const rel = b.path.slice(prefix.length);
      try {
        const raw = await githubFetch(
          doFetch,
          `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${commit}/${b.path.split("/").map(encodeURIComponent).join("/")}`,
          { "user-agent": UA },
        );
        if (!raw.ok) {
          results[i] = `fetch failed (${raw.status}): ${rel}`;
          continue;
        }
        const bytes = new Uint8Array(await raw.arrayBuffer());
        results[i] = { path: rel, content: decoder.decode(bytes), bytes };
      } catch (e) {
        // e.g. the Workers subrequest cap — record it and keep going; a partial
        // fetch makes the result SUSPICIOUS upstream, never NO_FLAGS.
        results[i] = `fetch failed (${(e as Error).message}): ${rel}`;
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(RAW_CONCURRENCY, wanted.length) }, worker));

  const files: SkillFile[] = [];
  for (const r of results) typeof r === "string" ? degraded.push(r) : files.push(r);
  return { files, source: { owner, repo, commit, path }, degraded };
}

function githubError(status: number, what: string): string {
  if (status >= 300 && status < 400) return `GitHub redirected (${status}) for ${what} — redirects are refused; if the repo was renamed, use its current URL`;
  if (status === 403 || status === 429) return `GitHub rate limit or access denied (${status}) for ${what} — retry later or pass files directly`;
  if (status === 404) return `not found on GitHub (404): ${what} — private repos aren't supported, and a branch name containing "/" can't be read from the URL; pass files directly in either case`;
  return `GitHub API error ${status} for ${what}`;
}
