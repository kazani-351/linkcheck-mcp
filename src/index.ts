// linkcheck-mcp Worker entrypoint (SPEC §5, §7, §11).
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { resolveUrl } from "./resolver.ts";
import { cleanUrl } from "./cleaner.ts";
import { runHeuristics, isIpLiteral } from "./heuristics.ts";
import { extractUrls } from "./extract.ts";
import { resolveIp } from "./dns.ts";
import {
  lookupDomain,
  lookupExactUrl,
  lookupTld,
  lookupDomainInBlob,
  lookupInBlob,
  type FeedHit,
  type WritableD1,
  type WritableKV,
} from "./feeds.ts";
import { computeVerdict, type Verdict } from "./scorer.ts";
import { checkVirusTotal } from "./virustotal.ts";
import { refreshAllFeeds } from "./refresh.ts";
import { LANDING_HTML, SERVER_CARD_JSON, LINK_HEADER } from "./landing.ts";
import { scanSkill, type SkillFile, type SkillScan, type SkillVerdict } from "./skillscan.ts";
import { parseGithubUrl, fetchSkillFromGithub, type GithubFetch } from "./github.ts";

// Typed against the minimal (but write-capable, for the cron refresh path)
// interfaces feeds.ts/refresh.ts actually use, rather than the full
// D1Database/KVNamespace surface — a real Cloudflare binding satisfies this
// structurally, and it lets tests use lightweight fakes without casting away
// type safety.
interface Env {
  MCP_BEARER_TOKEN?: string;
  FEEDS_DB?: WritableD1;
  VERDICT_CACHE?: WritableKV;
  VIRUSTOTAL_API_KEY?: string;
}

// Shared by check_url and check_text — resolve, clean, heuristically inspect, and
// check threat feeds for one URL. useVirusTotal defaults true (check_url's
// single-lookup path); check_text passes false on its first pass and only
// re-checks its single worst candidate with VT on, to stay under VT's 4/min
// free-tier limit (SPEC §7 "VT off in batch, worst-candidate only").
async function checkOneUrl(url: string, env: Env, useVirusTotal = true) {
  const resolved = await resolveUrl(url);
  const cleaned = cleanUrl(resolved.finalUrl);
  const heuristics = runHeuristics(resolved.finalUrl);

  const feedSignals: Array<FeedHit & { type: string }> = [];
  let isShortener = false;
  let resolvedIp: string | null = null;
  const degraded = [...resolved.degraded];

  let hostname: string | null = null;
  try {
    hostname = new URL(resolved.finalUrl).hostname;
  } catch {
    /* unparseable — resolved.finalUrl already carries the error context */
  }

  if (hostname && env.FEEDS_DB && env.VERDICT_CACHE) {
    const db = env.FEEDS_DB;
    const kv = env.VERDICT_CACHE;

    // If the host is already a literal IP, there's nothing to resolve — skip the
    // pointless DoH call and check that IP directly (real bug found+fixed via
    // production probe: a live URLhaus IP-literal URL silently skipped the
    // TIF-IPs check because resolveIp() found "no A record" for an IP it was
    // never meant to resolve — see CLAUDE.md).
    const hostIsIpLiteral = isIpLiteral(hostname);

    const [exactUrlHit, shortenerHit, tldHit, tifDomainHit, nrdHit, dns] = await Promise.all([
      lookupExactUrl(db, resolved.finalUrl),
      lookupDomain(db, hostname),
      lookupTld(db, hostname),
      lookupDomainInBlob(kv, "feed:tif-domains", hostname, "HaGeZi-TIF-domains"),
      lookupDomainInBlob(kv, "feed:entropy-nrd", hostname, "HaGeZi-Entropy-NRD"),
      hostIsIpLiteral ? Promise.resolve({ ip: hostname.replace(/^\[|\]$/g, "") }) : resolveIp(hostname),
    ]);

    if (exactUrlHit) feedSignals.push({ ...exactUrlHit, type: "urlhaus_exact_url" });
    if (tldHit) feedSignals.push({ ...tldHit, type: "abused_tld" });
    if (tifDomainHit) feedSignals.push({ ...tifDomainHit, type: "threat_intel_domain" });
    if (nrdHit) feedSignals.push({ ...nrdHit, type: "entropy_nrd" });
    isShortener = !!shortenerHit;

    if ("degraded" in dns && dns.degraded) degraded.push(dns.degraded);
    resolvedIp = dns.ip;
    if (dns.ip) {
      const ipHit = await lookupInBlob(kv, "feed:tif-ips", dns.ip, "HaGeZi-TIF-ips");
      if (ipHit) feedSignals.push({ ...ipHit, type: "threat_intel_ip" });
    }
  } else if (hostname) {
    degraded.push("feed lookups skipped: D1/KV bindings not configured");
  }

  if (useVirusTotal) {
    const vt = await checkVirusTotal(resolved.finalUrl, env.VIRUSTOTAL_API_KEY);
    if (vt.degraded) degraded.push(vt.degraded);
    if (vt.malicious > 0) feedSignals.push({ matchedValue: String(vt.malicious), source: "VirusTotal", type: "virustotal_malicious" });
    else if (vt.suspicious > 0) feedSignals.push({ matchedValue: String(vt.suspicious), source: "VirusTotal", type: "virustotal_suspicious" });
  }

  const { verdict, verdictReason } = computeVerdict({
    heuristics,
    feedSignals,
    isShortener,
    stoppedReason: resolved.stoppedReason,
    degraded,
    crossDomainHops: resolved.crossDomainHops,
  });

  return {
    verdict,
    verdictReason,
    ...resolved,
    degraded,
    cleanedUrl: cleaned.cleanedUrl,
    removedParams: cleaned.removedParams,
    queryParams: cleaned.queryParams,
    heuristics,
    feedSignals,
    isShortener,
    resolvedIp,
  };
}

interface FullResult extends Awaited<ReturnType<typeof checkOneUrl>> {}

/** SPEC §7: compact:true trims the DTO to verdict + verdict_reason + resolved_url
 *  + degraded — for callers that don't need the full evidence trail. */
function toCompact(r: FullResult) {
  return {
    verdict: r.verdict,
    verdictReason: r.verdictReason,
    resolvedUrl: r.finalUrl,
    degraded: r.degraded,
  };
}

// check_skill (SPEC §7): the deterministic static scan (re-runnable, attestable)
// is kept SEPARATE from the live URL reputation pass (time-varying), and the
// overall verdict is the worst of the two. URLs are checked without VT (batch
// rate-limit rule, same as check_text) and capped at MAX_SKILL_URLS — kept low
// because each check is several subrequests and the GitHub fetch already spends
// most of the ~50-per-invocation budget (see GITHUB_MAX_FILES in github.ts).
export const MAX_SKILL_URLS = 5;

// One table for both verdict vocabularies, so a new value is a type error here
// rather than an undefined that silently compares as "not worse".
const SEVERITY: Record<Verdict | SkillVerdict, number> = { SAFE: 0, NO_FLAGS: 0, SUSPICIOUS: 1, DANGEROUS: 2 };

export async function runCheckSkill(
  args: { files?: SkillFile[]; github_url?: string },
  env: Env,
) {
  const hasFiles = Array.isArray(args.files) && args.files.length > 0;
  if (hasFiles === !!args.github_url) throw new Error("pass exactly one of 'files' or 'github_url'");

  let files: SkillFile[];
  let source: GithubFetch["source"] | null = null;
  const degraded: string[] = [];
  if (args.github_url) {
    const target = parseGithubUrl(args.github_url);
    if (!target) throw new Error("github_url must look like https://github.com/{owner}/{repo}[/tree/{ref}/{path}]");
    const fetched = await fetchSkillFromGithub(target);
    files = fetched.files;
    source = fetched.source;
    degraded.push(...fetched.degraded);
  } else {
    files = args.files!;
  }

  const scan: SkillScan = await scanSkill(files);

  const urlChecks: Array<{ url: string; verdict?: Verdict; verdictReason?: string; error?: string }> = await Promise.all(
    scan.urls.slice(0, MAX_SKILL_URLS).map(async (url) => {
      try {
        const r = await checkOneUrl(url, env, false);
        return { url, verdict: r.verdict, verdictReason: r.verdictReason };
      } catch (e) {
        return { url, error: (e as Error).message };
      }
    }),
  );
  if (scan.urls.length > MAX_SKILL_URLS) degraded.push(`url checks truncated: ${scan.urls.length} URLs, checked first ${MAX_SKILL_URLS}`);
  for (const u of urlChecks) if (u.error) degraded.push(`url check failed: ${u.url}`);

  let overall: SkillVerdict = scan.verdict;
  for (const u of urlChecks) {
    // An errored check counts as SUSPICIOUS; a SAFE URL can't lower anything.
    const v: Verdict = u.verdict ?? "SUSPICIOUS";
    if (v !== "SAFE" && SEVERITY[v] > SEVERITY[overall]) overall = v;
  }
  // Never false-SAFE: an incomplete fetch or URL pass can't leave NO_FLAGS standing.
  if (overall === "NO_FLAGS" && degraded.length) overall = "SUSPICIOUS";

  const badUrls = urlChecks.filter((u) => u.verdict && u.verdict !== "SAFE");
  const overallReason =
    overall === scan.verdict && !badUrls.length && !degraded.length
      ? `static scan: ${scan.verdictReason}`
      : [
          `static scan: ${scan.verdict}`,
          badUrls.length ? `${badUrls.length} URL(s) flagged: ${badUrls.map((u) => `${u.url} → ${u.verdict}`).join(", ")}` : null,
          degraded.length ? `incomplete: ${degraded.join("; ")}` : null,
        ]
          .filter(Boolean)
          .join(" | ");

  return { overallVerdict: overall, overallReason, source, scan, urlChecks, degraded };
}

function createServer(env: Env): McpServer {
  const server = new McpServer({ name: "linkcheck-mcp", version: "0.1.0" });

  server.registerTool(
    "check_url",
    {
      description:
        "Resolve a URL's true destination by safely following redirects (HEAD-first, no page render), check it against threat-intelligence feeds, and return a SAFE/SUSPICIOUS/DANGEROUS verdict with the evidence behind it. Call this before opening, following, or recommending any link from an untrusted source.",
      inputSchema: {
        url: z.string().describe("The http(s) URL to inspect"),
        compact: z.boolean().optional().describe("Return only verdict/reason/resolvedUrl/degraded instead of the full evidence trail"),
      },
    },
    async ({ url, compact }: { url: string; compact?: boolean }) => {
      try {
        const result = await checkOneUrl(url, env);
        const payload = compact ? toCompact(result) : result;
        return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
      } catch (e) {
        return {
          content: [{ type: "text" as const, text: `Error: ${(e as Error).message}` }],
          isError: true,
        };
      }
    },
  );

  server.registerTool(
    "check_text",
    {
      description:
        "Extract every URL from a block of text (standard links, bare domains, and defanged forms like hxxp://evil[.]com) and check each one, returning a verdict for each. Call this on a pasted email, message, or document before trusting any link inside it.",
      inputSchema: {
        text: z.string().describe("Free text that may contain one or more URLs"),
        compact: z.boolean().optional().describe("Return only verdict/reason/resolvedUrl/degraded per URL instead of the full evidence trail"),
      },
    },
    async ({ text, compact }: { text: string; compact?: boolean }) => {
      const extracted = extractUrls(text);
      const order = { SAFE: 0, SUSPICIOUS: 1, DANGEROUS: 2 } as const;

      // First pass: no VT (SPEC §7 rate-limit guard — one call per URL would
      // exceed VT's 4/min free tier on any blob with more than a few links).
      type CheckedEntry = { url: string; error?: string } & Partial<FullResult>;
      const firstPass: CheckedEntry[] = await Promise.all(
        extracted.urls.map(async (url) => {
          try {
            const result = await checkOneUrl(url, env, false);
            return { url, ...result };
          } catch (e) {
            return { url, error: (e as Error).message };
          }
        }),
      );

      // Second pass: re-check ONLY the single worst candidate with VT on, if
      // it's already SUSPICIOUS+ from cheaper signals and a VT key exists.
      let worstIdx = -1;
      for (let i = 0; i < firstPass.length; i++) {
        const v = firstPass[i].verdict;
        if (v && order[v] > (worstIdx >= 0 ? order[firstPass[worstIdx].verdict as Verdict] : -1)) worstIdx = i;
      }
      if (worstIdx >= 0 && firstPass[worstIdx].verdict !== "SAFE" && env.VIRUSTOTAL_API_KEY) {
        try {
          const reChecked = await checkOneUrl(firstPass[worstIdx].url, env, true);
          firstPass[worstIdx] = { url: firstPass[worstIdx].url, ...reChecked };
        } catch {
          /* keep the first-pass result for this URL if the VT re-check itself throws */
        }
      }

      const checked = firstPass.map((c) => (compact && "verdict" in c && c.verdict ? { url: c.url, ...toCompact(c as FullResult) } : c));
      const worstVerdict = firstPass.reduce<string>(
        (worst, c) => (c.verdict && order[c.verdict] > (order[worst as Verdict] ?? -1) ? c.verdict : worst),
        "SAFE",
      );
      const result = {
        checked,
        worstVerdict,
        truncated: extracted.truncated,
        droppedCount: extracted.droppedCount,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.registerTool(
    "check_skill",
    {
      description:
        "Statically scan an agent skill (a SKILL.md folder) before installing or loading it: flags remote code execution, secret exfiltration, credential access, destructive commands, hidden characters and instruction-override phrasing with file:line evidence, checks every URL the skill references against threat feeds, and returns per-file sha256 digests (MCP Skills extension / SEP-2640 shape) pinning exactly what was scanned. Pass either the skill's files or a public GitHub URL. Best verdict is NO_FLAGS, never SAFE — a static scan cannot prove safety.",
      inputSchema: {
        files: z
          .array(z.object({ path: z.string(), content: z.string() }))
          .optional()
          .describe("The skill's files: paths relative to the skill folder (SKILL.md at root) and their text content"),
        github_url: z
          .string()
          .optional()
          .describe("Public GitHub URL of the skill folder, e.g. https://github.com/owner/repo/tree/main/skills/name"),
        compact: z.boolean().optional().describe("Return only verdict, reason, source, digestSetHash, findings and degraded"),
      },
    },
    async ({ files, github_url, compact }: { files?: SkillFile[]; github_url?: string; compact?: boolean }) => {
      try {
        const r = await runCheckSkill({ files, github_url }, env);
        const payload = compact
          ? {
              overallVerdict: r.overallVerdict,
              overallReason: r.overallReason,
              source: r.source,
              digestSetHash: r.scan.digestSetHash,
              findings: r.scan.findings,
              degraded: [...r.scan.degraded, ...r.degraded],
            }
          : r;
        return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
      } catch (e) {
        return {
          content: [{ type: "text" as const, text: `Error: ${(e as Error).message}` }],
          isError: true,
        };
      }
    },
  );

  return server;
}

export { createServer };

async function readFeedMeta(env: Env): Promise<unknown> {
  if (!env.FEEDS_DB) return "unavailable (D1 not bound)";
  try {
    const { results } = await env.FEEDS_DB.prepare(
      "SELECT source, last_refresh, last_status, entry_count FROM feed_meta",
    )
      .bind()
      .all();
    return results;
  } catch (e) {
    return `error reading feed_meta: ${(e as Error).message}`;
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);

    // Human landing page — served only for browser (text/html) GETs on "/", so
    // it never shadows the MCP transport, which POSTs (and negotiates SSE via
    // `accept: text/event-stream`) on this same origin. Public, like /health.
    if (
      request.method === "GET" &&
      pathname === "/" &&
      (request.headers.get("accept") ?? "").includes("text/html")
    ) {
      return new Response(LANDING_HTML, {
        headers: { "content-type": "text/html; charset=utf-8", link: LINK_HEADER },
      });
    }

    // Machine-readable server card for MCP discovery. Public.
    if (pathname === "/.well-known/mcp/server-card.json") {
      return new Response(SERVER_CARD_JSON, {
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    if (pathname === "/health") {
      return Response.json(
        { status: "ok", service: "linkcheck-mcp", version: "0.1.0", feeds: await readFeedMeta(env) },
        { headers: { link: LINK_HEADER } },
      );
    }

    // Bearer gate BEFORE any protected route — createMcpHandler does not verify
    // tokens itself (SPEC §11), and the admin route below is equally sensitive
    // (it makes real writes to D1/KV) so it shares the same gate, not a second one.
    const token = env.MCP_BEARER_TOKEN;
    if (token && request.headers.get("authorization") !== `Bearer ${token}`) {
      return new Response("unauthorized", { status: 401 });
    }

    // Plain-HTTP verdict endpoint — lets a non-MCP client (the local
    // UserPromptSubmit hook in ~/.claude/hooks) get a verdict with a single
    // curl, reusing the EXACT same checkOneUrl path as the MCP check_url tool.
    // Sits behind the same bearer gate as everything below. POST body:
    // { "url": string, "compact"?: boolean }. compact:true returns just
    // verdict/verdictReason/resolvedUrl/degraded (all the hook needs).
    if (pathname === "/check" && request.method === "POST") {
      let body: { url?: unknown; compact?: unknown };
      try {
        body = await request.json();
      } catch {
        return Response.json({ error: "invalid JSON body" }, { status: 400 });
      }
      if (typeof body.url !== "string" || body.url === "") {
        return Response.json({ error: "missing 'url' string in body" }, { status: 400 });
      }
      try {
        const result = await checkOneUrl(body.url, env);
        return Response.json(body.compact === true ? toCompact(result) : result);
      } catch (e) {
        return Response.json({ error: (e as Error).message }, { status: 500 });
      }
    }

    // Manual refresh trigger — exists because local wrangler dev can't fire a
    // real cron tick on this machine (workerd requires macOS 13.5+), so this is
    // also how the refresh logic gets verified against production. Doubles as a
    // genuine "force refresh now" if a feed goes stale before the next schedule.
    if (pathname === "/admin/refresh-feeds" && request.method === "POST") {
      if (!env.FEEDS_DB || !env.VERDICT_CACHE) {
        return Response.json({ error: "D1/KV bindings not configured" }, { status: 503 });
      }
      const results = await refreshAllFeeds(env.FEEDS_DB, env.VERDICT_CACHE, Date.now());
      const anyFailed = results.some((r) => r.status === "error");
      return Response.json({ results }, { status: anyFailed ? 207 : 200 });
    }

    // Built fresh per request so tool handlers can close over this request's env
    // (bindings aren't available via the McpServer factory's own context) — fine
    // per SPEC/docs since we don't use notify()/list-changed events.
    return createMcpHandler(() => createServer(env))(request, env, ctx);
  },

  // Cloudflare Cron Trigger entrypoint (wrangler.jsonc `triggers.crons`). Runs in
  // its own isolate on Cloudflare's schedule — ctx.waitUntil extends execution
  // past the point scheduled() itself returns, since the refresh (6 feeds, one
  // up to ~14MB) takes longer than a bare invocation is guaranteed to stay alive.
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    if (!env.FEEDS_DB || !env.VERDICT_CACHE) return; // nothing to refresh without bindings
    ctx.waitUntil(refreshAllFeeds(env.FEEDS_DB, env.VERDICT_CACHE, Date.now()).then(() => undefined));
  },
};
