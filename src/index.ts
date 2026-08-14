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
  type MinimalD1,
  type MinimalKV,
} from "./feeds.ts";
import { computeVerdict, type Verdict } from "./scorer.ts";
import { checkVirusTotal } from "./virustotal.ts";

// Typed against the minimal interfaces feeds.ts actually uses (prepare/bind/all,
// get) rather than the full D1Database/KVNamespace surface — a real Cloudflare
// binding satisfies this structurally, and it lets tests use lightweight fakes
// without casting away type safety.
interface Env {
  MCP_BEARER_TOKEN?: string;
  FEEDS_DB?: MinimalD1;
  VERDICT_CACHE?: MinimalKV;
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

  return server;
}

export { createServer };

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (pathname === "/health") {
      let feeds: unknown = "unavailable (D1 not bound)";
      if (env.FEEDS_DB) {
        try {
          const { results } = await env.FEEDS_DB.prepare(
            "SELECT source, last_refresh, last_status, entry_count FROM feed_meta",
          )
            .bind()
            .all();
          feeds = results;
        } catch (e) {
          feeds = `error reading feed_meta: ${(e as Error).message}`;
        }
      }
      return Response.json({ status: "ok", service: "linkcheck-mcp", version: "0.1.0", feeds });
    }

    // Bearer gate BEFORE the MCP handler — createMcpHandler does not verify tokens (SPEC §11).
    const token = env.MCP_BEARER_TOKEN;
    if (token && request.headers.get("authorization") !== `Bearer ${token}`) {
      return new Response("unauthorized", { status: 401 });
    }

    // Built fresh per request so tool handlers can close over this request's env
    // (bindings aren't available via the McpServer factory's own context) — fine
    // per SPEC/docs since we don't use notify()/list-changed events.
    return createMcpHandler(() => createServer(env))(request, env, ctx);
  },
};
