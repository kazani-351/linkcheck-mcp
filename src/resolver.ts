// Redirect resolver — the risky core (SPEC §9, §11). HEAD-first, GET-headers-only
// fallback, hop-capped, per-hop timeout, loop detection, lightweight SSRF guard.
// Runs in both Node (undici fetch) and the Workers runtime — no platform APIs used.

export interface Hop {
  url: string;
  status: number;
  method: "HEAD" | "GET";
  location?: string;
}

export type StoppedReason =
  | "ok"
  | "max_hops"
  | "loop"
  | "non_http_redirect"
  | "private_host"
  | "error";

export interface ResolveResult {
  inputUrl: string;
  finalUrl: string;
  chain: string[];
  hops: Hop[];
  stoppedReason: StoppedReason;
  degraded: string[];
  crossDomainHops: boolean;
}

/** Crude registrable-domain proxy: last two labels, no public-suffix-list
 *  dependency (same "no PSL in v1" precedent as feeds.ts's parent-label match —
 *  a rare over-broad case on a two-label TLD like "co.uk" is a missed edge case,
 *  not a false-safe). */
function registrableGuess(hostname: string): string {
  const labels = hostname.toLowerCase().split(".");
  return labels.slice(-2).join(".");
}

/** True if any consecutive pair of URLs in the chain changes REGISTRABLE domain —
 *  e.g. a shortener handing off to an entirely different organization's domain
 *  (bit.ly -> evil.ru). Deliberately NOT exact-hostname comparison: apex<->www
 *  (anthropic.com -> www.anthropic.com) and same-domain subdomain moves
 *  (login.x.com -> account.x.com) are both extremely common, benign redirect
 *  patterns — flagging them was a real false-positive found via production
 *  testing against a live top-tier site (SPEC §20 bug #16), not a hypothetical. */
export function hasCrossDomainHop(chain: string[]): boolean {
  for (let i = 1; i < chain.length; i++) {
    try {
      const prev = registrableGuess(new URL(chain[i - 1]).hostname);
      const cur = registrableGuess(new URL(chain[i]).hostname);
      if (prev !== cur) return true;
    } catch {
      /* unparseable chain entry — skip this pair, not fatal to the check */
    }
  }
  return false;
}

const MAX_HOPS = 10;
const HOP_TIMEOUT_MS = 5000;

/** Reject anything that isn't http/https. Throws on bad input. */
export function assertHttpUrl(raw: string): URL {
  const u = new URL(raw); // throws on malformed
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`unsupported scheme: ${u.protocol}`);
  }
  return u;
}

/** Lightweight SSRF guard: reject literal private/loopback/link-local hosts.
 *  (Right-sized for the Workers edge per SPEC §11 — literal-host check only;
 *  full DNS-resolution SSRF is out of scope.) */
export function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  // IPv6 loopback/ULA — only for IPv6 literals (they contain ":"). A bare
  // startsWith("fd") also matched domain names like fdic.gov and let a redirect
  // hop through any fc*/fd* domain stop resolution before the real destination.
  if (h.includes(":") && (h === "::1" || h.startsWith("fc") || h.startsWith("fd"))) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 127 || a === 10 || a === 0) return true; // loopback, private, this-host
  if (a === 169 && b === 254) return true; // link-local (incl. cloud metadata 169.254.169.254)
  if (a === 192 && b === 168) return true; // private
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  return false;
}

/** One request that follows NO redirects itself — we do it manually so every hop
 *  is inspected. Body is never read (HEAD has none; GET's is cancelled). */
async function probe(
  url: string,
  method: "HEAD" | "GET",
): Promise<{ status: number; location: string | null }> {
  const res = await fetch(url, {
    method,
    redirect: "manual",
    signal: AbortSignal.timeout(HOP_TIMEOUT_MS),
    headers: { "user-agent": "linkcheck-mcp/0.1 (+safe-resolver; HEAD-first)" },
  });
  const location = res.headers.get("location");
  // Never download/execute the body (SPEC §11). Cancel any GET stream.
  try {
    await res.body?.cancel();
  } catch {
    /* already consumed/closed */
  }
  return { status: res.status, location };
}

const isRedirect = (s: number) => s >= 300 && s < 400;

/** Resolve a URL to its true destination by following redirects safely. */
export async function resolveUrl(inputUrl: string): Promise<ResolveResult> {
  const degraded: string[] = [];
  const hops: Hop[] = [];
  const seen = new Set<string>();

  let current = assertHttpUrl(inputUrl).toString();
  let stoppedReason: StoppedReason = "ok";

  for (let i = 0; i < MAX_HOPS; i++) {
    if (isPrivateHost(new URL(current).hostname)) {
      stoppedReason = "private_host";
      degraded.push(`refused private/internal host at ${current}`);
      break;
    }
    if (seen.has(current)) {
      stoppedReason = "loop";
      break;
    }
    seen.add(current);

    // HEAD first; fall back to GET-headers-only when HEAD is unusable.
    let method: "HEAD" | "GET" = "HEAD";
    let status: number;
    let location: string | null;
    try {
      ({ status, location } = await probe(current, "HEAD"));
      // Some servers 405/501 on HEAD, or omit Location on HEAD → retry with GET.
      if (status === 405 || status === 501 || (isRedirect(status) && !location)) {
        method = "GET";
        ({ status, location } = await probe(current, "GET"));
      }
    } catch (headErr) {
      try {
        method = "GET";
        ({ status, location } = await probe(current, "GET"));
        degraded.push(`HEAD failed at ${current}, used GET fallback`);
      } catch (getErr) {
        stoppedReason = "error";
        degraded.push(`fetch failed at ${current}: ${(getErr as Error).message}`);
        break;
      }
    }

    hops.push({ url: current, status, method, location: location ?? undefined });

    if (!isRedirect(status) || !location) {
      stoppedReason = "ok";
      break; // reached final (non-redirect) or a redirect with no target
    }

    // Resolve next hop (handles relative Location).
    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      stoppedReason = "error";
      degraded.push(`unparseable redirect target: ${location}`);
      break;
    }
    if (next.protocol !== "http:" && next.protocol !== "https:") {
      stoppedReason = "non_http_redirect";
      degraded.push(`redirect to non-http scheme: ${next.protocol}`);
      break;
    }
    current = next.toString();
    if (i === MAX_HOPS - 1) stoppedReason = "max_hops";
  }

  const chain = hops
    .map((h) => h.url)
    .concat(stoppedReason === "ok" ? [current] : [])
    .filter((v, idx, arr) => arr.indexOf(v) === idx);

  return {
    inputUrl,
    finalUrl: current,
    chain,
    hops,
    stoppedReason,
    degraded,
    crossDomainHops: hasCrossDomainHop(chain),
  };
}
