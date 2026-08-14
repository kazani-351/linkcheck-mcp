// VirusTotal client (SPEC §6/§15) — optional, owner-supplied key, degrades
// cleanly if absent/rate-limited/erroring. Read-only lookup (GET /urls/{id}),
// no submission — v1 only checks URLs VT has already seen (SPEC §4 explicitly
// scopes VT to lookup, not scan-and-wait).
//
// Response shape verified live against the real API before writing this (not
// guessed from docs — the docs page is a JS-rendered SPA that didn't yield the
// schema on fetch): GET /api/v3/urls/{base64url(url), no padding} with header
// x-apikey. 200 -> data.attributes.last_analysis_stats.{malicious,suspicious}.
// 404 -> VT has never seen this URL (NOT an error/degraded state — just no
// opinion, same semantics as "not on this list" for the other feeds).

const VT_TIMEOUT_MS = 5000;

export interface VtResult {
  checked: boolean; // false if VT wasn't consulted at all (no key, or a real failure)
  malicious: number;
  suspicious: number;
  degraded?: string;
}

function urlId(url: string): string {
  // base64url, no padding — VT's URL identifier format (verified live).
  const b64 = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return b64;
}

export async function checkVirusTotal(url: string, apiKey: string | undefined): Promise<VtResult> {
  if (!apiKey) {
    return { checked: false, malicious: 0, suspicious: 0 };
  }

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId(url)}`, {
      headers: { "x-apikey": apiKey },
      signal: AbortSignal.timeout(VT_TIMEOUT_MS),
    });

    if (res.status === 404) {
      // VT has no report for this URL yet — a real, valid outcome, not a failure.
      return { checked: true, malicious: 0, suspicious: 0 };
    }
    if (res.status === 429) {
      return { checked: false, malicious: 0, suspicious: 0, degraded: "VirusTotal rate limit exceeded" };
    }
    if (!res.ok) {
      return { checked: false, malicious: 0, suspicious: 0, degraded: `VirusTotal returned HTTP ${res.status}` };
    }

    const body = (await res.json()) as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number } } };
    };
    const stats = body.data?.attributes?.last_analysis_stats;
    return { checked: true, malicious: stats?.malicious ?? 0, suspicious: stats?.suspicious ?? 0 };
  } catch (e) {
    return { checked: false, malicious: 0, suspicious: 0, degraded: `VirusTotal lookup failed: ${(e as Error).message}` };
  }
}
