// DNS-over-HTTPS lookup (SPEC §6 IP-reputation signal). Workers doesn't expose a
// raw DNS API — this is the standard workaround: plain fetch() to a DoH endpoint.
// Real gap this closes: the resolver's SSRF guard only handles LITERAL IP
// hostnames in a URL; it never resolves a domain name to an IP, which the
// TIF-IPs feed lookup needs. One extra fetch per check, not "free" as originally
// assumed in spec drafting — corrected here, not silently faked.

const DOH_TIMEOUT_MS = 3000;

export interface DnsResult {
  ip: string | null;
  degraded?: string;
}

export async function resolveIp(hostname: string): Promise<DnsResult> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
      { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(DOH_TIMEOUT_MS) },
    );
    if (!res.ok) return { ip: null, degraded: `DoH lookup returned HTTP ${res.status}` };

    const data = (await res.json()) as { Answer?: Array<{ type: number; data: string }> };
    const aRecord = data.Answer?.find((a) => a.type === 1); // type 1 = A record
    return aRecord ? { ip: aRecord.data } : { ip: null, degraded: "no A record found" };
  } catch (e) {
    return { ip: null, degraded: `DoH lookup failed: ${(e as Error).message}` };
  }
}
