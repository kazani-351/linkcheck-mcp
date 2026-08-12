// Kill-criterion probe (SPEC §17): does HEAD-first + GET-fallback resolution reliably
// reach the true destination of real redirects/shorteners? Run: `node src/resolver.probe.ts`
import { resolveUrl } from "./resolver.ts";

const targets = [
  "http://github.com", // http→https apex redirect (well-behaved server)
  "http://google.com", // http→https, common
  "https://bit.ly", // real shortener infra — does bit.ly honor HEAD?
  "https://tinyurl.com", // real shortener infra
  "https://t.co", // Twitter/X shortener infra
  "https://httpbin.org/redirect/3", // controlled 3-hop chain
  "https://httpbin.org/absolute-redirect/2", // controlled absolute redirects
  "http://neverssl.com", // stays http (no redirect) — should resolve in 0 hops
  "javascript:alert(1)", // must be rejected by assertHttpUrl
];

const line = (s: string) => console.log(s);

for (const t of targets) {
  line("\n─────────────────────────────────────────");
  line(`INPUT:  ${t}`);
  try {
    const r = await resolveUrl(t);
    line(`FINAL:  ${r.finalUrl}`);
    line(`STOP:   ${r.stoppedReason}   hops=${r.hops.length}`);
    line(
      `METHODS:${r.hops.map((h) => ` ${h.status}:${h.method}`).join("") || " (none)"}`,
    );
    if (r.degraded.length) line(`DEGRADED: ${r.degraded.join(" | ")}`);
  } catch (e) {
    line(`REJECTED: ${(e as Error).message}`);
  }
}
line("\n─────────────────────────────────────────");
line("Probe complete.");
