// Tiered scoring (SPEC §8): worst-signal-wins, transparent rules, no magic
// numbers. Combines every signal check_url/check_text already collects into one
// verdict + a one-line human reason. Anti-criterion AC1 (SPEC §13) is enforced
// here: a degraded check can only ever push toward SUSPICIOUS, never SAFE.

import type { HeuristicHit } from "./heuristics.ts";
import type { FeedHit } from "./feeds.ts";

export type Verdict = "SAFE" | "SUSPICIOUS" | "DANGEROUS";

export interface ScoringInput {
  heuristics: HeuristicHit[];
  feedSignals: Array<FeedHit & { type: string }>;
  isShortener: boolean;
  stoppedReason: string;
  degraded: string[];
  crossDomainHops: boolean;
}

export interface ScoreResult {
  verdict: Verdict;
  verdictReason: string;
}

interface Rule {
  test: (i: ScoringInput) => boolean;
  reason: (i: ScoringInput) => string;
}

const hasHeuristic = (i: ScoringInput, id: string) => i.heuristics.some((h) => h.id === id);
const hasFeed = (i: ScoringInput, type: string) => i.feedSignals.some((s) => s.type === type);

// Order doesn't affect the verdict tier (all DANGEROUS rules are checked as a
// group, then all SUSPICIOUS) but does affect which reason appears first.
const DANGEROUS_RULES: Rule[] = [
  { test: (i) => hasFeed(i, "urlhaus_exact_url"), reason: () => "URL matches a known malware-distribution entry (URLhaus)" },
  { test: (i) => hasFeed(i, "threat_intel_domain"), reason: () => "domain is on a threat-intelligence feed (malware/phishing/C2)" },
  { test: (i) => hasFeed(i, "threat_intel_ip"), reason: () => "resolved IP is on a threat-intelligence feed" },
  { test: (i) => hasHeuristic(i, "dangerous_scheme"), reason: () => "uses a dangerous URL scheme (javascript:/data:)" },
  { test: (i) => hasHeuristic(i, "embedded_credentials"), reason: () => "disguises its real destination with embedded credentials" },
];

const SUSPICIOUS_RULES: Rule[] = [
  { test: (i) => hasFeed(i, "abused_tld"), reason: () => "uses a commonly-abused top-level domain" },
  { test: (i) => hasFeed(i, "entropy_nrd"), reason: () => "domain matches a newly-registered, algorithmically-generated pattern (DGA)" },
  { test: (i) => hasHeuristic(i, "homograph_mixed_script"), reason: () => "hostname mixes character scripts (possible lookalike attack)" },
  { test: (i) => hasHeuristic(i, "ip_literal_host"), reason: () => "destination is a bare IP address, not a domain name" },
  { test: (i) => hasHeuristic(i, "deceptive_subdomain_depth"), reason: () => "unusually deep subdomain nesting (possible brand impersonation)" },
  { test: (i) => hasHeuristic(i, "insecure_http"), reason: () => "unencrypted http:// connection" },
  { test: (i) => i.crossDomainHops, reason: () => "redirect chain jumps between different domains" },
  {
    test: (i) => i.isShortener && (i.stoppedReason === "error" || i.stoppedReason === "private_host"),
    reason: () => "known URL shortener whose target could not be verified",
  },
];

function matchReasons(rules: Rule[], input: ScoringInput): string[] {
  return rules.filter((r) => r.test(input)).map((r) => r.reason(input));
}

export function computeVerdict(input: ScoringInput): ScoreResult {
  const dangerous = matchReasons(DANGEROUS_RULES, input);
  if (dangerous.length > 0) {
    return { verdict: "DANGEROUS", verdictReason: dangerous.join("; ") };
  }

  const suspicious = matchReasons(SUSPICIOUS_RULES, input);
  if (suspicious.length > 0) {
    return { verdict: "SUSPICIOUS", verdictReason: suspicious.join("; ") };
  }

  // AC1 (SPEC §13): never SAFE when a check failed to run — degrade to
  // SUSPICIOUS instead, even with zero positive signals.
  if (input.degraded.length > 0) {
    return { verdict: "SUSPICIOUS", verdictReason: `one or more checks could not complete: ${input.degraded.join("; ")}` };
  }

  return { verdict: "SAFE", verdictReason: "no threat signals found across all checks" };
}
