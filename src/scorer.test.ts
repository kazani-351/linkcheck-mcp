import { test } from "node:test";
import assert from "node:assert/strict";
import { computeVerdict, type ScoringInput } from "./scorer.ts";

function base(overrides: Partial<ScoringInput> = {}): ScoringInput {
  return {
    heuristics: [],
    feedSignals: [],
    isShortener: false,
    stoppedReason: "ok",
    degraded: [],
    crossDomainHops: false,
    ...overrides,
  };
}

// --- Golden set (SPEC §12) ---

test("SC2: URLhaus exact-URL hit -> DANGEROUS", () => {
  const r = computeVerdict(base({ feedSignals: [{ matchedValue: "x", source: "URLhaus", type: "urlhaus_exact_url" }] }));
  assert.equal(r.verdict, "DANGEROUS");
});

test("SC3a: embedded credentials -> DANGEROUS (per §8 tiering, stronger than plain SUSPICIOUS)", () => {
  const r = computeVerdict(base({ heuristics: [{ id: "embedded_credentials", severity: "dangerous", detail: "x" }] }));
  assert.equal(r.verdict, "DANGEROUS");
});

test("SC3b: IP-literal host -> SUSPICIOUS+", () => {
  const r = computeVerdict(base({ heuristics: [{ id: "ip_literal_host", severity: "suspicious", detail: "x" }] }));
  assert.equal(r.verdict, "SUSPICIOUS");
});

test("SC4: homograph -> SUSPICIOUS", () => {
  const r = computeVerdict(base({ heuristics: [{ id: "homograph_mixed_script", severity: "suspicious", detail: "x" }] }));
  assert.equal(r.verdict, "SUSPICIOUS");
});

test("SC5: clean input, nothing degraded -> SAFE", () => {
  const r = computeVerdict(base());
  assert.equal(r.verdict, "SAFE");
});

// --- AC1 anti-criterion (SPEC §13) — the one that must never break ---

test("AC1: a degraded check with zero positive signals is SUSPICIOUS, never SAFE", () => {
  const r = computeVerdict(base({ degraded: ["URLhaus feed unavailable"] }));
  assert.equal(r.verdict, "SUSPICIOUS");
  assert.match(r.verdictReason, /could not complete/);
});

test("AC1: degradation never downgrades an already-DANGEROUS verdict", () => {
  const r = computeVerdict(
    base({
      feedSignals: [{ matchedValue: "x", source: "URLhaus", type: "urlhaus_exact_url" }],
      degraded: ["some unrelated feed unavailable"],
    }),
  );
  assert.equal(r.verdict, "DANGEROUS");
});

// --- Remaining DANGEROUS rules ---

test("threat_intel_domain (TIF) -> DANGEROUS", () => {
  assert.equal(computeVerdict(base({ feedSignals: [{ matchedValue: "x", source: "TIF", type: "threat_intel_domain" }] })).verdict, "DANGEROUS");
});

test("threat_intel_ip (TIF-IPs) -> DANGEROUS", () => {
  assert.equal(computeVerdict(base({ feedSignals: [{ matchedValue: "1.2.3.4", source: "TIF", type: "threat_intel_ip" }] })).verdict, "DANGEROUS");
});

test("dangerous_scheme (javascript:/data:) -> DANGEROUS", () => {
  assert.equal(computeVerdict(base({ heuristics: [{ id: "dangerous_scheme", severity: "dangerous", detail: "x" }] })).verdict, "DANGEROUS");
});

// --- Remaining SUSPICIOUS rules ---

test("abused_tld -> SUSPICIOUS", () => {
  assert.equal(computeVerdict(base({ feedSignals: [{ matchedValue: "top", source: "HaGeZi", type: "abused_tld" }] })).verdict, "SUSPICIOUS");
});

test("entropy_nrd (DGA) -> SUSPICIOUS", () => {
  assert.equal(computeVerdict(base({ feedSignals: [{ matchedValue: "x.com", source: "HaGeZi", type: "entropy_nrd" }] })).verdict, "SUSPICIOUS");
});

test("deceptive_subdomain_depth -> SUSPICIOUS", () => {
  assert.equal(computeVerdict(base({ heuristics: [{ id: "deceptive_subdomain_depth", severity: "suspicious", detail: "x" }] })).verdict, "SUSPICIOUS");
});

test("insecure_http -> SUSPICIOUS", () => {
  assert.equal(computeVerdict(base({ heuristics: [{ id: "insecure_http", severity: "suspicious", detail: "x" }] })).verdict, "SUSPICIOUS");
});

test("crossDomainHops -> SUSPICIOUS", () => {
  assert.equal(computeVerdict(base({ crossDomainHops: true })).verdict, "SUSPICIOUS");
});

test("shortener with unresolvable target -> SUSPICIOUS", () => {
  assert.equal(computeVerdict(base({ isShortener: true, stoppedReason: "error" })).verdict, "SUSPICIOUS");
  assert.equal(computeVerdict(base({ isShortener: true, stoppedReason: "private_host" })).verdict, "SUSPICIOUS");
});

test("shortener that resolved fine is NOT suspicious on its own", () => {
  assert.equal(computeVerdict(base({ isShortener: true, stoppedReason: "ok" })).verdict, "SAFE");
});

// --- Combination behavior ---

test("worst-signal-wins: DANGEROUS beats SUSPICIOUS when both are present", () => {
  const r = computeVerdict(
    base({
      feedSignals: [{ matchedValue: "x", source: "URLhaus", type: "urlhaus_exact_url" }],
      heuristics: [{ id: "insecure_http", severity: "suspicious", detail: "x" }],
    }),
  );
  assert.equal(r.verdict, "DANGEROUS");
});

test("multiple SUSPICIOUS signals all appear in the reason, verdict stays SUSPICIOUS (not escalated)", () => {
  const r = computeVerdict(
    base({
      heuristics: [
        { id: "insecure_http", severity: "suspicious", detail: "x" },
        { id: "ip_literal_host", severity: "suspicious", detail: "x" },
      ],
    }),
  );
  assert.equal(r.verdict, "SUSPICIOUS");
  assert.match(r.verdictReason, /http/);
  assert.match(r.verdictReason, /IP address/);
});
