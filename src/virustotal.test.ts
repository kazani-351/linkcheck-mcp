import { test } from "node:test";
import assert from "node:assert/strict";
import { checkVirusTotal } from "./virustotal.ts";

// Real network, like resolver.test.ts/dns.test.ts — but VT's free tier is 4
// req/min, so these reuse the SAME two URLs already verified live during
// development (a known-malicious URLhaus entry + a guaranteed-unseen probe)
// rather than minting fresh lookups per test run.

const KEY = process.env.VT_TEST_KEY; // set locally to run live; skipped in CI without one

test("checkVirusTotal: no key -> checked:false, no network call, no crash", async () => {
  const r = await checkVirusTotal("https://example.com/", undefined);
  assert.equal(r.checked, false);
  assert.equal(r.malicious, 0);
  assert.equal(r.degraded, undefined);
});

test("checkVirusTotal: known-malicious URL returns real malicious/suspicious counts", { skip: !KEY }, async () => {
  const r = await checkVirusTotal("http://27.215.181.39:44858/i", KEY);
  assert.equal(r.checked, true);
  assert.ok(r.malicious > 0, "expected at least one AV engine to flag this real malware URL");
});

test("checkVirusTotal: a URL VT has never seen returns checked:true, zero counts, not degraded", { skip: !KEY }, async () => {
  const r = await checkVirusTotal(
    "https://linkcheck-mcp-never-submitted-probe-xyz123.example.com/nonexistent-path-9f8e7d",
    KEY,
  );
  assert.equal(r.checked, true);
  assert.equal(r.malicious, 0);
  assert.equal(r.suspicious, 0);
  assert.equal(r.degraded, undefined, "a 404 (never scanned) is a valid outcome, not a degraded failure");
});
