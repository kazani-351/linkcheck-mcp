import { test } from "node:test";
import assert from "node:assert/strict";
import { runHeuristics } from "./heuristics.ts";

const ids = (url: string) => runHeuristics(url).map((h) => h.id);

test("SC3a: embedded credentials disguise (google.com@evil.ru)", () => {
  const hits = runHeuristics("http://google.com@evil.ru/");
  assert.ok(hits.some((h) => h.id === "embedded_credentials" && h.severity === "dangerous"));
});

test("SC3b: IP-literal host (192.0.2.1/paypal)", () => {
  const hits = runHeuristics("http://192.0.2.1/paypal");
  assert.ok(hits.some((h) => h.id === "ip_literal_host"));
});

test("SC4: homograph — Cyrillic а in аpple.com", () => {
  const hits = runHeuristics("https://аpple.com/"); // U+0430 CYRILLIC SMALL LETTER A
  assert.ok(hits.some((h) => h.id === "homograph_mixed_script"));
});

test("SC5: clean URL yields no hits", () => {
  assert.deepEqual(ids("https://anthropic.com/"), []);
});

test("legitimate single-script IDN is NOT flagged as homograph", () => {
  // münchen.de is a real German domain — pure non-Latin/diacritic content should
  // not trip mixed-script detection since there's no Latin+confusable mixing here.
  assert.deepEqual(ids("https://xn--mnchen-3ya.de/"), []); // punycode form; no raw Latin chars mixed in
});

test("javascript: and data: schemes are flagged dangerous", () => {
  assert.ok(runHeuristics("javascript:alert(1)").some((h) => h.id === "dangerous_scheme"));
  assert.ok(runHeuristics("data:text/html,<script>1</script>").some((h) => h.id === "dangerous_scheme"));
});

test("insecure http:// is flagged suspicious (not dangerous)", () => {
  const hits = runHeuristics("http://example.com/");
  const hit = hits.find((h) => h.id === "insecure_http");
  assert.ok(hit);
  assert.equal(hit.severity, "suspicious");
});

test("deep subdomain nesting is flagged", () => {
  const hits = runHeuristics("https://paypal.com.login.secure.evil.ru/");
  assert.ok(hits.some((h) => h.id === "deceptive_subdomain_depth"));
});

test("normal single-subdomain URL is not flagged for depth", () => {
  assert.equal(ids("https://www.anthropic.com/").filter((i) => i === "deceptive_subdomain_depth").length, 0);
});
