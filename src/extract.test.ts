import { test } from "node:test";
import assert from "node:assert/strict";
import { extractUrls, MAX_URLS } from "./extract.ts";

test("SC7: extracts standard URL + bare domain + defanged URL from one blob", () => {
  const text = `
    Check this out: https://example.com/path?a=1
    Also visit shady-site.com for details.
    And this one: hxxp://evil[.]com/phish
  `;
  const r = extractUrls(text);
  assert.equal(r.urls.length, 3);
  assert.ok(r.urls.includes("https://example.com/path?a=1"));
  assert.ok(r.urls.includes("http://shady-site.com/"));
  assert.ok(r.urls.includes("http://evil.com/phish")); // refanged: hxxp-> http, [.] -> .
  assert.equal(r.truncated, false);
});

test("defanged variants: hxxps, (dot), [:]" , () => {
  const r = extractUrls("hxxps://bank(dot)example(dot)com/login");
  assert.equal(r.urls[0], "https://bank.example.com/login");
});

test("bare tokens without a real TLD are NOT extracted (false-positive guard)", () => {
  const r = extractUrls("See report.final for v1.2 notes, e.g. section 3.1.");
  assert.equal(r.urls.length, 0);
});

test("caps at MAX_URLS and reports truncation, never silently", () => {
  const many = Array.from({ length: MAX_URLS + 7 }, (_, i) => `https://site${i}.com`).join(" ");
  const r = extractUrls(many);
  assert.equal(r.urls.length, MAX_URLS);
  assert.equal(r.truncated, true);
  assert.equal(r.droppedCount, 7);
});

test("deduplicates repeated URLs", () => {
  const r = extractUrls("https://example.com/x https://example.com/x https://example.com/x");
  assert.equal(r.urls.length, 1);
});

test("empty text yields no URLs, no crash", () => {
  const r = extractUrls("just some plain text with no links at all");
  assert.deepEqual(r.urls, []);
  assert.equal(r.truncated, false);
});
