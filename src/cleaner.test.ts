import { test } from "node:test";
import assert from "node:assert/strict";
import { cleanUrl } from "./cleaner.ts";

test("SC6: strips utm_* and fbclid via globalRules", () => {
  const r = cleanUrl("https://example.com/page?utm_source=x&utm_medium=y&fbclid=abc123&id=42");
  assert.equal(r.cleanedUrl, "https://example.com/page?id=42");
  assert.deepEqual(r.removedParams.sort(), ["fbclid", "utm_medium", "utm_source"]);
});

test("enumerates every param with a tracker flag, removes none if no trackers", () => {
  const r = cleanUrl("https://example.com/search?q=hello&page=2");
  assert.equal(r.cleanedUrl, "https://example.com/search?q=hello&page=2");
  assert.equal(r.removedParams.length, 0);
  assert.deepEqual(
    r.queryParams,
    [
      { key: "q", value: "hello", tracker: false },
      { key: "page", value: "2", tracker: false },
    ],
  );
});

test("Google-specific rules strip provider params (ved, ei) alongside global ones", () => {
  const r = cleanUrl("https://www.google.com/search?q=cats&ved=abc&ei=xyz&gclid=123");
  assert.equal(r.cleanedUrl, "https://www.google.com/search?q=cats");
  assert.deepEqual(r.removedParams.sort(), ["ei", "gclid", "ved"]);
});

test("exceptions suppress a provider's rules on matching URLs", () => {
  // globalRules has an exception carving out matrix.org's federation API — a
  // legitimate non-tracker use that happens to overlap tracker-shaped param names.
  const r = cleanUrl("https://matrix.org/_matrix/client/versions?utm_source=x");
  assert.equal(r.removedParams.length, 0, "exception should suppress globalRules here");
});

test("URL with no query string round-trips unchanged", () => {
  const r = cleanUrl("https://example.com/path");
  assert.equal(r.cleanedUrl, "https://example.com/path");
  assert.equal(r.queryParams.length, 0);
});
