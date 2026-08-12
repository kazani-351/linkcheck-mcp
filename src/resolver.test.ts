// Deterministic unit tests for the resolver's pure logic (no network).
// Run: `node --test src/resolver.test.ts`
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertHttpUrl, isPrivateHost } from "./resolver.ts";

test("assertHttpUrl accepts http and https", () => {
  assert.equal(assertHttpUrl("https://example.com").protocol, "https:");
  assert.equal(assertHttpUrl("http://example.com").protocol, "http:");
});

test("assertHttpUrl rejects non-http schemes and junk", () => {
  for (const bad of ["ftp://x.com", "javascript:alert(1)", "data:text/html,x", "mailto:a@b.c", "not a url"]) {
    assert.throws(() => assertHttpUrl(bad), `should reject ${bad}`);
  }
});

test("isPrivateHost flags loopback, private, link-local, metadata", () => {
  for (const h of ["localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.255", "169.254.169.254", "0.0.0.0", "::1"]) {
    assert.equal(isPrivateHost(h), true, `${h} should be private`);
  }
});

test("isPrivateHost allows public hosts", () => {
  for (const h of ["8.8.8.8", "1.1.1.1", "github.com", "example.com", "172.32.0.1", "172.15.0.1"]) {
    assert.equal(isPrivateHost(h), false, `${h} should be public`);
  }
});
