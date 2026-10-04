// Deterministic unit tests for the resolver's pure logic (no network).
// Run: `node --test src/resolver.test.ts`
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertHttpUrl, isPrivateHost, hasCrossDomainHop } from "./resolver.ts";

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
  for (const h of ["localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.255", "169.254.169.254", "0.0.0.0", "::1", "[::1]", "fd00::1", "[fc00::1]"]) {
    assert.equal(isPrivateHost(h), true, `${h} should be private`);
  }
});

test("isPrivateHost allows public hosts", () => {
  for (const h of ["8.8.8.8", "1.1.1.1", "github.com", "example.com", "172.32.0.1", "172.15.0.1", "fdic.gov", "fcbarcelona.com", "fd-login-verify.com"]) {
    assert.equal(isPrivateHost(h), false, `${h} should be public`);
  }
});

test("hasCrossDomainHop: true when the chain jumps domains mid-flight", () => {
  assert.equal(hasCrossDomainHop(["https://bit.ly/x", "https://evil.ru/phish"]), true);
});

test("hasCrossDomainHop: false for same-domain redirects (e.g. http->https on one site)", () => {
  assert.equal(hasCrossDomainHop(["http://example.com/", "https://example.com/"]), false);
});

test("hasCrossDomainHop: false for apex<->www (real prod false-positive, SPEC §20 bug #16)", () => {
  assert.equal(hasCrossDomainHop(["https://anthropic.com/", "https://www.anthropic.com/"]), false);
});

test("hasCrossDomainHop: false for same-registrable-domain subdomain moves (login.x.com -> account.x.com)", () => {
  assert.equal(hasCrossDomainHop(["https://login.example.com/", "https://account.example.com/"]), false);
});

test("hasCrossDomainHop: single-URL chain (no redirect) is never a cross-domain hop", () => {
  assert.equal(hasCrossDomainHop(["https://example.com/"]), false);
});

test("isPrivateHost: IPv4-mapped, link-local and unspecified IPv6, and CGNAT are private; public stays public", () => {
  for (const u of ["http://[::ffff:127.0.0.1]/", "http://[::ffff:169.254.169.254]/", "http://[fe80::1]/", "http://[::]/", "http://100.64.0.1/"]) {
    assert.equal(isPrivateHost(new URL(u).hostname), true, u);
  }
  for (const u of ["http://[2606:4700::1]/", "http://[::ffff:8.8.8.8]/", "http://fdic.gov/", "http://100.128.0.1/"]) {
    assert.equal(isPrivateHost(new URL(u).hostname), false, u);
  }
});
