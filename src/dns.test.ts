import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveIp } from "./dns.ts";

// Real network, like resolver.test.ts — DoH is exactly the kind of thing worth
// verifying against live infra rather than a mock (SPEC's "prove the risky part
// first" pattern, same as the resolver kill-criterion probe).

test("resolveIp: real domain returns a plausible IPv4", async () => {
  const r = await resolveIp("github.com");
  assert.ok(r.ip, "expected an IP");
  assert.match(r.ip!, /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
  assert.equal(r.degraded, undefined);
});

test("resolveIp: nonexistent domain degrades loud, never throws", async () => {
  const r = await resolveIp("this-domain-should-not-exist-linkcheck-probe-xyz123.invalid");
  assert.equal(r.ip, null);
  assert.ok(r.degraded, "expected a degraded reason for an unresolvable domain");
});
