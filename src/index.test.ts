// Full-stack tests for the Worker fetch wrapper (auth gate + MCP protocol routing),
// run in plain Node — workerd/wrangler dev is unavailable on macOS < 13.5, so we
// exercise the web-standard handler directly. Run: `node --test src/index.test.ts`
import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "./index.ts";

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const ENV = { MCP_BEARER_TOKEN: "test-secret" };

function mcpReq(body: unknown, auth?: string): Request {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    host: "localhost", // handler's DNS-rebinding guard requires a Host it trusts
  };
  if (auth) headers.authorization = `Bearer ${auth}`;
  return new Request("http://localhost/mcp", { method: "POST", headers, body: JSON.stringify(body) });
}

test("/health returns ok without auth", async () => {
  const res = await worker.fetch(new Request("http://localhost/health"), ENV, ctx);
  assert.equal(res.status, 200);
  assert.equal((await res.json() as { status: string }).status, "ok");
});

test("POST /mcp without bearer -> 401", async () => {
  const res = await worker.fetch(mcpReq({ jsonrpc: "2.0", id: 1, method: "tools/list" }), ENV, ctx);
  assert.equal(res.status, 401);
});

test("POST /mcp with wrong bearer -> 401", async () => {
  const res = await worker.fetch(mcpReq({ jsonrpc: "2.0", id: 1, method: "tools/list" }, "nope"), ENV, ctx);
  assert.equal(res.status, 401);
});

test("tools/list with valid bearer returns check_url", async () => {
  const res = await worker.fetch(mcpReq({ jsonrpc: "2.0", id: 1, method: "tools/list" }, "test-secret"), ENV, ctx);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /"name":"check_url"/);
});

test("check_url end-to-end: resolves AND strips trackers from the final URL", async () => {
  // example.com is a plain IANA test domain with no ClearURLs-specific provider,
  // so globalRules' utm_*/fbclid stripping applies (unlike e.g. github.com, which
  // ClearURLs deliberately exempts from globalRules in favor of its own narrow rules).
  const res = await worker.fetch(
    mcpReq(
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "check_url", arguments: { url: "https://example.com/?utm_source=test&fbclid=abc" } },
      },
      "test-secret",
    ),
    ENV,
    ctx,
  );
  assert.equal(res.status, 200);
  const text = await res.text();
  // Unwrap the double-encoded content: SSE frame -> JSON-RPC result -> tool's text payload.
  const rpcResult = JSON.parse(text.split("data: ")[1]);
  const payload = JSON.parse(rpcResult.result.content[0].text);
  // No redirect occurs (example.com answers 200 directly), so finalUrl retains the
  // original query string — cleaning is a separate step, reflected only in cleanedUrl.
  assert.equal(payload.finalUrl, "https://example.com/?utm_source=test&fbclid=abc");
  assert.equal(payload.cleanedUrl, "https://example.com/");
  assert.deepEqual(payload.removedParams.sort(), ["fbclid", "utm_source"]);
});

test("check_url flags heuristic hits for a structurally suspicious URL", async () => {
  const res = await worker.fetch(
    mcpReq(
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        // no network hop needed: resolveUrl on a non-redirecting target still runs
        // (the private-IP guard fires before any fetch, so this is instant + offline)
        params: { name: "check_url", arguments: { url: "http://169.254.169.254/paypal" } },
      },
      "test-secret",
    ),
    ENV,
    ctx,
  );
  assert.equal(res.status, 200);
  const rpcResult = JSON.parse((await res.text()).split("data: ")[1]);
  const payload = JSON.parse(rpcResult.result.content[0].text);
  assert.equal(payload.stoppedReason, "private_host");
  const ids = payload.heuristics.map((h: { id: string }) => h.id);
  assert.ok(ids.includes("ip_literal_host"));
});

test("tools/list includes check_text", async () => {
  const res = await worker.fetch(mcpReq({ jsonrpc: "2.0", id: 4, method: "tools/list" }, "test-secret"), ENV, ctx);
  assert.match(await res.text(), /"name":"check_text"/);
});

test("check_text end-to-end: extracts and checks multiple URLs from a blob", async () => {
  const text = "Please review https://example.com/?utm_source=x and also http://169.254.169.254/internal";
  const res = await worker.fetch(
    mcpReq(
      { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "check_text", arguments: { text } } },
      "test-secret",
    ),
    ENV,
    ctx,
  );
  assert.equal(res.status, 200);
  const rpcResult = JSON.parse((await res.text()).split("data: ")[1]);
  const payload = JSON.parse(rpcResult.result.content[0].text);
  assert.equal(payload.checked.length, 2);
  assert.equal(payload.truncated, false);
  const cleanOne = payload.checked.find((c: { url: string }) => c.url.includes("example.com"));
  assert.deepEqual(cleanOne.removedParams, ["utm_source"]);
  const badOne = payload.checked.find((c: { url: string }) => c.url.includes("169.254"));
  assert.ok(badOne.heuristics.some((h: { id: string }) => h.id === "ip_literal_host"));
});
