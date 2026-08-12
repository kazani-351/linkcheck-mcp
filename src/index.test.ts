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
