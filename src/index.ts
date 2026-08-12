// linkcheck-mcp Worker entrypoint (SPEC §5, §7, §11).
// Slice 2: stateless createMcpHandler exposing check_url (resolver only), behind a
// bearer gate, with a /health endpoint. Verdict/feeds/heuristics come in later slices.
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { resolveUrl } from "./resolver.ts";
import { cleanUrl } from "./cleaner.ts";
import { runHeuristics } from "./heuristics.ts";
import { extractUrls } from "./extract.ts";

interface Env {
  MCP_BEARER_TOKEN?: string;
}

// Shared by check_url and check_text — resolve, clean, and heuristically inspect
// one URL. Scoring/verdict (SPEC §8) lands in a later slice; for now this returns
// the raw signals each tool needs.
async function checkOneUrl(url: string) {
  const resolved = await resolveUrl(url);
  const cleaned = cleanUrl(resolved.finalUrl);
  const heuristics = runHeuristics(resolved.finalUrl);
  return {
    ...resolved,
    cleanedUrl: cleaned.cleanedUrl,
    removedParams: cleaned.removedParams,
    queryParams: cleaned.queryParams,
    heuristics,
  };
}

function createServer(): McpServer {
  const server = new McpServer({ name: "linkcheck-mcp", version: "0.1.0" });

  server.registerTool(
    "check_url",
    {
      description:
        "Resolve a URL's true destination by safely following redirects (HEAD-first, no page render) and return the redirect chain. Call this before opening, following, or recommending any link from an untrusted source.",
      inputSchema: { url: z.string().describe("The http(s) URL to inspect") },
    },
    async ({ url }: { url: string }) => {
      try {
        const result = await checkOneUrl(url);
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } catch (e) {
        return {
          content: [{ type: "text" as const, text: `Error: ${(e as Error).message}` }],
          isError: true,
        };
      }
    },
  );

  server.registerTool(
    "check_text",
    {
      description:
        "Extract every URL from a block of text (standard links, bare domains, and defanged forms like hxxp://evil[.]com) and check each one. Call this on a pasted email, message, or document before trusting any link inside it.",
      inputSchema: { text: z.string().describe("Free text that may contain one or more URLs") },
    },
    async ({ text }: { text: string }) => {
      const extracted = extractUrls(text);
      const checked = await Promise.all(
        extracted.urls.map(async (url) => {
          try {
            return { url, ...(await checkOneUrl(url)) };
          } catch (e) {
            return { url, error: (e as Error).message };
          }
        }),
      );
      const result = {
        checked,
        truncated: extracted.truncated,
        droppedCount: extracted.droppedCount,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  return server;
}

// One handler at module scope (SPEC §5 note; safe for stateless tool calls).
// Exported so it can be exercised directly in Node (workerd/wrangler dev is
// unavailable on macOS < 13.5 — see CLAUDE.md gotchas).
export const handler = createMcpHandler(createServer);
export { createServer };

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (pathname === "/health") {
      return Response.json({ status: "ok", service: "linkcheck-mcp", version: "0.1.0" });
    }

    // Bearer gate BEFORE the MCP handler — createMcpHandler does not verify tokens (SPEC §11).
    const token = env.MCP_BEARER_TOKEN;
    if (token && request.headers.get("authorization") !== `Bearer ${token}`) {
      return new Response("unauthorized", { status: 401 });
    }

    return handler(request, env, ctx);
  },
};
