// Human landing page (served at GET / for text/html requests) and the
// machine-readable MCP server-card (served at /.well-known/mcp/server-card.json).
// Both are public — no bearer gate — so agents and people can discover the
// server without authenticating. Kept out of index.ts to keep the router lean.

export const PROD_ENDPOINT = "https://linkcheck-mcp.kazani.workers.dev/mcp";
const PROD_ORIGIN = "https://linkcheck-mcp.kazani.workers.dev";

// A pragmatic MCP "server card": enough for an agent or directory to understand
// what this server is, where it lives, how it authenticates, and what it exposes.
// (No locked cross-vendor schema exists yet; this mirrors the fields Linkeddit
// and the emerging well-known convention publish.)
export const SERVER_CARD = {
  name: "linkcheck-mcp",
  version: "0.1.0",
  description:
    "Resolve a URL's true destination and judge its safety (SAFE/SUSPICIOUS/DANGEROUS) before anyone opens it — redirect resolution, tracker stripping, phishing heuristics, and live threat-intelligence feeds.",
  endpoint: PROD_ENDPOINT,
  transport: "streamable-http",
  authentication: { type: "none" },
  homepage: PROD_ORIGIN + "/",
  maintainer: "kazani",
  tools: [
    {
      name: "check_url",
      description:
        "Resolve a single URL through its redirects and return a SAFE/SUSPICIOUS/DANGEROUS verdict with the evidence behind it.",
    },
    {
      name: "check_text",
      description:
        "Extract every URL from a block of text (including bare and defanged forms like hxxp://evil[.]com), check each, and return the worst verdict.",
    },
  ],
} as const;

export const SERVER_CARD_JSON = JSON.stringify(SERVER_CARD, null, 2);

// Advertised on the landing page + /health so clients can find the card.
export const LINK_HEADER =
  '</.well-known/mcp/server-card.json>; rel="service-desc"; type="application/json"';

export const LANDING_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>linkcheck — URL safety for AI agents</title>
<meta name="description" content="A remote MCP server that checks where a link actually goes and whether it's safe, before anyone opens it.">
<style>
  :root {
    --bg: #f7f7f5; --fg: #1a1a18; --muted: #6b6b66; --line: #e2e2dd;
    --card: #ffffff; --accent: #1f6feb; --code-bg: #f0f0ec;
    --safe: #1a7f37; --warn: #9a6700; --danger: #b42318;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14140f; --fg: #ececdf; --muted: #9a9a8f; --line: #2b2b24;
      --card: #1c1c16; --accent: #6ba4ff; --code-bg: #22221b;
      --safe: #4ac26b; --warn: #d9a441; --danger: #ff6f61;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 720px; margin: 0 auto; padding: 4rem 1.25rem 6rem; }
  h1 { font-size: 2.1rem; margin: 0 0 .35rem; letter-spacing: -0.02em; }
  .tag { color: var(--muted); font-size: 1.1rem; margin: 0 0 2.25rem; }
  h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin: 2.5rem 0 .75rem; }
  p { margin: 0 0 1rem; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9em; }
  code { background: var(--code-bg); padding: .1em .4em; border-radius: 4px; }
  pre { background: var(--code-bg); border: 1px solid var(--line); border-radius: 10px; padding: 1rem; overflow-x: auto; }
  pre code { background: none; padding: 0; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .endpoint { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap;
    background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: .85rem 1rem; }
  .endpoint code { background: none; font-size: 1rem; }
  .pill { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: var(--safe);
    border: 1px solid var(--safe); border-radius: 999px; padding: .1em .6em; }
  .tools { display: grid; gap: .75rem; }
  .tool { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 1rem 1.1rem; }
  .tool code { background: none; padding: 0; font-size: .95rem; font-weight: 600; }
  .tool p { margin: .35rem 0 0; color: var(--muted); font-size: .93rem; }
  .verdicts { display: flex; gap: 1.1rem; flex-wrap: wrap; margin: .25rem 0 0; font-size: .9rem; }
  .verdicts b.safe { color: var(--safe); } .verdicts b.warn { color: var(--warn); } .verdicts b.danger { color: var(--danger); }
  footer { margin-top: 3.5rem; padding-top: 1.5rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .88rem; }
  .links { display: flex; gap: 1.25rem; flex-wrap: wrap; margin-bottom: .75rem; }
</style>
</head>
<body>
<main class="wrap">
  <h1>linkcheck</h1>
  <p class="tag">URL safety for AI agents — check where a link <em>actually</em> goes, and whether it's safe, before anyone opens it.</p>

  <div class="endpoint">
    <span class="pill">Live</span>
    <code>${PROD_ENDPOINT}</code>
  </div>

  <h2>What it does</h2>
  <p>A remote <a href="https://modelcontextprotocol.io">MCP</a> server. Give it a link and it follows the redirects (HEAD-first, no page render), strips tracking parameters, inspects the structure for phishing tricks (homographs, <code>@</code>-authority, IP-literal hosts), and checks the destination against six live threat-intelligence feeds plus VirusTotal — then returns a tiered verdict with the evidence behind it.</p>
  <p class="verdicts"><b class="safe">SAFE</b> · <b class="warn">SUSPICIOUS</b> · <b class="danger">DANGEROUS</b></p>

  <h2>Tools</h2>
  <div class="tools">
    <div class="tool"><code>check_url(url, compact?)</code>
      <p>Resolve one URL and return a verdict with the full evidence trail. <code>compact:true</code> trims it to verdict / reason / resolvedUrl / degraded.</p></div>
    <div class="tool"><code>check_text(text, compact?)</code>
      <p>Extract every URL from a blob — standard, bare, and defanged (<code>hxxp://evil[.]com</code>) — check each, and return a <code>worstVerdict</code> summary.</p></div>
  </div>
  <p style="margin-top:.9rem;color:var(--muted);font-size:.9rem">There's also a plain <code>POST /check</code> REST endpoint (body <code>{url, compact?}</code>) for non-MCP clients — used by a local pre-flight hook that verifies links before an agent acts on them.</p>

  <h2>Connect (Claude Desktop)</h2>
  <p>Settings → Connectors → Add custom connector, and paste the endpoint. It runs authless, so leave the OAuth fields blank.</p>
  <pre><code>{
  "mcpServers": {
    "linkcheck": {
      "type": "http",
      "url": "${PROD_ENDPOINT}"
    }
  }
}</code></pre>

  <footer>
    <div class="links">
      <a href="/health">/health</a>
      <a href="/.well-known/mcp/server-card.json">server-card.json</a>
      <a href="https://modelcontextprotocol.io">About MCP</a>
    </div>
    Built by <a href="https://kazani.pages.dev">kazani</a>. Threat intel from HaGeZi, URLhaus (abuse.ch), and VirusTotal.
  </footer>
</main>
</body>
</html>`;
