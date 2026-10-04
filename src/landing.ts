// Human landing page (served at GET / for text/html requests) and the
// machine-readable MCP server-card (served at /.well-known/mcp/server-card.json).
// Both are public — no bearer gate — so agents and people can discover the
// server without authenticating. Kept out of index.ts to keep the router lean.

export const PROD_ENDPOINT = "https://linkcheck-mcp.kazani.workers.dev/mcp";
export const PROD_ORIGIN = "https://linkcheck-mcp.kazani.workers.dev";
export const REPO_URL = "https://github.com/kazani-351/linkcheck-mcp";

// A pragmatic MCP "server card": enough for an agent or directory to understand
// what this server is, where it lives, how it authenticates, and what it exposes.
// (No locked cross-vendor schema exists yet; this mirrors the fields Linkeddit
// and the emerging well-known convention publish.)
export const SERVER_CARD = {
  name: "linkcheck-mcp",
  version: "0.1.0",
  description:
    "Resolve a URL's true destination and judge its safety (SAFE/SUSPICIOUS/DANGEROUS) before anyone opens it: redirect resolution, tracker stripping, phishing heuristics, and live threat-intelligence feeds.",
  endpoint: PROD_ENDPOINT,
  transport: "streamable-http",
  authentication: { type: "none" },
  homepage: PROD_ORIGIN + "/",
  repository: REPO_URL,
  icon: PROD_ORIGIN + "/icon-256.png",
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
        "Extract every URL from a block of text (including bare and defanged forms like hxxp://evil[.]com), check each, and return the worst verdict. Also surfaces hidden content (Unicode tag text, zero-width characters, base64 text, hidden elements).",
    },
    {
      name: "check_skill",
      description:
        "Statically scan an agent skill (pasted files or a public GitHub folder, pinned to a commit) for risky patterns, and check every URL inside it. Best verdict is NO_FLAGS, never SAFE.",
    },
  ],
} as const;

export const SERVER_CARD_JSON = JSON.stringify(SERVER_CARD, null, 2);

// Advertised on the landing page + /health so clients can find the card.
export const LINK_HEADER =
  '</.well-known/mcp/server-card.json>; rel="service-desc"; type="application/json"';

const DESCRIPTION = "A free MCP server that follows a link's redirects, strips trackers, and checks it against live threat feeds, so an AI agent knows where a link goes before anyone clicks it.";

export function landingHtml(markSvg: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>linkcheck: URL safety for AI agents</title>
<meta name="description" content="${DESCRIPTION}">
<meta name="theme-color" content="#0a0c0b">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta property="og:type" content="website">
<meta property="og:url" content="${PROD_ORIGIN}/">
<meta property="og:title" content="linkcheck: know where a link goes before anyone clicks it">
<meta property="og:description" content="${DESCRIPTION}">
<meta property="og:image" content="${PROD_ORIGIN}/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="${PROD_ORIGIN}/og.png">
<style>
  :root {
    --bg: #0a0c0b; --card: #0f1413; --elev: #111514; --line: #1e2522; --line-soft: #171d1b;
    --text: #e9efec; --dim: #93a39d; --faint: #5f6e69;
    --accent: #5cc8a8; --accent-hover: #6fd6b8; --on-accent: #06231b;
    --safe: #5cc8a8; --warn: #e3b341; --danger: #ff7b72;
    --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    color-scheme: dark;
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    margin: 0; background: var(--bg); color: var(--dim); font: 16px/1.6 var(--sans);
    -webkit-font-smoothing: antialiased;
    background-image: radial-gradient(640px 420px at 100% 0%, rgba(92,200,168,.10), transparent 70%);
    background-repeat: no-repeat;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { color: var(--accent-hover); text-decoration: underline; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 6px; }
  code { font-family: var(--mono); font-size: .88em; color: var(--text); }
  .wrap { max-width: 760px; margin: 0 auto; padding: 1.5rem 16px 5rem; }

  nav { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 4.5rem; }
  .brand { display: flex; align-items: center; gap: .6rem; color: var(--text); font-weight: 650; font-size: 1.1rem; letter-spacing: -.02em; }
  .brand:hover { color: var(--text); text-decoration: none; }
  .brand svg { width: 30px; height: 26px; }
  .navlinks { display: flex; gap: 1.25rem; font-size: .92rem; }
  .navlinks a { color: var(--dim); }
  .navlinks a:hover { color: var(--text); }

  h1 { color: var(--text); font-size: clamp(2.2rem, 7vw, 3.4rem); font-weight: 650; line-height: 1.05; letter-spacing: -.04em; margin: 0 0 1.1rem; }
  h1 em { font-style: normal; color: var(--accent); }
  .lede { font-size: clamp(1.05rem, 2.6vw, 1.2rem); line-height: 1.55; margin: 0 0 2.5rem; max-width: 620px; }

  .card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; }
  .try { padding: 1.25rem; }
  .try form { display: flex; gap: .6rem; }
  .try input {
    flex: 1; min-width: 0; font: 1rem var(--mono); color: var(--text); background: var(--bg);
    border: 1px solid var(--line); border-radius: 10px; padding: .75rem .9rem;
  }
  .try input::placeholder { color: var(--faint); }
  .try input:focus { border-color: var(--accent); outline: none; }
  button {
    font: 600 .95rem var(--sans); border: 0; border-radius: 999px; cursor: pointer;
    background: var(--accent); color: var(--on-accent); padding: .75rem 1.35rem;
  }
  button:hover { background: var(--accent-hover); }
  button:disabled { opacity: .55; cursor: progress; }
  .examples { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin-top: .8rem; font-size: .82rem; color: var(--faint); }
  .examples button { font: .78rem var(--mono); background: none; color: var(--dim); border: 1px solid var(--line); padding: .3rem .7rem; }
  .examples button:hover { color: var(--text); border-color: var(--faint); background: none; }

  .result { margin-top: 1rem; border-top: 1px solid var(--line-soft); padding-top: 1rem; }
  .result[hidden] { display: none; }
  .verdict { display: inline-block; font: 600 .78rem var(--mono); letter-spacing: .08em; border: 1.5px solid currentColor; border-radius: 999px; padding: .2rem .7rem; }
  .v-SAFE { color: var(--safe); } .v-SUSPICIOUS { color: var(--warn); } .v-DANGEROUS { color: var(--danger); }
  .reason { color: var(--text); margin: .6rem 0 .9rem; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .35rem 1rem; margin: 0; font-size: .88rem; }
  dt { color: var(--faint); }
  dd { margin: 0; font-family: var(--mono); font-size: .82rem; color: var(--dim); overflow-wrap: anywhere; }
  .err { color: var(--danger); margin: 0; }
  .fine { font-size: .82rem; color: var(--faint); margin: .9rem 0 0; }

  h2 { color: var(--text); font-size: 1.05rem; font-weight: 600; letter-spacing: -.01em; margin: 3.5rem 0 1rem; }
  .steps { margin: 0; padding: 0; list-style: none; display: grid; gap: .75rem; counter-reset: s; }
  .steps li { counter-increment: s; display: grid; grid-template-columns: 2rem 1fr; }
  .steps li::before { content: counter(s); font: .82rem var(--mono); color: var(--accent); padding-top: .15rem; }
  .steps b { color: var(--text); font-weight: 600; }

  .endpoint { display: flex; align-items: center; gap: .75rem; padding: .7rem .7rem .7rem 1rem; }
  .endpoint code { flex: 1; min-width: 0; overflow-wrap: anywhere; font-size: .9rem; }
  .endpoint button { padding: .5rem 1rem; font-size: .85rem; }
  .connect p { margin: .9rem 0 0; }
  pre { margin: .9rem 0 0; background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 1rem; overflow-x: auto; }
  pre code { font-size: .82rem; color: var(--dim); }

  .tools { display: grid; gap: .75rem; }
  .tool { padding: 1rem 1.1rem; }
  .tool h3 { margin: 0; font: 600 .95rem var(--mono); color: var(--text); }
  .tool p { margin: .35rem 0 0; font-size: .92rem; line-height: 1.5; }

  footer { margin-top: 4rem; padding-top: 1.5rem; border-top: 1px solid var(--line-soft); color: var(--faint); font-size: .86rem; }
  footer .links { display: flex; flex-wrap: wrap; gap: .5rem 1.25rem; margin-bottom: .6rem; }
  footer a { color: var(--dim); }

  @media (max-width: 520px) {
    nav { margin-bottom: 3rem; }
    .try form { flex-direction: column; }
    .try button[type=submit] { width: 100%; }
    dl { grid-template-columns: 1fr; gap: .1rem; }
    dd { margin-bottom: .45rem; }
  }
  @media (prefers-reduced-motion: no-preference) {
    .result:not([hidden]) { animation: rise .25s ease-out; }
    @keyframes rise { from { opacity: 0; transform: translateY(4px); } }
  }
</style>
</head>
<body>
<div class="wrap">
  <nav>
    <a class="brand" href="/" aria-label="linkcheck home">${markSvg}<span>linkcheck</span></a>
    <div class="navlinks"><a href="#connect">Connect</a><a href="${REPO_URL}">GitHub</a></div>
  </nav>

  <main>
    <h1>Know where a link <em>actually</em> goes, before anyone clicks it.</h1>
    <p class="lede">linkcheck is a free <a href="https://modelcontextprotocol.io">MCP</a> server for AI agents. It follows a link's redirects without loading the page, strips trackers, looks for phishing tricks, and checks the destination against live threat feeds. Then it gives a plain verdict with the evidence.</p>

    <section class="card try" aria-labelledby="try-label">
      <form id="f">
        <label id="try-label" for="u" style="position:absolute;left:-9999px">Link to check</label>
        <input id="u" name="url" type="text" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="2048" placeholder="Paste a link" required>
        <button type="submit" id="go">Check</button>
      </form>
      <div class="examples">Try:
        <button type="button" data-u="https://example.com/?utm_source=newsletter&amp;fbclid=abc123">a link with trackers</button>
        <button type="button" data-u="http://example.com">plain http</button>
      </div>
      <div class="result" id="out" hidden aria-live="polite"></div>
      <p class="fine">The page is never rendered: linkcheck only reads redirect headers. Links you check are not stored. Public checks use the six feeds and the structural checks; VirusTotal is reserved for the maintainer's own key. Verdicts are a best-effort signal, not a guarantee: a SAFE link can still turn out to be bad.</p>
    </section>

    <h2>How it decides</h2>
    <ol class="steps">
      <li><span><b>Follow the redirects.</b> HEAD requests only, so the page never loads and nothing runs. Shorteners and redirect chains are unwound to the real destination.</span></li>
      <li><span><b>Clean it.</b> Tracking parameters like <code>utm_*</code> and <code>fbclid</code> are stripped and listed.</span></li>
      <li><span><b>Inspect the shape.</b> Lookalike characters, <code>@</code> tricks, raw IP hosts, and abused domain endings.</span></li>
      <li><span><b>Check the feeds.</b> URLhaus plus five HaGeZi lists (threat intel, newly registered domains, shorteners, abused domain endings), refreshed daily. If any check can't finish, the verdict can only get stricter, never SAFE.</span></li>
    </ol>

    <h2 id="connect">Connect it to your agent</h2>
    <div class="connect">
      <div class="card endpoint"><code id="ep">${PROD_ENDPOINT}</code><button type="button" id="copy">Copy</button></div>
      <p><b style="color:var(--text);font-weight:600">Claude:</b> Settings → Connectors → Add custom connector. Paste the URL above and pick <i>No sign-in</i>. No account or key needed.</p>
      <p><b style="color:var(--text);font-weight:600">Other MCP clients:</b></p>
      <pre><code>{
  "mcpServers": {
    "linkcheck": {
      "type": "http",
      "url": "${PROD_ENDPOINT}"
    }
  }
}</code></pre>
    </div>

    <h2>Tools</h2>
    <div class="tools">
      <div class="card tool"><h3>check_url</h3><p>One link in, a SAFE / SUSPICIOUS / DANGEROUS verdict out, with the redirect chain, removed trackers, and every feed hit.</p></div>
      <div class="card tool"><h3>check_text</h3><p>Paste an email, message, or page. Every link is found, including defanged ones like <code>hxxp://evil[.]com</code>, and checked. It also surfaces text hidden from human readers, like invisible Unicode or base64.</p></div>
      <div class="card tool"><h3>check_skill</h3><p>Scan an agent skill before you install it: risky patterns in its files, pinned to a GitHub commit, plus a check of every link inside.</p></div>
    </div>
  </main>

  <footer>
    <div class="links">
      <a href="${REPO_URL}">Source on GitHub</a>
      <a href="/.well-known/mcp/server-card.json">Server card</a>
      <a href="/health">Status</a>
    </div>
    Built by <a href="https://kazani.pages.dev">kazani</a>. Threat intel from <a href="https://urlhaus.abuse.ch">URLhaus</a> and <a href="https://github.com/hagezi/dns-blocklists">HaGeZi</a>.
  </footer>
</div>
<script>
(() => {
  const f = document.getElementById("f"), u = document.getElementById("u"), go = document.getElementById("go"), out = document.getElementById("out");
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const row = (dl, k, v) => { dl.append(el("dt", null, k), el("dd", null, v)); };

  async function check(url) {
    go.disabled = true; go.textContent = "Checking…";
    out.hidden = false; out.replaceChildren(el("p", "reason", "Following redirects…"));
    try {
      const res = await fetch("/check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }), signal: AbortSignal.timeout(25000) });
      const r = await res.json();
      if (!res.ok || !r.verdict) throw new Error(r.error || "the check failed (" + res.status + ")");
      const dl = el("dl");
      row(dl, "Goes to", r.finalUrl);
      if (r.chain && r.chain.length > 1) row(dl, "Redirects", (r.chain.length - 1) + " hop" + (r.chain.length > 2 ? "s" : "") + ": " + r.chain.join(" → "));
      if (r.removedParams && r.removedParams.length) row(dl, "Trackers", r.removedParams.join(", "));
      if (r.removedParams && r.removedParams.length) row(dl, "Clean link", r.cleanedUrl);
      row(dl, "Feed hits", r.feedSignals && r.feedSignals.length ? r.feedSignals.map((s) => s.source).join(", ") : "none");
      out.replaceChildren(el("span", "verdict v-" + r.verdict, r.verdict), el("p", "reason", r.verdictReason), dl);
    } catch (e) {
      out.replaceChildren(el("p", "err", "Couldn't check that link: " + (e.name === "TimeoutError" ? "it took too long" : e.message)));
    } finally {
      go.disabled = false; go.textContent = "Check";
    }
  }
  f.addEventListener("submit", (e) => { e.preventDefault(); const v = u.value.trim(); if (v) check(v); });
  document.querySelectorAll("[data-u]").forEach((b) => b.addEventListener("click", () => { u.value = b.dataset.u; check(b.dataset.u); }));
  const copy = document.getElementById("copy");
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(document.getElementById("ep").textContent); copy.textContent = "Copied"; }
    catch { copy.textContent = "Select and copy"; }
    setTimeout(() => (copy.textContent = "Copy"), 1600);
  });
})();
</script>
</body>
</html>`;
}
