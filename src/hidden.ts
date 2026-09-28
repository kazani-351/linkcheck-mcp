// Hidden-content surfacer for check_text. Plain code, no model: text can't talk
// a regex out of anything. Finds what an agent reads but a human skimming the
// rendered page or message doesn't see — the extraction half of a prompt-
// injection gate (pattern from juraj.bednar.io's hermes-firewall, 2026-09-28).
//
// It reports, it doesn't judge: a finding means "something here is hidden from
// a human reader", not "this is an injection". Deliberately regex-level HTML
// handling (no DOM in Workers without a dependency): nested same-name hidden
// elements are cut at the first closing tag, which still surfaces the text.

import { INVISIBLE_SRC, visible } from "./skillscan.ts";

export const MAX_HIDDEN_FINDINGS = 20;
const MAX_EXCERPT = 200;
// Every scan below looks at most this far past its starting point, so total
// work stays linear in input size (a Worker gets ~2 s of CPU). A hidden
// element or unclosed comment longer than this is still reported, just from
// its first MAX_SPAN characters.
const MAX_SPAN = 4096;

export type HiddenKind =
  | "unicode-tags"
  | "invisible-chars"
  | "html-comment"
  | "hidden-element"
  | "id-sentence"
  | "base64-text";

export interface HiddenFinding {
  kind: HiddenKind;
  /** strong = rarely legitimate. weak = common on normal pages (dev comments,
   *  collapsed menus, "signed in another tab" banners) — context, not alarm. */
  signal: "strong" | "weak";
  why: string;
  excerpt: string;
}

export interface HiddenResult {
  /** True only when a strong finding exists — weak ones alone don't set it. */
  found: boolean;
  /** Capped at MAX_HIDDEN_FINDINGS — findings quote untrusted text back to the caller. */
  findings: HiddenFinding[];
  total: number;
  /** Decoded text that wasn't readable in the input (tag chars, base64), so the
   *  caller can run URL extraction over it too. */
  decoded: string[];
}

// Unicode tag block U+E0000–E007F: invisible, but U+E0020–E007E map 1:1 onto
// printable ASCII, so a run of them is a hidden plain-text message.
const TAG_RUN = /[\u{E0000}-\u{E007F}]+/gu;
// Subdivision flag emoji (England, Scotland, Wales) are U+1F3F4 followed by a
// lowercase tag-letter code and CANCEL TAG — tag characters with a real job.
const BLACK_FLAG = 0x1f3f4;
const FLAG_TAGS = /^[\u{E0030}-\u{E0039}\u{E0061}-\u{E007A}]{2,7}\u{E007F}$/u;
const INVISIBLE = new RegExp(INVISIBLE_SRC, "g");

// ZWJ/ZWNJ are legitimate inside emoji sequences and in Indic/Persian script
// shaping; a leading BOM is an encoding artifact. None of those hide anything.
const BENIGN_JOINERS = /(?<=[\p{Extended_Pictographic}\uFE0F])\u200D(?=\p{Extended_Pictographic})|(?<=[^\x00-\x7F])[\u200C\u200D](?=[^\x00-\x7F])|^\uFEFF/gu;

const OPEN_TAG = /<([a-z][a-z0-9-]*)\b([^<>]{0,2048})>/gi;
const HIDING_STYLE = /style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?![.\d]))/i;
const ID_ATTR = /\sid\s*=\s*(["'])([^"'<>\n]{0,512})\1/gi;
const BASE64 = /[A-Za-z0-9+/_-]{24,}={0,2}/g;

function wordCount(s: string): number {
  return s.match(/\p{L}{2,}/gu)?.length ?? 0;
}

function excerpt(s: string): string {
  const one = visible(s.replace(/\s+/g, " ").trim());
  return one.length > MAX_EXCERPT ? `${one.slice(0, MAX_EXCERPT)}…` : one;
}

function decodeTags(run: string): string {
  let out = "";
  for (const ch of run) {
    const cp = ch.codePointAt(0)! - 0xe0000;
    if (cp >= 0x20 && cp <= 0x7e) out += String.fromCharCode(cp);
  }
  return out;
}

/** Index of `</tag` in `window` (case-insensitive), or -1. Walks "</" hits so
 *  the cost is the distance to the close, not a lowercase of the whole window. */
function findClose(window: string, tag: string): number {
  for (let i = window.indexOf("</"); i !== -1; i = window.indexOf("</", i + 2)) {
    if (window.slice(i + 2, i + 2 + tag.length).toLowerCase() === tag) return i;
  }
  return -1;
}

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
// Most BASE64 candidates are URL paths and ids that decode to binary noise;
// rejecting control bytes on the atob string skips the costly fatal-decode throw.
const CONTROL_BYTES = /[\x00-\x08\x0E-\x1F\x7F]/;
const PRINTABLE = /[\p{L}\p{N}\p{P}\p{Zs}]/gu;

/** Decode a base64/base64url token, or null unless it's readable text with words
 *  in it. Hex ids and API tokens decode to binary noise and fail the check. */
function decodeBase64Text(token: string): string | null {
  const b64 = token.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (b64.length % 4 === 1) return null;
  let text: string;
  try {
    const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    if (CONTROL_BYTES.test(binary)) return null;
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    text = UTF8.decode(bytes);
  } catch {
    return null;
  }
  const printable = text.match(PRINTABLE)?.length ?? 0;
  return printable / Math.max(1, [...text].length) >= 0.9 && wordCount(text) >= 3 ? text : null;
}

export function surfaceHidden(text: string): HiddenResult {
  // Strong and weak kept apart so strong ones lead: padding a page with
  // comments can't push them past the cap.
  const strong: HiddenFinding[] = [];
  const weak: HiddenFinding[] = [];
  const add = (f: HiddenFinding) => (f.signal === "strong" ? strong : weak).push(f);
  const decoded: string[] = [];
  const addDecoded = (msg: string) => {
    if (decoded.length < MAX_HIDDEN_FINDINGS) decoded.push(msg.slice(0, MAX_SPAN));
  };

  for (const m of text.matchAll(TAG_RUN)) {
    const run = m[0];
    if (text.codePointAt(m.index! - 2) === BLACK_FLAG && FLAG_TAGS.test(run)) continue;
    const msg = decodeTags(run);
    if (!msg) continue;
    addDecoded(msg);
    add({ kind: "unicode-tags", signal: "strong", why: "invisible Unicode tag characters spell out hidden text", excerpt: excerpt(msg) });
  }

  let invisibleCount = 0;
  const invisibleKinds = new Set<string>();
  for (const [c] of text.replace(BENIGN_JOINERS, "").matchAll(INVISIBLE)) {
    invisibleCount++;
    invisibleKinds.add(c);
  }
  if (invisibleCount) {
    const kinds = [...invisibleKinds].map(visible).join(" ");
    add({ kind: "invisible-chars", signal: "strong", why: `${invisibleCount} zero-width or direction-override character(s)`, excerpt: kinds });
  }

  // indexOf, not a lazy regex: /<!--[\s\S]*?-->/ rescans to the end of the
  // input from every unclosed "<!--". An unclosed comment hides the rest of
  // the page from a browser, so it's reported (from its first MAX_SPAN chars).
  for (let open = text.indexOf("<!--"); open !== -1; ) {
    const close = text.indexOf("-->", open + 4);
    const body = text.slice(open + 4, Math.min(close === -1 ? text.length : close, open + 4 + MAX_SPAN));
    if (!/^\s*\[if\b/i.test(body) && wordCount(body) >= 3) {
      add({ kind: "html-comment", signal: "weak", why: "sentence in an HTML comment (not rendered)", excerpt: excerpt(body) });
    }
    if (close === -1) break;
    open = text.indexOf("<!--", close + 3);
  }

  // Tags inside a region already scanned are skipped (their text is in that
  // excerpt), so each character is windowed at most once.
  let scannedUntil = 0;
  for (const m of text.matchAll(OPEN_TAG)) {
    const [whole, tag, attrs] = m;
    if (m.index! < scannedUntil) continue;
    const bareHidden = /(^|\s)hidden(\s|=|\/|$)/i.test(attrs.replace(/"[^"]*"|'[^']*'/g, '""'));
    if (!bareHidden && !HIDING_STYLE.test(attrs)) continue;
    const start = m.index! + whole.length;
    const window = text.slice(start, start + MAX_SPAN);
    const close = findClose(window, tag.toLowerCase());
    scannedUntil = start + (close === -1 ? window.length : close);
    const inner = window.slice(0, close === -1 ? undefined : close).replace(/<[^>]*>/g, " ");
    if (wordCount(inner) < 3) continue;
    add({ kind: "hidden-element", signal: "weak", why: `text inside a hidden <${tag.toLowerCase()}> (display:none, hidden, zero size or opacity)`, excerpt: excerpt(inner) });
  }

  // ids can't legally contain spaces, so a sentence there is only for a reader
  // of the raw HTML — i.e. an agent. Underscore-joined ids are NOT flagged:
  // every Wikipedia section anchor looks like Prompt_injection_and_jailbreak.
  for (const [, , value] of text.matchAll(ID_ATTR)) {
    if (!/\s/.test(value.trim()) || wordCount(value) < 3) continue;
    add({ kind: "id-sentence", signal: "strong", why: "a sentence inside an HTML id attribute", excerpt: excerpt(value) });
  }

  for (const [token] of text.matchAll(BASE64)) {
    const msg = decodeBase64Text(token);
    if (!msg) continue;
    // URLs inside get checked either way, but base64'd JSON is routine plumbing
    // (analytics payloads, JWT segments), so it isn't reported as hidden text.
    addDecoded(msg);
    if (/^\s*[{[]/.test(msg)) continue;
    add({ kind: "base64-text", signal: "strong", why: "base64 that decodes to readable text", excerpt: excerpt(msg) });
  }

  const ranked = [...strong, ...weak];
  return { found: strong.length > 0, findings: ranked.slice(0, MAX_HIDDEN_FINDINGS), total: ranked.length, decoded };
}
