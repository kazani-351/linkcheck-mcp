// Hidden-content surfacer for check_text. Plain code, no model: text can't talk
// a regex out of anything. Finds what an agent reads but a human skimming the
// rendered page or message doesn't see — the extraction half of a prompt-
// injection gate (pattern from juraj.bednar.io's hermes-firewall, 2026-09-28).
//
// It reports, it doesn't judge: a finding means "something here is hidden from
// a human reader", not "this is an injection". Deliberately regex-level HTML
// handling (no DOM in Workers without a dependency): nested same-name hidden
// elements are cut at the first closing tag, which still surfaces the text.

import { HIDDEN_SRC, visible } from "./skillscan.ts";

export const MAX_HIDDEN_FINDINGS = 20;
const MAX_EXCERPT = 200;

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
const TAG_CHAR = /[\u{E0000}-\u{E007F}]/u;
const HIDDEN_ANY = new RegExp(HIDDEN_SRC, "g");

// ZWJ/ZWNJ are legitimate inside emoji sequences and in Indic/Persian script
// shaping; a leading BOM is an encoding artifact. None of those hide anything.
const BENIGN_JOINERS = /(?<=[\p{Extended_Pictographic}️])‍(?=\p{Extended_Pictographic})|(?<=[^\x00-\x7F])[‌‍](?=[^\x00-\x7F])|^﻿/gu;

const COMMENT = /<!--([\s\S]*?)-->/g;
const OPEN_TAG = /<([a-z][a-z0-9-]*)\b([^>]*)>/gi;
const HIDING_STYLE = /style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?![.\d]))/i;
const ID_ATTR = /\sid\s*=\s*(["'])(.*?)\1/gi;
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

/** Decode a base64/base64url token, or null unless it's readable text with words
 *  in it. Hex ids and API tokens decode to binary noise and fail the check. */
function decodeBase64Text(token: string): string | null {
  const b64 = token.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (b64.length % 4 === 1) return null;
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    return null;
  }
  const printable = [...text].filter((c) => /[\p{L}\p{N}\p{P}\p{Zs}]/u.test(c)).length;
  // Base64'd JSON is routine plumbing (analytics payloads, JWT segments).
  if (/^\s*[{[]/.test(text)) return null;
  return printable / Math.max(1, [...text].length) >= 0.9 && wordCount(text) >= 3 ? text : null;
}

export function surfaceHidden(text: string): HiddenResult {
  const all: HiddenFinding[] = [];
  const decoded: string[] = [];

  for (const [run] of text.matchAll(TAG_RUN)) {
    const msg = decodeTags(run);
    if (!msg) continue;
    decoded.push(msg);
    all.push({ kind: "unicode-tags", signal: "strong", why: "invisible Unicode tag characters spell out hidden text", excerpt: excerpt(msg) });
  }

  const invisible = [...text.replace(BENIGN_JOINERS, "").matchAll(HIDDEN_ANY)].filter(([c]) => !TAG_CHAR.test(c));
  if (invisible.length) {
    const kinds = [...new Set(invisible.map(([c]) => visible(c)))].join(" ");
    all.push({ kind: "invisible-chars", signal: "strong", why: `${invisible.length} zero-width or direction-override character(s)`, excerpt: kinds });
  }

  for (const [, body] of text.matchAll(COMMENT)) {
    if (/^\s*\[if\b/i.test(body) || wordCount(body) < 3) continue;
    all.push({ kind: "html-comment", signal: "weak", why: "sentence in an HTML comment (not rendered)", excerpt: excerpt(body) });
  }

  for (const m of text.matchAll(OPEN_TAG)) {
    const [whole, tag, attrs] = m;
    const bareHidden = /(^|\s)hidden(\s|=|\/|$)/i.test(attrs.replace(/"[^"]*"|'[^']*'/g, '""'));
    if (!bareHidden && !HIDING_STYLE.test(attrs)) continue;
    const start = m.index! + whole.length;
    const close = text.toLowerCase().indexOf(`</${tag.toLowerCase()}`, start);
    const inner = text.slice(start, close === -1 ? undefined : close).replace(/<[^>]*>/g, " ");
    if (wordCount(inner) < 3) continue;
    all.push({ kind: "hidden-element", signal: "weak", why: `text inside a hidden <${tag.toLowerCase()}> (display:none, hidden, zero size or opacity)`, excerpt: excerpt(inner) });
  }

  // ids can't legally contain spaces, so a sentence there is only for a reader
  // of the raw HTML — i.e. an agent. Underscore-joined ids are NOT flagged:
  // every Wikipedia section anchor looks like Prompt_injection_and_jailbreak.
  for (const [, , value] of text.matchAll(ID_ATTR)) {
    if (/\s/.test(value.trim()) && wordCount(value) >= 3) all.push({ kind: "id-sentence", signal: "strong", why: "a sentence inside an HTML id attribute", excerpt: excerpt(value) });
  }

  for (const [token] of text.matchAll(BASE64)) {
    const msg = decodeBase64Text(token);
    if (!msg) continue;
    decoded.push(msg);
    all.push({ kind: "base64-text", signal: "strong", why: "base64 that decodes to readable text", excerpt: excerpt(msg) });
  }

  // Strong first, so padding a page with comments can't push them past the cap.
  const ranked = [...all.filter((f) => f.signal === "strong"), ...all.filter((f) => f.signal === "weak")];
  return { found: ranked[0]?.signal === "strong", findings: ranked.slice(0, MAX_HIDDEN_FINDINGS), total: all.length, decoded };
}
