// Deterministic static scan of an agent skill (SPEC §7 check_skill). Shared,
// byte-for-byte, with the skill-attest CLI — keep it dependency-free and
// web-standard (crypto.subtle, TextEncoder) so it runs in Workers AND Node.
//
// Two outputs:
// 1. A SEP-2640-shaped `resources` manifest (per-file sha256 + size) and a
//    digestSetHash over it — the exact "atomic unit of things-users-consent-to"
//    the MCP Skills extension binds approvals to.
// 2. Rule findings with file:line evidence, and a verdict.
//
// Never false-SAFE (SPEC §13): a regex scan cannot prove a skill is safe, so the
// best verdict is NO_FLAGS, never SAFE. Same input + same SCANNER_VERSION/rulesHash
// → same findings and verdict, so anyone can re-run it ("verifiable, not trusted").

export const SCANNER_NAME = "skillscan";
export const SCANNER_VERSION = "0.1.0";

export const MAX_FILES = 200;
export const MAX_FILE_BYTES = 512 * 1024;
export const MAX_TOTAL_BYTES = 2 * 1024 * 1024;

export type Severity = "high" | "medium";
export type SkillVerdict = "DANGEROUS" | "SUSPICIOUS" | "NO_FLAGS";

interface Rule {
  id: string;
  severity: Severity;
  why: string;
  re: RegExp;
}

// Ported from the vet-install skill's scan list (network / destructive /
// credentials / self-modification / execution / install hooks / remote-exec +
// secret-exfil combos / unauthorized git push), plus hidden-text and injection
// phrasing, which matter more for skills than packages: a skill IS model input.
// Order is part of the rules hash — append, don't reorder.
export const RULES: readonly Rule[] = [
  {
    id: "remote-exec",
    severity: "high",
    why: "downloads and executes code, or runs an inline interpreter",
    re: /\b(curl|wget)\b[^\n]{0,160}\|\s*(sudo\s+)?(sh|bash|zsh)\b|\b(bash|sh)\s+-c\b|\bpython3?\s+-c\b|\bnode\s+-e\b/,
  },
  {
    id: "secret-exfil",
    severity: "high",
    why: "reads a secret and sends it over the network on the same line",
    re: /\b(cat|printenv|env|grep)\b[^\n]{0,160}(\.aws\/credentials|\.ssh\/|\.npmrc|id_rsa|API_KEY|TOKEN|SECRET)[^\n]{0,160}\b(curl|wget|nc|netcat|scp)\b/,
  },
  {
    id: "credential-path",
    severity: "high",
    why: "references a credential file or key material",
    re: /(~|\$HOME)?\/?\.(aws\/credentials|ssh\/|npmrc|pypirc|netrc|docker\/config\.json|kube\/config)|\bid_(rsa|ed25519)\b|\.mcp\.json\b|\bkubeconfig\b|[\w-]+\.(pem|p12|pfx)\b/,
  },
  {
    id: "destructive",
    severity: "high",
    why: "deletes or overwrites data broadly",
    re: /\brm\s+-(rf|fr|r)\b|\bdd\s+if=|\bmkfs(\.\w+)?\b|\bshred\b/,
  },
  {
    id: "git-push",
    severity: "high",
    why: "pushes to a git remote on its own",
    re: /\bgit[\s_-]+push\b|["'`]git["'`]\s*,\s*\[?\s*["'`]push["'`]/,
  },
  {
    id: "install-hook",
    severity: "high",
    why: "package lifecycle script runs automatically on install",
    re: /"(pre|post)?install"\s*:/,
  },
  {
    id: "hidden-text",
    severity: "high",
    why: "invisible or direction-overriding characters can hide instructions from a human reviewer",
    re: /[​-‏‪-‮⁠-⁤⁦-⁩﻿]|\uDB40[\uDC00-\uDC7F]/,
  },
  {
    id: "injection-phrasing",
    severity: "high",
    why: "instruction-override or concealment phrasing aimed at the model",
    re: /\bignore (all |any )?(previous|prior|above) instructions\b|\bdo not (tell|inform|mention (this )?to) the user\b|\bwithout (telling|informing|asking) the user\b/i,
  },
  {
    id: "self-modification",
    severity: "medium",
    why: "touches agent config, hooks, or other skills",
    re: /\.claude\/(settings(\.local)?\.json|hooks|skills|commands)\b|\bCLAUDE\.md\b|\bAGENTS\.md\b/,
  },
  {
    id: "code-execution",
    severity: "medium",
    why: "dynamic code execution or process spawning",
    re: /\beval\s*\(|\bexec(Sync)?\s*\(|\bchild_process\b|\bsubprocess\b|\bos\.system\s*\(|\bbase64\s+(-d|--decode)\b|\batob\s*\(/,
  },
  {
    id: "network",
    severity: "medium",
    why: "makes network requests",
    re: /\b(curl|wget)\b|\bfetch\s*\(|\baxios\b|\brequests\.(get|post|put)\b|\burllib\b/,
  },
];

export interface SkillFile {
  path: string;
  content: string;
}

export interface Finding {
  rule: string;
  severity: Severity;
  why: string;
  file: string;
  line: number;
  excerpt: string;
}

export interface SkillResource {
  path: string;
  digest: string;
  size: number;
}

export interface SkillScan {
  scanner: { name: string; version: string; rulesHash: string };
  skillName: string | null;
  description: string | null;
  resources: SkillResource[];
  digestSetHash: string;
  verdict: SkillVerdict;
  verdictReason: string;
  findings: Finding[];
  urls: string[];
  degraded: string[];
  limits: string;
}

const LIMITS =
  "Static pattern scan only. It cannot prove a skill is safe: it misses obfuscated or novel payloads and cannot see what fetched URLs serve at run time. NO_FLAGS means no known-bad pattern matched, not SAFE.";

async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function rulesHash(): Promise<string> {
  const canon = RULES.map((r) => `${r.id}\t${r.severity}\t${r.re.source}\t${r.re.flags}`).join("\n");
  return "sha256:" + (await sha256Hex(SCANNER_VERSION + "\n" + canon));
}

/** digestSetHash = sha256 over sorted "path\0digest" lines — changes if any file
 *  is added, removed, renamed, or edited, mirroring SEP-2640's rule that the
 *  whole `resources` set is what an approval binds to. */
export async function digestSetHash(resources: SkillResource[]): Promise<string> {
  const lines = resources
    .map((r) => `${r.path}\0${r.digest}`)
    .sort()
    .join("\n");
  return "sha256:" + (await sha256Hex(lines));
}

/** Flat `key: value` read of SKILL.md frontmatter — enough for name/description.
 *  Deliberately not a YAML parser (no dependency); nested values are ignored. */
export function readFrontmatter(md: string): Record<string, string> {
  const m = md.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  const out: Record<string, string> = {};
  if (!m) return out;
  for (const line of m[1].split(/\r?\n/)) {
    const kv = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (kv) out[kv[1]] = kv[2].replace(/^["']|["']$/g, "").trim();
  }
  return out;
}

const URL_RE = /\bhttps?:\/\/[^\s<>"'`)\]}]+/g;

function normalizePath(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.?\/+/, "");
}

export async function scanSkill(input: SkillFile[]): Promise<SkillScan> {
  const degraded: string[] = [];
  let files = input.map((f) => ({ path: normalizePath(f.path), content: f.content }));

  if (files.length > MAX_FILES) {
    degraded.push(`truncated: ${files.length} files, scanned first ${MAX_FILES}`);
    files = files.slice(0, MAX_FILES);
  }

  const enc = new TextEncoder();
  const resources: SkillResource[] = [];
  const findings: Finding[] = [];
  const urls = new Set<string>();
  let total = 0;

  // Code-unit order, not localeCompare — locale collation differs across
  // runtimes, which would break "same input → same scan" between CLI and Worker.
  for (const f of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    const bytes = enc.encode(f.content);
    resources.push({ path: f.path, digest: "sha256:" + (await sha256Hex(bytes)), size: bytes.length });
    total += bytes.length;

    if (bytes.length > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES) {
      degraded.push(`not scanned (size limit): ${f.path}`);
      continue;
    }
    if (f.content.includes("\u0000")) {
      degraded.push(`not scanned (binary): ${f.path}`);
      continue;
    }

    const lines = f.content.split(/\r?\n/);
    lines.forEach((text, i) => {
      for (const rule of RULES) {
        if (rule.re.test(text)) {
          findings.push({
            rule: rule.id,
            severity: rule.severity,
            why: rule.why,
            file: f.path,
            line: i + 1,
            excerpt: visible(text.trim()).slice(0, 160),
          });
        }
      }
      for (const u of text.match(URL_RE) ?? []) urls.add(u.replace(/[.,;:]+$/, ""));
    });
  }

  const skillMd = files.find((f) => /(^|\/)SKILL\.md$/.test(f.path));
  if (!skillMd) degraded.push("no SKILL.md found");
  const fm = skillMd ? readFrontmatter(skillMd.content) : {};

  const high = findings.filter((f) => f.severity === "high");
  const medium = findings.filter((f) => f.severity === "medium");
  let verdict: SkillVerdict;
  let verdictReason: string;
  if (high.length) {
    verdict = "DANGEROUS";
    verdictReason = `${high.length} high-severity finding(s): ${[...new Set(high.map((f) => f.rule))].join(", ")}`;
  } else if (medium.length || degraded.length) {
    verdict = "SUSPICIOUS";
    verdictReason = medium.length
      ? `${medium.length} finding(s) needing review: ${[...new Set(medium.map((f) => f.rule))].join(", ")}`
      : `scan incomplete: ${degraded.join("; ")}`;
  } else {
    verdict = "NO_FLAGS";
    verdictReason = "no known-bad pattern matched (not a safety guarantee — see limits)";
  }

  return {
    scanner: { name: SCANNER_NAME, version: SCANNER_VERSION, rulesHash: await rulesHash() },
    skillName: fm.name ?? null,
    description: fm.description ?? null,
    resources,
    digestSetHash: await digestSetHash(resources),
    verdict,
    verdictReason,
    findings,
    urls: [...urls].sort(),
    degraded,
    limits: LIMITS,
  };
}

// Render invisible characters as <U+XXXX> so the excerpt shows the reviewer
// what's actually there instead of hiding it again.
function visible(s: string): string {
  return s.replace(/[​-‏‪-‮⁠-⁤⁦-⁩﻿]|\uDB40[\uDC00-\uDC7F]/g, (c) =>
    `<U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`,
  );
}
