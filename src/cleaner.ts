// Tracker/param stripping via the ClearURLs ruleset (SPEC §4, §6). Bundled snapshot
// at build time; cron-refreshed into D1 in production (see SPEC §6, §15).
//
// Scope (v1): applies `rules` + `referralMarketing` (param-name regexes) and
// `exceptions` (skip a provider's rules if the URL matches). Deliberately NOT
// implemented in v1 — documented, not silently dropped: `redirections` (unwrap an
// embedded target URL, e.g. Google's /url?q=...), `rawRules` (whole-URL regex
// replace, only 4 providers use it), `completeProvider` (strip entire URL, only
// 10 providers). Candidates for v1.1 if evidence shows they're worth it.
import rulesData from "./data/clearurls-rules.json" with { type: "json" };

interface Provider {
  urlPattern: string;
  rules: string[];
  referralMarketing: string[];
  exceptions: string[];
}

interface CompiledProvider {
  urlRe: RegExp;
  paramRes: RegExp[];
  exceptionRes: RegExp[];
}

// Compiled once at module load — not per-call (this module is loaded once per
// request under createMcpHandler's per-request factory, and reused across warm
// invocations of the same isolate; see SPEC §5).
const PROVIDERS: CompiledProvider[] = Object.values(
  rulesData.providers as Record<string, Provider>,
).map((p) => ({
  urlRe: new RegExp(p.urlPattern, "i"),
  paramRes: [...p.rules, ...p.referralMarketing].map((r) => new RegExp(`^${r}$`, "i")),
  exceptionRes: p.exceptions.map((r) => new RegExp(r, "i")),
}));

export interface QueryParam {
  key: string;
  value: string;
  tracker: boolean;
}

export interface CleanResult {
  cleanedUrl: string;
  removedParams: string[];
  queryParams: QueryParam[];
}

/** Strip known tracking/affiliate params from a URL and enumerate every param seen. */
export function cleanUrl(inputUrl: string): CleanResult {
  const u = new URL(inputUrl);
  const applicable = PROVIDERS.filter(
    (p) => p.urlRe.test(inputUrl) && !p.exceptionRes.some((ex) => ex.test(inputUrl)),
  );

  const queryParams: QueryParam[] = [];
  const removedParams: string[] = [];
  const kept = new URLSearchParams();

  for (const [key, value] of u.searchParams) {
    const isTracker = applicable.some((p) => p.paramRes.some((re) => re.test(key)));
    queryParams.push({ key, value, tracker: isTracker });
    if (isTracker) {
      removedParams.push(key);
    } else {
      kept.append(key, value);
    }
  }

  const cleaned = new URL(u.toString());
  cleaned.search = kept.toString();

  return { cleanedUrl: cleaned.toString(), removedParams, queryParams };
}
