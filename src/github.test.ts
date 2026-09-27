import { test } from "node:test";
import assert from "node:assert/strict";
import { parseGithubUrl, fetchSkillFromGithub } from "./github.ts";

test("parseGithubUrl shapes", () => {
  assert.deepEqual(parseGithubUrl("https://github.com/a/b"), { owner: "a", repo: "b", ref: null, path: "" });
  assert.deepEqual(parseGithubUrl("https://github.com/a/b.git"), { owner: "a", repo: "b", ref: null, path: "" });
  assert.deepEqual(parseGithubUrl("https://github.com/a/b/tree/main/skills/x"), {
    owner: "a", repo: "b", ref: "main", path: "skills/x",
  });
  assert.deepEqual(parseGithubUrl("https://github.com/a/b/blob/v1/skills/x/SKILL.md"), {
    owner: "a", repo: "b", ref: "v1", path: "skills/x",
  });
  assert.equal(parseGithubUrl("https://gitlab.com/a/b"), null);
  assert.equal(parseGithubUrl("https://github.com/a"), null);
  assert.equal(parseGithubUrl("https://github.com/a/b/issues/1"), null);
  assert.equal(parseGithubUrl("not a url"), null);
});

const SHA = "a".repeat(40);

function fakeFetch(routes: Record<string, () => Response>): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    const hit = routes[url];
    if (!hit) return new Response("nope", { status: 404 });
    return hit();
  }) as typeof fetch;
}

test("fetches only files under the skill path, pinned to the commit SHA", async () => {
  const f = fakeFetch({
    "https://api.github.com/repos/o/r": () => Response.json({ default_branch: "main" }),
    "https://api.github.com/repos/o/r/commits/main": () => new Response(SHA + "\n"),
    [`https://api.github.com/repos/o/r/git/trees/${SHA}?recursive=1`]: () =>
      Response.json({
        tree: [
          { path: "README.md", type: "blob", size: 5 },
          { path: "skills/x", type: "tree" },
          { path: "skills/x/SKILL.md", type: "blob", size: 10 },
          { path: "skills/x/ref/a.md", type: "blob", size: 3 },
          { path: "skills/xy/SKILL.md", type: "blob", size: 3 },
        ],
      }),
    [`https://raw.githubusercontent.com/o/r/${SHA}/skills/x/SKILL.md`]: () => new Response("---\nname: x\n---\n"),
    [`https://raw.githubusercontent.com/o/r/${SHA}/skills/x/ref/a.md`]: () => new Response("abc"),
  });
  const r = await fetchSkillFromGithub({ owner: "o", repo: "r", ref: null, path: "skills/x" }, f);
  assert.equal(r.source.commit, SHA);
  // "skills/xy" must NOT match the "skills/x" prefix
  assert.deepEqual(r.files.map((x) => x.path), ["SKILL.md", "ref/a.md"]);
  assert.deepEqual(r.degraded, []);
});

test("rate limit surfaces as a loud error, not an empty scan", async () => {
  const f = fakeFetch({ "https://api.github.com/repos/o/r/commits/main": () => new Response("", { status: 403 }) });
  await assert.rejects(
    fetchSkillFromGithub({ owner: "o", repo: "r", ref: "main", path: "" }, f),
    /rate limit/,
  );
});

test("a failed raw fetch is reported in degraded", async () => {
  const f = fakeFetch({
    "https://api.github.com/repos/o/r/commits/main": () => new Response(SHA),
    [`https://api.github.com/repos/o/r/git/trees/${SHA}?recursive=1`]: () =>
      Response.json({ tree: [{ path: "SKILL.md", type: "blob", size: 3 }] }),
  });
  const r = await fetchSkillFromGithub({ owner: "o", repo: "r", ref: "main", path: "" }, f);
  assert.deepEqual(r.files, []);
  assert.match(r.degraded[0], /fetch failed \(404\): SKILL\.md/);
});
