import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(__dirname, "..");
const CLI = join(ROOT, "dist", "cli.js");

beforeAll(() => {
  execFileSync("npx", ["tsup"], { cwd: ROOT, stdio: "ignore" });
}, 60_000);

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function project(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "sgl-"));
  dirs.push(dir);
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(join(dir, path), body);
  }
  return dir;
}

const run = (cwd: string, ...args: string[]) => {
  const r = spawnSync("node", [CLI, ...args], { cwd, encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  return { code: r.status, out: r.stdout + r.stderr };
};

const OK = `
CREATE TABLE posts (id uuid PRIMARY KEY);
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON posts FROM anon, authenticated;
GRANT SELECT ON posts TO authenticated;
GRANT ALL ON posts TO service_role;
`;

describe("cli", () => {
  it("passes a clean project", () => {
    const dir = project({ "supabase/migrations/001_posts.sql": OK });
    const r = run(dir);
    expect(r.code).toBe(0);
    expect(r.out).toContain("✔ No new problems in 1 migration, 1 table, 0 views, 0 functions");
  });

  it("fails with file:line and a fix", () => {
    const dir = project({ "supabase/migrations/001_posts.sql": "\nCREATE TABLE posts (id int);" });
    const r = run(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("supabase/migrations/001_posts.sql:2");
    expect(r.out).toContain("fix: ALTER TABLE posts ENABLE ROW LEVEL SECURITY;");
  });

  it("finds tables the browser client reads", () => {
    const dir = project({
      "supabase/migrations/001_posts.sql": OK.replace("GRANT SELECT ON posts TO authenticated;", ""),
      "supabase-grant-lint.config.json": JSON.stringify({ client: { marker: "lib/supabaseClient" } }),
      "components/Feed.tsx": `import { supabase } from "../lib/supabaseClient";\nsupabase.from("posts").select("*");\nsupabase.storage.from("avatars");`,
      "pages/api/admin.ts": `import { supabase } from "../../lib/supabaseClient";\nsupabase.from("secrets");`,
    });
    const r = run(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("client-table-no-grant");
    expect(r.out).not.toContain("avatars");
  });

  it("baseline: write, tolerate, report fixed entries, prune", () => {
    const dir = project({ "supabase/migrations/001_old.sql": "CREATE TABLE legacy (id int);" });
    expect(run(dir).code).toBe(1);

    expect(run(dir, "--write-baseline").out).toContain("Wrote 2 entries");
    const baseline = JSON.parse(readFileSync(join(dir, "supabase-grant-lint.baseline.json"), "utf8"));
    expect(baseline).toEqual({ version: 1, entries: ["public.legacy::missing-service-role-grant", "public.legacy::rls-disabled"] });

    const known = run(dir);
    expect(known.code).toBe(0);
    expect(known.out).toContain("2 known in baseline");

    // a new violation still fails
    writeFileSync(join(dir, "supabase/migrations/002_new.sql"), "CREATE TABLE fresh (id int);");
    const fresh = run(dir);
    expect(fresh.code).toBe(1);
    expect(fresh.out).toContain("fresh");
    expect(fresh.out).not.toMatch(/error {2}legacy/);

    // fixing the old one makes the entry stale
    writeFileSync(join(dir, "supabase/migrations/002_new.sql"), "ALTER TABLE legacy ENABLE ROW LEVEL SECURITY;");
    // the baseline does not grow by accident
    writeFileSync(join(dir, "supabase/migrations/003_more.sql"), "CREATE TABLE more (id int);");
    expect(run(dir, "--write-baseline").code).toBe(1);
    writeFileSync(join(dir, "supabase/migrations/003_more.sql"), "SELECT 1;");

    const stale = run(dir);
    expect(stale.code).toBe(0);
    expect(stale.out).toContain("--prune-baseline");
    expect(run(dir, "--fail-on-stale").code).toBe(1);
    expect(run(dir, "--prune-baseline").out).toMatch(/Removed 1 fixed entry from .* \(1 left\)/);
    expect(run(dir, "--fail-on-stale").code).toBe(0);
  });

  it("github format emits annotations", () => {
    const dir = project({ "supabase/migrations/001.sql": "CREATE TABLE posts (id int);" });
    const out = run(dir, "--format", "github").out;
    expect(out).toMatch(/^::error file=supabase\/migrations\/001\.sql,line=1,title=rls-disabled: posts::/m);
    expect(out).toMatch(/^::warning file=.*title=missing-service-role-grant: posts::/m);
  });

  it("json format and presets", () => {
    const dir = project({ "supabase/migrations/001.sql": "CREATE TABLE posts (id int); ALTER TABLE posts ENABLE ROW LEVEL SECURITY;" });
    expect(JSON.parse(run(dir, "--format=json").out).violations.map((v: { rule: string }) => v.rule)).toEqual(["missing-service-role-grant"]);
    const strict = JSON.parse(run(dir, "--format=json", "--preset", "strict").out);
    expect(strict.violations.map((v: { rule: string }) => v.rule).sort()).toEqual([
      "anon-table-access",
      "missing-explicit-revoke",
      "missing-service-role-grant",
    ]);
  });

  it("reports usage errors with exit code 2", () => {
    const dir = project({});
    expect(run(dir).code).toBe(2);
    expect(run(dir, "--preset", "loose").code).toBe(2);
    expect(run(dir, "--bogus").code).toBe(2);
    const empty = project({ "supabase/migrations/README.md": "no sql here" });
    expect(run(empty).out).toContain("No .sql files");
    expect(run(empty).code).toBe(2);
  });

  it("rejects config mistakes instead of silently linting less", () => {
    const bad = (cfg: unknown) =>
      run(project({ "supabase/migrations/001.sql": "CREATE TABLE posts (id int);", "supabase-grant-lint.config.json": JSON.stringify(cfg) }));
    for (const cfg of [
      { preset: "strickt" },
      { rules: { "rls-disabled": "fatal" } },
      { rules: { "rls-disable": "error" } },
      { schemas: "public" },
      { client: {} },
      { client: { marker: "(" } },
      { defaults: "supabase" },
      { migration: "db" },
    ]) {
      const r = bad(cfg);
      expect(r.code, JSON.stringify(cfg)).toBe(2);
      expect(r.out).toMatch(/supabase-grant-lint\.config\.json: /);
    }
  });

  it("reads exposed schemas from supabase/config.toml", () => {
    const dir = project({
      "supabase/migrations/001.sql": "CREATE TABLE content.pages (id int);",
      "supabase/config.toml": '[api]\nenabled = true\n# schemas = ["nope"]\nschemas = [\n  "public",\n  "content",\n]\n\n[db]\nport = 54322\n',
    });
    const r = run(dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("content.pages");
    expect(r.out).toContain("schemas: public, content");
  });

  it("normalises client exclude paths", () => {
    const dir = project({
      "supabase/migrations/001.sql": OK,
      "supabase-grant-lint.config.json": JSON.stringify({ client: { marker: "supabaseClient", exclude: ["./pages/api/"] } }),
      "pages/api/admin.ts": `import { supabase } from "../../lib/supabaseClient";\nsupabase.from("secrets");`,
      "components/x.ts": `import { supabase } from "../lib/supabaseClient";\nArray.from("abc"); Buffer.from("xyz");`,
    });
    const r = run(dir, "--format=json");
    expect(JSON.parse(r.out).violations).toEqual([]);
  });
});
