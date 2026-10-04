// The README's examples are part of the contract: if the linter's behaviour drifts, these fail.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { analyze } from "../src/analyze";
import { EXAMPLES } from "../playground/examples";

const readme = (name: string) => readFileSync(join(__dirname, "..", name), "utf8");
const sqlBlocks = (md: string) => [...md.matchAll(/```sql\n([\s\S]*?)```/g)].map((m) => m[1]);

describe.each(["README.md", "README.ja.md"])("%s", (file) => {
  const blocks = sqlBlocks(readme(file));

  it("the shape that passes strict really passes, in every defaults mode", () => {
    const shape = blocks.find((b) => b.includes("CREATE TABLE notes"))!.replace("$$ ... $$", "$$ SELECT true $$");
    for (const defaults of ["both", "auto-expose", "no-auto-expose"] as const) {
      const res = analyze([{ name: "001.sql", sql: shape }], { preset: "strict", defaults, clientTables: ["notes", "my_notes"] });
      expect(res.violations, defaults).toEqual([]);
    }
  });

  it("the grant-lint-as example covers the function it sweeps", () => {
    const sweep = blocks.find((b) => b.includes("grant-lint-as"))!;
    const fn = "CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;";
    expect(analyze([{ name: "1.sql", sql: fn }, { name: "2.sql", sql: sweep }]).violations).toEqual([]);
  });

  it("the grant-lint-ignore example suppresses anon-table-access", () => {
    const ignore = blocks.find((b) => b.includes("grant-lint-ignore"))!.replace("(...)", "(id int)");
    const res = analyze([{ name: "1.sql", sql: ignore + "ALTER TABLE public_announcements ENABLE ROW LEVEL SECURITY;" }], {
      preset: "strict",
      rules: { "missing-explicit-revoke": "off", "missing-service-role-grant": "off" },
    });
    expect(res.violations).toEqual([]);
  });
});

it("the README's sample output is what the linter prints for that situation", () => {
  const md = readme("README.md");
  const res = analyze(
    [
      { name: "20261101000000_apply.sql", sql: "CREATE FUNCTION term_apply(p_term uuid) RETURNS void\nLANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN END $$;\nREVOKE ALL ON FUNCTION term_apply(uuid) FROM PUBLIC, anon;" },
      {
        name: "20261102000000_todos.sql",
        sql: "CREATE TABLE todos (id uuid PRIMARY KEY, user_id uuid, title text);\nALTER TABLE todos ENABLE ROW LEVEL SECURITY;\nGRANT ALL ON todos TO service_role;",
      },
      { name: "20261103000000_apply_dry_run.sql", sql: "CREATE OR REPLACE FUNCTION term_apply(p_term uuid, p_dry_run boolean DEFAULT false)\nRETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN END $$;" },
    ],
    { clientTables: ["todos"] }
  );
  expect(res.violations.map((v) => v.rule)).toEqual(["client-table-no-grant", "definer-public-execute"]);
  for (const v of res.violations) {
    expect(md).toContain(`error  ${v.object}  ${v.rule}`);
    expect(md).toContain(`supabase/migrations/${v.file}:${v.line}`);
    expect(md).toContain(v.message);
    expect(md).toContain(`fix: ${v.fix}`);
    if (v.note && v.rule === "definer-public-execute") expect(md).toContain(v.note);
  }
});

describe("playground examples", () => {
  const expectations: Record<string, string[]> = {
    "forgot-grant": ["client-table-no-grant:todos", "missing-service-role-grant:todos"],
    "grant-order": ["grant-order:profiles", "missing-service-role-grant:profiles"],
    definer: ["definer-public-execute:book_slot(uuid, uuid)"],
    overload: ["definer-public-execute:term_apply(uuid, boolean)"],
    view: ["view-bypasses-rls:post_feed"],
    sweep: [],
    good: [],
  };
  it.each(EXAMPLES.map((e) => [e.id, e] as const))("%s", (id, ex) => {
    const files = ex.sql.split(/^-- file: (\S+)\n/m);
    const list = files.length > 1 ? files.slice(1).reduce<{ name: string; sql: string }[]>((acc, x, i) => (i % 2 === 0 ? [...acc, { name: x, sql: "" }] : (acc[acc.length - 1].sql = x, acc)), []) : [{ name: "migration.sql", sql: ex.sql }];
    const res = analyze(list, { preset: ex.preset, clientTables: (ex.clientTables || "").split(/[\s,]+/).filter(Boolean) });
    expect(res.violations.map((v) => `${v.rule}:${v.object}`).sort()).toEqual([...expectations[id]].sort());
  });
});
