import { describe, expect, it } from "vitest";
import { analyze } from "../src/analyze";
import type { AnalyzeOptions } from "../src/analyze";

const lint = (sql: string | string[], opts: AnalyzeOptions = {}) => {
  const list = Array.isArray(sql) ? sql : [sql];
  return analyze(
    list.map((s, i) => ({ name: `${String(i + 1).padStart(3, "0")}.sql`, sql: s })),
    opts
  ).violations;
};
/** `rule:object` for every finding. service_role is muted unless a test is about it. */
const rules = (sql: string | string[], opts: AnalyzeOptions = {}) =>
  lint(sql, { ...opts, rules: { "missing-service-role-grant": "off", ...opts.rules } }).map((v) => `${v.rule}:${v.object}`);
const all = (sql: string | string[], opts: AnalyzeOptions = {}) => lint(sql, opts).map((v) => `${v.rule}:${v.object}`).sort();

/** The shape every table should end up with. */
const GOOD_TABLE = `
  CREATE TABLE posts (id uuid PRIMARY KEY, body text);
  ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
  REVOKE ALL ON posts FROM anon, authenticated;
  GRANT SELECT, INSERT, UPDATE, DELETE ON posts TO service_role;
  GRANT SELECT ON posts TO authenticated;
`;

describe("tables", () => {
  it("accepts the correct shape under the strict preset, in every defaults mode", () => {
    for (const defaults of ["both", "auto-expose", "no-auto-expose"] as const) {
      expect(all(GOOD_TABLE, { preset: "strict", clientTables: ["posts"], defaults })).toEqual([]);
    }
  });

  it("rls-disabled", () => {
    expect(rules("CREATE TABLE posts (id int);")).toEqual(["rls-disabled:posts"]);
    expect(rules("CREATE TABLE posts (id int); ALTER TABLE posts ENABLE ROW LEVEL SECURITY;")).toEqual([]);
    expect(rules("CREATE TABLE IF NOT EXISTS public.posts (id int); ALTER TABLE ONLY public.posts ENABLE ROW LEVEL SECURITY;")).toEqual([]);
    expect(
      rules("CREATE TABLE posts (id int); ALTER TABLE posts ENABLE ROW LEVEL SECURITY; ALTER TABLE posts DISABLE ROW LEVEL SECURITY;")
    ).toEqual(["rls-disabled:posts"]);
    // FORCE only makes RLS apply to the owner as well — it does not turn RLS on
    expect(rules("CREATE TABLE posts (id int); ALTER TABLE posts FORCE ROW LEVEL SECURITY;")).toEqual(["rls-disabled:posts"]);
    // a quoted column name is not a keyword
    expect(rules(`CREATE TABLE posts (id int); ALTER TABLE posts ADD COLUMN "enable row level security" int;`)).toEqual(["rls-disabled:posts"]);
  });

  it("checks UNLOGGED tables, skips TEMP tables and schemas that are not exposed", () => {
    expect(rules("CREATE UNLOGGED TABLE cache (id int);")).toEqual(["rls-disabled:cache"]);
    expect(rules("CREATE TABLE private.secrets (id int); CREATE TEMP TABLE scratch (id int);")).toEqual([]);
    expect(rules("CREATE TABLE api.items (id int);", { schemas: ["api"] })).toEqual(["rls-disabled:api.items"]);
  });

  it("follows ALTER TABLE ... SET SCHEMA", () => {
    expect(rules("CREATE TABLE posts (id int); ALTER TABLE posts SET SCHEMA private;")).toEqual([]);
    // and into an exposed schema: the table was tracked all along
    expect(rules("CREATE TABLE private.t (id int); ALTER TABLE private.t SET SCHEMA public;")).toEqual(["rls-disabled:t"]);
  });

  it("grant-order: REVOKE ALL after a GRANT to the same role wipes it", () => {
    const sql = `
      CREATE TABLE posts (id int);
      ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
      GRANT SELECT ON posts TO authenticated;
      REVOKE ALL ON posts FROM anon, authenticated;
    `;
    const found = lint(sql).filter((v) => v.rule === "grant-order");
    expect(found).toHaveLength(1);
    expect(found[0].line).toBe(5); // points at the REVOKE
  });

  it("grant-order: fine when the role is different or the privilege is granted again", () => {
    const base = "CREATE TABLE posts (id int); ALTER TABLE posts ENABLE ROW LEVEL SECURITY;";
    expect(rules(base + "GRANT ALL ON posts TO service_role; REVOKE ALL ON posts FROM anon, authenticated;")).toEqual([]);
    expect(
      rules(base + "GRANT SELECT ON posts TO authenticated; REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated; GRANT SELECT ON posts TO authenticated;")
    ).toEqual([]);
    expect(rules([GOOD_TABLE, "REVOKE ALL ON posts FROM authenticated;"])).toEqual([]); // a later migration may revoke on purpose
  });

  it("grant-order can be ignored above the REVOKE it points at", () => {
    const sql = `
      CREATE TABLE posts (id int); ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
      GRANT SELECT ON posts TO authenticated;
      -- grant-lint-ignore grant-order
      REVOKE ALL ON posts FROM authenticated;
    `;
    expect(rules(sql)).toEqual([]);
  });

  it("client-table-no-grant: only with clientTables, and only when no client role can touch it", () => {
    const sql = `
      CREATE TABLE posts (id int);
      ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
      REVOKE ALL ON posts FROM anon, authenticated;
    `;
    expect(rules(sql)).toEqual([]);
    expect(rules(sql, { clientTables: ["posts"] })).toEqual(["client-table-no-grant:posts"]);
    expect(rules(sql + "GRANT SELECT ON posts TO authenticated;", { clientTables: ["posts"] })).toEqual([]);
  });

  it("client-table-no-grant: a table that only works because of auto-expose is reported by default", () => {
    const table = "CREATE TABLE todos (id int); ALTER TABLE todos ENABLE ROW LEVEL SECURITY;";
    expect(rules(table, { clientTables: ["todos"] })).toEqual(["client-table-no-grant:todos"]);
    expect(rules(table, { clientTables: ["todos"], defaults: "no-auto-expose" })).toEqual(["client-table-no-grant:todos"]);
    expect(rules(table, { clientTables: ["todos"], defaults: "auto-expose" })).toEqual([]);
  });

  it("missing-service-role-grant: warns where tables are not auto-exposed", () => {
    const table = "CREATE TABLE posts (id int); ALTER TABLE posts ENABLE ROW LEVEL SECURITY;";
    const [v] = lint(table);
    expect([v.rule, v.severity]).toEqual(["missing-service-role-grant", "warn"]);
    expect(lint(table, { defaults: "auto-expose" })).toEqual([]);
    expect(lint(table + "GRANT ALL ON posts TO service_role;")).toEqual([]);
    expect(lint(table + "GRANT SELECT ON ALL TABLES IN SCHEMA public TO service_role;")).toEqual([]);
  });

  it("tracks ALTER DEFAULT PRIVILEGES, honouring FOR ROLE", () => {
    const table = "CREATE TABLE posts (id int); ALTER TABLE posts ENABLE ROW LEVEL SECURITY;";
    const revoke = "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;";
    expect(rules([revoke, table], { clientTables: ["posts"], defaults: "auto-expose" })).toEqual(["client-table-no-grant:posts"]);
    const other = "ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;";
    expect(rules([other, table], { clientTables: ["posts"], defaults: "auto-expose" })).toEqual([]);
    const mine = other.replace("supabase_admin", "postgres");
    expect(rules([mine, table], { clientTables: ["posts"], defaults: "auto-expose" })).toEqual(["client-table-no-grant:posts"]);
    expect(rules([other, table], { clientTables: ["posts"], defaults: "auto-expose", migrationRole: "supabase_admin" })).toEqual([
      "client-table-no-grant:posts",
    ]);
  });

  it("follows DROP / re-CREATE in the same file, and DROP of several tables", () => {
    expect(rules("DROP TABLE IF EXISTS posts; CREATE TABLE posts (id int);")).toEqual(["rls-disabled:posts"]);
    expect(rules(["CREATE TABLE posts (id int);", "DROP TABLE IF EXISTS public.posts, other CASCADE;"])).toEqual([]);
  });

  it("follows ALTER TABLE ... RENAME TO", () => {
    expect(all([GOOD_TABLE, "ALTER TABLE posts RENAME TO articles;"], { preset: "strict", clientTables: ["articles"] })).toEqual([]);
  });

  it("handles multi-table GRANTs, quoted names and ALL TABLES IN SCHEMA", () => {
    const sql = `
      CREATE TABLE a (id int); CREATE TABLE "B" (id int);
      ALTER TABLE a ENABLE ROW LEVEL SECURITY; ALTER TABLE "B" ENABLE ROW LEVEL SECURITY;
      REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;
      GRANT SELECT ON TABLE a, public."B" TO authenticated;
      GRANT ALL ON a, "B" TO "service_role";
    `;
    expect(all(sql, { preset: "strict", clientTables: ["a", "B"] })).toEqual([]);
  });

  it("serial-sequence-grant: authenticated can insert but not use the sequence", () => {
    const sql = `
      CREATE TABLE notes (id bigserial PRIMARY KEY, body text);
      ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
      REVOKE ALL ON notes FROM anon, authenticated;
      GRANT SELECT, INSERT ON notes TO authenticated;
      REVOKE ALL ON SEQUENCE notes_id_seq FROM authenticated;
    `;
    const found = lint(sql).filter((v) => v.rule === "serial-sequence-grant");
    expect(found.map((v) => `${v.object}:${v.severity}`)).toEqual(["notes_id_seq:warn"]);
    expect(rules(sql + "GRANT USAGE, SELECT ON SEQUENCE notes_id_seq TO authenticated;")).toEqual([]);
    expect(rules(sql.replace("bigserial", "bigint GENERATED ALWAYS AS IDENTITY").replace(/REVOKE ALL ON SEQUENCE.*;/, ""))).toEqual([]);
  });

  it("strict rules: explicit revoke, explicit service_role grant, anon access", () => {
    const sql = "CREATE TABLE posts (id int); ALTER TABLE posts ENABLE ROW LEVEL SECURITY;";
    expect(all(sql, { preset: "strict" })).toEqual([
      "anon-table-access:posts",
      "missing-explicit-revoke:posts",
      "missing-service-role-grant:posts",
    ]);
  });

  it("anon-table-access counts privileges granted to PUBLIC", () => {
    expect(all(GOOD_TABLE + "GRANT SELECT ON posts TO PUBLIC;", { preset: "strict" })).toEqual(["anon-table-access:posts"]);
  });

  it("rule overrides, ignore comments and bad options", () => {
    expect(rules("CREATE TABLE posts (id int);", { rules: { "rls-disabled": "off" } })).toEqual([]);
    expect(rules("-- grant-lint-ignore rls-disabled\nCREATE TABLE posts (id int);")).toEqual([]);
    expect(rules("-- grant-lint-ignore grant-order\nCREATE TABLE posts (id int);")).toEqual(["rls-disabled:posts"]);
    expect(() => rules("SELECT 1;", { rules: { "no-such-rule": "error" } })).toThrow(/Unknown rule/);
    expect(() => rules("SELECT 1;", { rules: { "rls-disabled": "fatal" as never } })).toThrow(/severity/);
    expect(() => rules("SELECT 1;", { preset: "strickt" as never })).toThrow(/Unknown preset/);
    expect(() => rules("SELECT 1;", { defaults: "supabase" as never })).toThrow(/defaults/);
  });

  it("baseline keys are schema-qualified and do not depend on the file", () => {
    const v = lint(["SELECT 1;", "CREATE TABLE posts (id int);"]).find((x) => x.rule === "rls-disabled")!;
    expect(v.key).toBe("public.posts::rls-disabled");
    expect(v.file).toBe("002.sql");
    expect(lint("CREATE TABLE api.items (id int);", { schemas: ["api"] }).find((x) => x.rule === "rls-disabled")!.key).toBe("api.items::rls-disabled");
  });
});

describe("views", () => {
  const base = "CREATE TABLE posts (id int, draft boolean); ALTER TABLE posts ENABLE ROW LEVEL SECURITY;";

  it("view-bypasses-rls: a default (security definer) view readable by client roles", () => {
    expect(rules(base + "CREATE VIEW published AS SELECT * FROM posts WHERE NOT draft;")).toEqual(["view-bypasses-rls:published"]);
    expect(rules(base + "CREATE VIEW published WITH (security_invoker = on) AS SELECT * FROM posts;")).toEqual([]);
    expect(rules(base + "CREATE VIEW published WITH (security_invoker) AS SELECT * FROM posts;")).toEqual([]);
    expect(rules(base + "CREATE VIEW published AS SELECT * FROM posts; ALTER VIEW published SET (security_invoker = true);")).toEqual([]);
    expect(rules(base + "CREATE VIEW published AS SELECT * FROM posts; REVOKE ALL ON published FROM anon, authenticated;")).toEqual([]);
  });

  it("only flags views client roles can read", () => {
    expect(rules(base + "CREATE VIEW published AS SELECT * FROM posts;", { defaults: "no-auto-expose" })).toEqual([]);
    expect(
      rules(base + "CREATE VIEW published AS SELECT * FROM posts; GRANT SELECT ON published TO authenticated;", { defaults: "no-auto-expose" })
    ).toEqual(["view-bypasses-rls:published"]);
  });

  it("CREATE OR REPLACE VIEW takes the options of the new statement", () => {
    const v1 = "CREATE VIEW v WITH (security_invoker = on) AS SELECT 1 AS x;";
    expect(rules([v1, "CREATE OR REPLACE VIEW v AS SELECT 1 AS x;"])).toEqual(["view-bypasses-rls:v"]);
  });

  it("materialized views cannot be security invoker", () => {
    const found = lint(base + "CREATE MATERIALIZED VIEW stats AS SELECT count(*) FROM posts;").filter((v) => v.rule !== "missing-service-role-grant");
    expect(found.map((v) => v.rule)).toEqual(["view-bypasses-rls"]);
    expect(found[0].note).toMatch(/Materialized views cannot use security_invoker/);
  });

  it("views in unexposed schemas, temp views and dropped views are ignored", () => {
    expect(rules("CREATE VIEW private.v AS SELECT 1; CREATE TEMP VIEW t AS SELECT 1; CREATE VIEW d AS SELECT 1; DROP VIEW d;")).toEqual([]);
  });
});

describe("SECURITY DEFINER functions", () => {
  const fn = (args = "p_id uuid", extra = "") => `
    CREATE OR REPLACE FUNCTION public.is_owner(${args}) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
    AS $$ SELECT true $$;
    ${extra}
  `;

  it("is flagged until EXECUTE is revoked from PUBLIC and anon", () => {
    expect(rules(fn())).toEqual(["definer-public-execute:is_owner(uuid)"]);
    expect(rules(fn("p_id uuid", "REVOKE ALL ON FUNCTION is_owner(uuid) FROM PUBLIC;"))).toEqual(["definer-public-execute:is_owner(uuid)"]);
    expect(rules(fn("p_id uuid", "REVOKE ALL ON FUNCTION public.is_owner(p_id uuid) FROM PUBLIC, anon;"))).toEqual([]);
  });

  it("with function defaults revoked from anon, REVOKE FROM PUBLIC is enough", () => {
    const sweep = "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM anon;";
    expect(rules([sweep, fn("p_id uuid", "REVOKE EXECUTE ON FUNCTION is_owner(uuid) FROM PUBLIC;")])).toEqual([]);
  });

  it("a global ALTER DEFAULT PRIVILEGES removes PUBLIC's EXECUTE; one IN SCHEMA does not", () => {
    // the basejump pattern
    const global = `
      ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
      ALTER DEFAULT PRIVILEGES IN SCHEMA PUBLIC REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;
    `;
    expect(rules([global, fn()])).toEqual([]);
    const perSchema = "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, anon;";
    expect(rules([perSchema, fn()])).toEqual(["definer-public-execute:is_owner(uuid)"]);
  });

  it("an explicit GRANT EXECUTE to anon is respected as intent", () => {
    const open = fn("p_id uuid", "REVOKE ALL ON FUNCTION is_owner(uuid) FROM PUBLIC; GRANT EXECUTE ON FUNCTION is_owner(uuid) TO anon;");
    expect(rules(open)).toEqual([]);
    // a blanket grant is not intent for this function
    const blanket = ["REVOKE EXECUTE ON FUNCTION is_owner(uuid) FROM anon;", "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO anon;"];
    expect(rules([open, ...blanket])).toEqual(["definer-public-execute:is_owner(uuid)"]);
  });

  it("ignores SECURITY INVOKER functions, trigger functions (quoted too) and other schemas", () => {
    expect(rules(fn().replace("SECURITY DEFINER", ""))).toEqual([]);
    expect(rules(fn("").replace("RETURNS boolean", "RETURNS trigger"))).toEqual([]);
    expect(rules(fn("").replace("RETURNS boolean", 'RETURNS "trigger"'))).toEqual([]);
    expect(rules(fn("").replace("RETURNS boolean", "RETURNS pg_catalog.event_trigger"))).toEqual([]);
    expect(rules(fn().replace("public.is_owner", "private.is_owner"))).toEqual([]);
    expect(rules("CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$; COMMENT ON FUNCTION f() IS 'SECURITY DEFINER';")).toEqual([]);
  });

  it("catches a REVOKE that targets a different overload", () => {
    const v1 = fn("p_id uuid", "REVOKE ALL ON FUNCTION is_owner(uuid) FROM PUBLIC, anon;");
    const v2 = fn("p_id uuid, p_team uuid");
    const found = lint([v1, v2]).filter((v) => v.rule === "definer-public-execute");
    expect(found.map((v) => v.object)).toEqual(["is_owner(uuid, uuid)"]);
    expect(found[0].note).toMatch(/is_owner\(uuid\) \(001\.sql:5\), a different overload/);
    expect(found[0].fix).toContain("is_owner(uuid, uuid)");
  });

  it("matches signatures written differently", () => {
    const ok = (args: string, revoke: string) =>
      rules(fn(args, `REVOKE ALL ON FUNCTION ${revoke} FROM PUBLIC, anon;`)).length === 0;
    expect(ok("a int=1", "is_owner(integer)")).toBe(true);
    expect(ok("a public.my_type", '"public"."is_owner"("public"."my_type")')).toBe(true);
    expect(ok("a posts.id%TYPE", "is_owner(uuid)")).toBe(true);
    expect(ok("a varchar(20), b timestamptz", "is_owner(character varying, timestamp with time zone)")).toBe(true);
  });

  it("CREATE OR REPLACE keeps the ACL; DROP + CREATE resets it", () => {
    const first = fn("p_id uuid", "REVOKE ALL ON FUNCTION is_owner(uuid) FROM PUBLIC, anon;");
    expect(rules([first, fn()])).toEqual([]);
    expect(rules([first, "DROP FUNCTION is_owner(uuid);", fn()])).toEqual(["definer-public-execute:is_owner(uuid)"]);
  });

  it("follows ALTER FUNCTION ... SECURITY DEFINER / SET SCHEMA, and ALL FUNCTIONS vs ALL PROCEDURES", () => {
    const invoker = "CREATE FUNCTION g(int) RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;";
    const definer = "ALTER FUNCTION g(integer) SECURITY DEFINER;";
    expect(rules([invoker, definer])).toEqual(["definer-public-execute:g(integer)"]);
    expect(rules([invoker, definer, "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon;"])).toEqual([]);
    expect(rules([invoker, definer, "REVOKE ALL ON ALL ROUTINES IN SCHEMA public FROM PUBLIC, anon;"])).toEqual([]);
    expect(rules([invoker, definer, "REVOKE ALL ON ALL PROCEDURES IN SCHEMA public FROM PUBLIC, anon;"])).toEqual([
      "definer-public-execute:g(integer)",
    ]);
    expect(rules([invoker, definer, "ALTER FUNCTION g(int) SET SCHEMA private;"])).toEqual([]);
  });

  it("an ignore on an earlier CREATE survives CREATE OR REPLACE", () => {
    expect(rules(["-- grant-lint-ignore definer-public-execute\n" + fn(), fn()])).toEqual([]);
  });

  it("a sweep done in a DO block is visible through grant-lint-as", () => {
    const sweep = `
      -- grant-lint-as: REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon;
      DO $$ DECLARE r record; BEGIN
        FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p LOOP
          EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon', r.sig);
        END LOOP;
      END $$;
    `;
    expect(rules([fn(), sweep])).toEqual([]);
  });
});

describe("robustness", () => {
  it("parses GRANT in linear time", () => {
    const huge = "GRANT SELECT ON " + "x ".repeat(100_000);
    const t0 = Date.now();
    lint(huge);
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it("ignores role membership grants", () => {
    expect(rules("GRANT anon TO authenticator;")).toEqual([]);
  });
});

describe("policies", () => {
  const T = `CREATE TABLE notes (id int, owner uuid); ALTER TABLE notes ENABLE ROW LEVEL SECURITY;`;
  const only = (sql: string, opts: AnalyzeOptions = {}) =>
    lint(T + sql, { ...opts, rules: { "missing-service-role-grant": "off", ...opts.rules } })
      .filter((v) => v.rule === "rls-per-row-call")
      .map((v) => `${v.object} | ${v.note}`);

  it("rls-per-row-call: bare auth.uid() / auth.jwt() in USING and WITH CHECK", () => {
    expect(only(`CREATE POLICY "own" ON notes FOR ALL TO authenticated USING (owner = auth.uid());`)).toEqual([
      "notes.own | Bare: auth.uid(). Wrap each as (select ...).",
    ]);
    expect(
      only(`CREATE POLICY p ON public.notes FOR INSERT WITH CHECK (owner = auth.uid() AND auth.jwt() ->> 'role' = 'x');`)
    ).toEqual(["notes.p | Bare: auth.uid(), auth.jwt(). Wrap each as (select ...)."]);
  });

  it("accepts (select ...) in any spelling", () => {
    expect(only(`CREATE POLICY p ON notes USING ((select auth.uid()) = owner);`)).toEqual([]);
    expect(only(`CREATE POLICY p ON notes USING (owner = ( SELECT auth.uid() AS uid));`)).toEqual([]);
  });

  it("zero-argument helpers defined in the migrations count; helpers with arguments do not", () => {
    const fns = `
      CREATE FUNCTION public.current_profile_role() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT 'x' $$;
      CREATE FUNCTION can_write(uuid) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT true $$;`;
    expect(only(fns + `CREATE POLICY p ON notes USING (current_profile_role() = 'admin' OR can_write(owner));`)).toEqual([
      "notes.p | Bare: current_profile_role(). Wrap each as (select ...).",
    ]);
    expect(only(fns + `CREATE POLICY p ON notes USING ((select public.current_profile_role()) = 'admin');`)).toEqual([]);
    // an unknown zero-arg call (now(), a builtin) is left alone
    expect(only(`CREATE POLICY p ON notes USING (now() > '2020-01-01');`)).toEqual([]);
  });

  it("follows ALTER POLICY, RENAME and DROP to the final state", () => {
    const bare = `CREATE POLICY p ON notes USING (owner = auth.uid());`;
    expect(only(bare + `ALTER POLICY p ON notes USING ((select auth.uid()) = owner);`)).toEqual([]);
    expect(only(bare + `ALTER POLICY p ON notes TO authenticated;`)).toHaveLength(1);
    expect(only(bare + `ALTER POLICY p ON notes RENAME TO q;`)).toEqual(["notes.q | Bare: auth.uid(). Wrap each as (select ...)."]);
    expect(only(bare + `DROP POLICY IF EXISTS p ON notes;`)).toEqual([]);
    expect(only(bare + `DROP TABLE notes;`)).toEqual([]);
  });

  it("ALTER POLICY replaces only the clause it names", () => {
    const sql = `CREATE POLICY p ON notes FOR UPDATE USING (owner = auth.uid()) WITH CHECK (owner = auth.uid());
                 ALTER POLICY p ON notes USING ((select auth.uid()) = owner);`;
    expect(only(sql)).toHaveLength(1); // WITH CHECK is still bare
  });

  it("is a warning in recommended, an error in strict, and can be ignored", () => {
    const sql = T + `CREATE POLICY p ON notes USING (owner = auth.uid());`;
    const sev = (preset: "recommended" | "strict") =>
      lint(sql, { preset }).find((v) => v.rule === "rls-per-row-call")?.severity;
    expect(sev("recommended")).toBe("warn");
    expect(sev("strict")).toBe("error");
    expect(only(`-- grant-lint-ignore rls-per-row-call\nCREATE POLICY p ON notes USING (owner = auth.uid());`)).toEqual([]);
  });

  it("only checks exposed schemas, keyed by table and policy", () => {
    expect(only(`CREATE POLICY p ON storage.objects USING (owner = auth.uid());`)).toEqual([]);
    const v = lint(T + `CREATE POLICY "own rows" ON notes USING (owner = auth.uid());`).find((x) => x.rule === "rls-per-row-call")!;
    expect(v.key).toBe("public.notes.own rows::rls-per-row-call");
  });
});
