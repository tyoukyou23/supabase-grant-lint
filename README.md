# supabase-grant-lint

**Catch missing RLS, GRANT and REVOKE in Supabase migrations — before they ship.**

[Playground](https://tyoukyou23.github.io/supabase-grant-lint/) · [日本語](./README.ja.md)

```sh
npx supabase-grant-lint
```

```
error  todos  client-table-no-grant
       supabase/migrations/20261102000000_todos.sql:1
       The browser client queries this table, but neither anon nor authenticated is granted anything on it (42501 permission denied).
       fix: GRANT SELECT ON todos TO authenticated;  -- only the operations your RLS policies allow

error  term_apply(uuid, boolean)  definer-public-execute
       supabase/migrations/20261103000000_apply_dry_run.sql:1
       SECURITY DEFINER function is executable by PUBLIC/anon. It bypasses RLS, and anyone with the anon key can call it via /rpc.
       A REVOKE was written for term_apply(uuid) (20261101000000_apply.sql:3), a different overload, so it does not cover term_apply(uuid, boolean).
       fix: REVOKE ALL ON FUNCTION term_apply(uuid, boolean) FROM PUBLIC, anon;  -- and authenticated too, unless signed-in users or RLS policies call it
```

It reads `supabase/migrations/*.sql` in order and replays every `CREATE TABLE` / `VIEW` / `FUNCTION`, `GRANT`, `REVOKE`, `ALTER DEFAULT PRIVILEGES`, `ALTER ... RENAME / SET SCHEMA` and `DROP`, so it knows which role ends up holding which privilege. No database connection and no Docker. It runs in CI on every pull request and takes about a second.

## Why

These mistakes pass `supabase db push`, pass your tests, and the app looks fine — until someone opens the one screen that reads the table, or someone else calls your function with the anon key.

- **Supabase no longer auto-exposes new tables.** New projects since 2026-05-30, and tables created in existing projects from **2026-10-30**, no longer get `SELECT/INSERT/UPDATE/DELETE` for `anon`, `authenticated` or `service_role` (and sequences lose `USAGE/SELECT`). Local `supabase db reset` behaves the same way with `auto_expose_new_tables = false`. A table without an explicit `GRANT` returns `42501 permission denied`, even with perfect RLS policies. ([changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically))
- **`GRANT` adds, `REVOKE ALL` removes everything.** `GRANT SELECT ... TO authenticated;` followed by `REVOKE ALL ... FROM anon, authenticated;` leaves authenticated with nothing.
- **Functions are still executable by everyone by default.** PostgreSQL grants `EXECUTE` to `PUBLIC`, and Supabase grants it to `anon` and `authenticated` as well. A `SECURITY DEFINER` function bypasses RLS. If it takes a user id as a parameter, anyone can call `/rpc/your_function` and act as anyone. `REVOKE ... FROM PUBLIC` alone does not remove `anon`'s own grant.
- **A `REVOKE` names one overload.** Add a parameter, `CREATE OR REPLACE` the function, and you now have two functions. The old `REVOKE` protects the old one only.
- **Views ignore RLS by default.** A view runs with its owner's rights unless it is created `WITH (security_invoker = on)`, so a view over an RLS-protected table can show every row to `anon`.

Supabase's [Security Advisor](https://supabase.com/docs/guides/database/database-advisors) catches some of these on a live database, after the fact. This tool catches them in the migration, in the pull request that introduces them.

## Rules

| Rule | recommended | strict | Finds |
|---|---|---|---|
| `rls-disabled` | error | error | Table in an exposed schema without `ENABLE ROW LEVEL SECURITY` (`FORCE` alone does not enable it) |
| `view-bypasses-rls` | error | error | View without `security_invoker`, or a materialized view, that `anon`/`authenticated` can `SELECT` |
| `grant-order` | error | error | `REVOKE ALL` after a `GRANT` to the same role in the same migration, wiping privileges that are not granted again |
| `client-table-no-grant` | error | error | Your browser code calls `.from("table")`, but `anon` and `authenticated` have no privileges on it (needs `client` config) |
| `definer-public-execute` | error | error | `SECURITY DEFINER` function still executable by `PUBLIC` or `anon`, including when the `REVOKE` names a different overload |
| `missing-service-role-grant` | warn | error | `service_role` has no privileges on the table where new tables are not auto-exposed |
| `serial-sequence-grant` | warn | error | A client role may `INSERT`, but has no `USAGE` on the `serial` column's sequence |
| `missing-explicit-revoke` | off | error | No explicit `REVOKE ... FROM anon, authenticated` |
| `anon-table-access` | off | error | `anon` (or `PUBLIC`) holds SELECT/INSERT/UPDATE/DELETE. RLS still applies, so this is defence in depth |
| `rls-per-row-call` | warn | error | A policy calls `auth.uid()` / `auth.role()` / `auth.jwt()` or a zero-argument helper from your migrations without `(select ...)`, so it runs once per row. A helper that queries a table turns every scan into a query per row |

`strict` is meant for teams that want every table spelled out. On an existing project, adopt it with a [baseline](#adopting-on-an-existing-project-the-baseline).

Only schemas exposed through the Data API are checked. Trigger functions and procedures are skipped, because PostgREST cannot call them. A function you explicitly `GRANT EXECUTE ... TO anon` is taken as intentional.

The shape that passes `strict`:

```sql
CREATE TABLE notes (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, owner uuid NOT NULL, body text);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "owner" ON notes FOR ALL TO authenticated USING (owner = (select auth.uid()));

REVOKE ALL ON notes FROM anon, authenticated;                       -- REVOKE first
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO authenticated;     -- what the policies allow
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO service_role;

CREATE VIEW my_notes WITH (security_invoker = on) AS SELECT * FROM notes;
GRANT SELECT ON my_notes TO authenticated;

CREATE FUNCTION is_team_admin(p_team uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$ ... $$;
REVOKE ALL ON FUNCTION is_team_admin(uuid) FROM PUBLIC, anon;       -- exact argument types
GRANT EXECUTE ON FUNCTION is_team_admin(uuid) TO authenticated;     -- if RLS policies call it
```

## Two worlds

A Supabase migration has to be right both where new tables are auto-exposed (older projects, tables created before 2026-10-30) and where they are not (new projects, `db reset`, tables created later). By default (`"defaults": "both"`) the linter replays your migrations in both worlds. It reports each rule in the world where that rule can fail:

- **Too open** (`anon-table-access`, `view-bypasses-rls`, `definer-public-execute`): checked where everything is auto-granted, because your production tables really do still carry those grants.
- **Not granted** (`client-table-no-grant`, `missing-service-role-grant`, `serial-sequence-grant`): checked where nothing is, because that is what a fresh environment gets.

If all your environments are in one world, set `"defaults": "auto-expose"` or `"no-auto-expose"`. `ALTER DEFAULT PRIVILEGES` in your migrations is applied on top, in order. `FOR ROLE` is honoured: only the role that runs your migrations counts (`migrationRole`, default `postgres`).

## Configuration

Optional. Put `supabase-grant-lint.config.json` in your project root (or a `"supabaseGrantLint"` key in `package.json`). Unknown keys and invalid values are errors, so a typo cannot silently switch a check off.

```json
{
  "migrations": "supabase/migrations",
  "preset": "recommended",
  "schemas": ["public"],
  "defaults": "both",
  "migrationRole": "postgres",
  "rules": { "serial-sequence-grant": "error" },
  "client": {
    "marker": "lib/supabaseClient",
    "include": ["src", "app", "pages", "components", "hooks", "lib"],
    "exclude": ["pages/api", "app/api", "supabase"]
  }
}
```

- **`schemas`** defaults to `[api] schemas` in `supabase/config.toml`, or `["public"]` if there is none.
- **`client`** turns on `client-table-no-grant`. Files under `include` that match the `marker` regular expression (typically the import of your *browser* Supabase client) are scanned for `.from("table")`. `supabase.storage.from("bucket")`, `Array.from(...)` and the like are ignored. Leave server-only code out with `exclude`.

## Adopting on an existing project: the baseline

An older project will have findings you cannot fix today. Record them once, and from then on only **new** problems fail:

```sh
npx supabase-grant-lint --write-baseline     # writes supabase-grant-lint.baseline.json; commit it
npx supabase-grant-lint                      # passes; a new table without RLS still fails
npx supabase-grant-lint --prune-baseline     # after fixing some: removes those entries
```

Entries are `schema.object::rule` (for example `public.posts::rls-disabled`), so they survive `supabase migration squash` and file renames. The baseline only ever shrinks. `--write-baseline` refuses to add new entries to an existing baseline unless you pass `--force`, and `--fail-on-stale` makes CI insist that fixed entries are removed.

## Comment directives

```sql
-- grant-lint-ignore anon-table-access
CREATE TABLE public_announcements (...);   -- readable without login, on purpose
```

`-- grant-lint-ignore [rule, ...]` applies to the next statement (all rules if none are listed). Put it above the `CREATE` of the object, or above the statement the finding points at (for `grant-order`, the `REVOKE`).

```sql
-- grant-lint-as: REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public'
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon', r.sig);
  END LOOP;
END $$;
```

Dynamic SQL inside `DO` blocks cannot be read statically. `-- grant-lint-as: <SQL>` tells the linter what the block is equivalent to; the SQL is analysed in its place.

## CI

```yaml
# .github/workflows/migrations.yml
name: migrations
on: [pull_request]
jobs:
  grants:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npx supabase-grant-lint --format github
```

`--format github` turns findings into annotations on the pull request diff. `--format json` prints everything for other tools.

## CLI

```
--dir <path>          Migrations directory (default: supabase/migrations)
--config <path>       Config file
--preset <name>       recommended | strict
--format <name>       text | json | github
--no-baseline         Ignore the baseline file
--write-baseline      Record all current violations as the baseline
--force               With --write-baseline: allow adding entries to an existing baseline
--prune-baseline      Remove baseline entries that are fixed
--fail-on-stale       Exit 1 if the baseline has entries that are already fixed
--list-rules          Show the rules and their severity per preset
```

Exit codes: `0` no new errors (warnings do not fail), `1` new errors, `2` usage or configuration error (including an empty migrations directory). Requires Node.js 20 or later.

## API

```ts
import { analyze } from "supabase-grant-lint";           // pure, runs in the browser too
import { lintProject } from "supabase-grant-lint/node";   // reads files, config and baseline

const { violations } = analyze(
  [{ name: "001_init.sql", sql: "CREATE TABLE posts (id int);" }],
  { preset: "strict", clientTables: ["posts"] }
);
```

## How it is tested

Besides unit tests, the model is checked against real PostgreSQL. Randomly generated migrations are run in PostgreSQL, set up once with Supabase's default privileges and once with auto-expose off. The privileges PostgreSQL ends up with (`has_table_privilege`, `has_function_privilege`, `relrowsecurity`, view options) are compared with what the linter derives. The linter has also been run on the migrations of public Supabase projects.

## Limitations

- It is a migration linter, not a database scanner: privileges changed by hand in the dashboard are invisible to it. Run Supabase's Security Advisor as well.
- Dynamic SQL (`EXECUTE format(...)`) is not executed. Use `grant-lint-as`.
- Not checked yet: what RLS policies allow (only how they call functions is checked), objects created through `SET search_path` without a schema-qualified name, `SELECT ... INTO`, and declarative schema files in `supabase/schemas/`.
- Column-level grants (`GRANT SELECT (col)`) count as access to the table.

## License

MIT
