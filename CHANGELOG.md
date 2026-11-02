# Changelog

## 0.2.0

- New rule `rls-per-row-call` (recommended: warn, strict: error). A policy that calls `auth.uid()`, `auth.role()`, `auth.jwt()` or a zero-argument function defined in your migrations without wrapping it in `(select ...)` is evaluated once per row instead of once per query. When the helper is `SECURITY DEFINER` and reads a table (the usual `current_user_role()`), every row of every scan pays for an extra query. Seen in production: one Storage signed-URL lookup took 142 ms and 21,616 buffers; wrapping the calls brought it to 7 ms and 786 buffers, with exactly the same rows visible.
- Policies are now replayed: `CREATE POLICY`, `ALTER POLICY` (only the clauses it names), `ALTER POLICY ... RENAME TO`, `DROP POLICY`, and `DROP TABLE`. Baseline key: `schema.table.policy::rls-per-row-call`.
- README and playground examples use `(select auth.uid())`.

## 0.1.0 — unreleased

First release.

- Rules: `rls-disabled`, `view-bypasses-rls`, `grant-order`, `client-table-no-grant`, `definer-public-execute`, `missing-service-role-grant`, `serial-sequence-grant`, `missing-explicit-revoke`, `anon-table-access`
- Presets `recommended` and `strict`; per-rule overrides
- Checks each rule in both Supabase worlds (new tables auto-exposed or not) — `defaults: "both" | "auto-expose" | "no-auto-expose"`
- Replays `ALTER DEFAULT PRIVILEGES` (global and per schema, honouring `FOR ROLE`), `ALL TABLES/SEQUENCES/FUNCTIONS/ROUTINES IN SCHEMA`, `DROP`, `RENAME`, `SET SCHEMA`, `CREATE OR REPLACE` (keeps the ACL), function overloads and view options
- Exposed schemas read from `supabase/config.toml`
- `client` config: finds the tables your browser code reads
- Baseline keyed by `schema.object::rule` (`--write-baseline`, `--prune-baseline`, `--fail-on-stale`)
- Comment directives `grant-lint-ignore` and `grant-lint-as`
- Output formats `text`, `json`, `github`
- Browser playground
- Verified against PostgreSQL with differential fuzzing
