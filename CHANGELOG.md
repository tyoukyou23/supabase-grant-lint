# Changelog

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
