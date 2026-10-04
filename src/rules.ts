export type Severity = "error" | "warn" | "off";

export type RuleId =
  | "rls-disabled"
  | "view-bypasses-rls"
  | "grant-order"
  | "client-table-no-grant"
  | "definer-public-execute"
  | "missing-service-role-grant"
  | "serial-sequence-grant"
  | "missing-explicit-revoke"
  | "anon-table-access";

export type Preset = "recommended" | "strict";

export const SEVERITIES: Severity[] = ["error", "warn", "off"];
export const PRESETS: Preset[] = ["recommended", "strict"];

export interface RuleMeta {
  id: RuleId;
  /** One line, shown in --list-rules and the README. */
  summary: string;
  /** What to write instead. `{name}` is replaced with the object. */
  fix: string;
  recommended: Severity;
  strict: Severity;
}

export const RULES: Record<RuleId, RuleMeta> = {
  "rls-disabled": {
    id: "rls-disabled",
    summary: "Table in an exposed schema without ENABLE ROW LEVEL SECURITY.",
    fix: "ALTER TABLE {name} ENABLE ROW LEVEL SECURITY;",
    recommended: "error",
    strict: "error",
  },
  "view-bypasses-rls": {
    id: "view-bypasses-rls",
    summary:
      "Client roles can SELECT from this view, which runs with its owner's rights and ignores the RLS of the tables it reads.",
    fix: "ALTER VIEW {name} SET (security_invoker = on);  -- PostgreSQL 15+",
    recommended: "error",
    strict: "error",
  },
  "grant-order": {
    id: "grant-order",
    summary:
      "REVOKE ALL comes after a GRANT to the same role in the same migration and silently wipes it.",
    fix: "Move `REVOKE ALL ON {name} FROM ...;` above the GRANT statements.",
    recommended: "error",
    strict: "error",
  },
  "client-table-no-grant": {
    id: "client-table-no-grant",
    summary:
      "The browser client queries this table, but neither anon nor authenticated is granted anything on it (42501 permission denied).",
    fix: "GRANT SELECT ON {name} TO authenticated;  -- only the operations your RLS policies allow",
    recommended: "error",
    strict: "error",
  },
  "definer-public-execute": {
    id: "definer-public-execute",
    summary:
      "SECURITY DEFINER function is executable by PUBLIC/anon. It bypasses RLS, and anyone with the anon key can call it via /rpc.",
    fix: "REVOKE ALL ON FUNCTION {name} FROM PUBLIC, anon;  -- and authenticated too, unless signed-in users or RLS policies call it",
    recommended: "error",
    strict: "error",
  },
  "missing-service-role-grant": {
    id: "missing-service-role-grant",
    summary:
      "service_role has no privileges on this table where new tables are not auto-exposed (new projects, `db reset`, tables created after 2026-10-30): server code using the service key gets 42501.",
    fix: "GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO service_role;",
    recommended: "warn",
    strict: "error",
  },
  "serial-sequence-grant": {
    id: "serial-sequence-grant",
    summary:
      "A client role may INSERT into this table, but has no USAGE on its serial sequence (inserts fail with 42501).",
    fix: "GRANT USAGE, SELECT ON SEQUENCE {name} TO authenticated;  -- or use GENERATED ... AS IDENTITY",
    recommended: "warn",
    strict: "error",
  },
  "missing-explicit-revoke": {
    id: "missing-explicit-revoke",
    summary:
      "No explicit REVOKE ... FROM anon, authenticated for this table. Defaults differ between projects; be explicit.",
    fix: "REVOKE ALL ON {name} FROM anon, authenticated;  -- then GRANT only what you need",
    recommended: "off",
    strict: "error",
  },
  "anon-table-access": {
    id: "anon-table-access",
    summary:
      "anon (or PUBLIC) holds SELECT/INSERT/UPDATE/DELETE on this table. RLS still applies; this is defence in depth.",
    fix: "REVOKE ALL ON {name} FROM anon;  -- if anonymous access is intended, ignore this rule for the table",
    recommended: "off",
    strict: "error",
  },
};

export const RULE_IDS = Object.keys(RULES) as RuleId[];

export function resolveSeverities(
  preset: Preset = "recommended",
  overrides: Partial<Record<string, Severity>> = {}
): Record<RuleId, Severity> {
  if (!PRESETS.includes(preset)) throw new Error(`Unknown preset "${preset}". Use ${PRESETS.join(" or ")}.`);
  const out = {} as Record<RuleId, Severity>;
  for (const id of RULE_IDS) out[id] = RULES[id][preset];
  for (const [id, sev] of Object.entries(overrides)) {
    if (!(id in RULES)) throw new Error(`Unknown rule "${id}". Known rules: ${RULE_IDS.join(", ")}`);
    if (!SEVERITIES.includes(sev as Severity)) throw new Error(`Rule "${id}": severity must be ${SEVERITIES.join(", ")} (got "${sev}")`);
    out[id as RuleId] = sev as Severity;
  }
  return out;
}
