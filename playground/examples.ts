export interface Example {
  id: string;
  title: string;
  blurb: string;
  sql: string;
  clientTables?: string;
  preset?: "recommended" | "strict";
}

export const EXAMPLES: Example[] = [
  {
    id: "forgot-grant",
    title: "Forgot the GRANT",
    blurb:
      "From 2026-10-30 new tables are no longer granted to anon, authenticated or service_role. A table your app reads needs an explicit GRANT, or the client gets 42501 permission denied. RLS policies alone are not enough.",
    clientTables: "todos",
    sql: `CREATE TABLE todos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users,
  title text NOT NULL
);
ALTER TABLE todos ENABLE ROW LEVEL SECURITY;

CREATE POLICY "own todos" ON todos
  FOR ALL TO authenticated USING (user_id = auth.uid());
-- ...but no GRANT, so the policy is never reached.
`,
  },
  {
    id: "grant-order",
    title: "REVOKE after GRANT",
    blurb: "GRANT adds, REVOKE ALL removes everything. Written in this order, the REVOKE silently wipes the GRANT above it.",
    sql: `CREATE TABLE profiles (id uuid PRIMARY KEY, display_name text);
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

GRANT SELECT, UPDATE ON profiles TO authenticated;
REVOKE ALL ON profiles FROM anon, authenticated;   -- wipes the line above
`,
  },
  {
    id: "definer",
    title: "SECURITY DEFINER open to anon",
    blurb:
      "PostgreSQL grants EXECUTE on every new function to PUBLIC. A SECURITY DEFINER function bypasses RLS, and anyone with the anon key can call it through /rpc.",
    sql: `CREATE FUNCTION public.book_slot(p_slot uuid, p_student uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  UPDATE slots SET student_id = p_student WHERE id = p_slot;
END $$;

-- Missing:
-- REVOKE ALL ON FUNCTION book_slot(uuid, uuid) FROM PUBLIC, anon;
`,
  },
  {
    id: "overload",
    title: "REVOKE hit the old overload",
    blurb:
      "The function gained a parameter. CREATE OR REPLACE with a new argument list creates a second function — the old REVOKE still points at the first one.",
    sql: `-- file: 001_apply.sql
CREATE FUNCTION term_apply(p_term uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN END $$;
REVOKE ALL ON FUNCTION term_apply(uuid) FROM PUBLIC, anon;

-- file: 002_apply_dry_run.sql
CREATE OR REPLACE FUNCTION term_apply(p_term uuid, p_dry_run boolean DEFAULT false)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN END $$;
`,
  },
  {
    id: "view",
    title: "View that skips RLS",
    blurb:
      "A view runs with its owner's rights unless it is created WITH (security_invoker = on). This one shows every draft to anyone with the anon key, although the table's policy hides drafts.",
    sql: `CREATE TABLE posts (id uuid PRIMARY KEY, author uuid, draft boolean, body text);
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "published or mine" ON posts FOR SELECT
  USING (NOT draft OR author = auth.uid());
GRANT SELECT ON posts TO anon, authenticated;
GRANT ALL ON posts TO service_role;

CREATE VIEW post_feed AS
  SELECT id, body, draft FROM posts;   -- add WITH (security_invoker = on)
`,
  },
  {
    id: "sweep",
    title: "Sweep in a DO block",
    blurb:
      "Hardening sweeps often loop over pg_proc and EXECUTE dynamic REVOKEs, which no static tool can read. A grant-lint-as comment says what the block does.",
    sql: `-- file: 001_helpers.sql
CREATE FUNCTION is_staff() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER AS $$ SELECT true $$;

-- file: 002_sweep.sql
-- grant-lint-as: REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT p.oid::regprocedure AS sig
           FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public'
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon', r.sig);
  END LOOP;
END $$;
`,
  },
  {
    id: "good",
    title: "The shape that passes",
    blurb: "RLS on, REVOKE first, then only the GRANTs your policies allow. Passes the strict preset.",
    preset: "strict",
    clientTables: "notes",
    sql: `CREATE TABLE notes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner uuid NOT NULL DEFAULT auth.uid(),
  body text
);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "owner" ON notes FOR ALL TO authenticated USING (owner = auth.uid());

REVOKE ALL ON notes FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO service_role;
`,
  },
];
