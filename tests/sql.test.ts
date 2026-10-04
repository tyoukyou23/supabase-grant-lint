import { describe, expect, it } from "vitest";
import { splitSql } from "../src/sql";
import { argTypes, normalizeType } from "../src/signature";

describe("splitSql", () => {
  it("splits on semicolons and reports start lines", () => {
    const s = splitSql("CREATE TABLE a (id int);\n\n-- note\nGRANT SELECT ON a TO anon;");
    expect(s.map((x) => [x.text, x.line])).toEqual([
      ["CREATE TABLE a (id int)", 1],
      ["GRANT SELECT ON a TO anon", 4],
    ]);
  });

  it("does not see statements inside dollar-quoted bodies, strings or comments", () => {
    const sql = `
      CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $body$
      BEGIN
        EXECUTE 'GRANT ALL ON t TO anon';  -- not a real grant
      END $body$;
      /* GRANT ALL ON t TO anon; /* nested */ still a comment; */
      SELECT 'it''s; fine', E'back\\'slash; too';
      DO $$ BEGIN GRANT ALL ON t TO anon; END $$;
    `;
    const texts = splitSql(sql).map((x) => x.text);
    expect(texts).toHaveLength(3);
    expect(texts.join(" ")).not.toMatch(/GRANT/);
  });

  it("keeps quoted identifiers", () => {
    const [s] = splitSql(`ALTER TABLE "My Table" ENABLE ROW LEVEL SECURITY;`);
    expect(s.text).toContain('"My Table"');
  });

  it("does not treat positional parameters as dollar quotes", () => {
    const s = splitSql("PREPARE p AS SELECT $1; SELECT 2;");
    expect(s).toHaveLength(2);
  });

  it("attaches grant-lint-ignore to the next statement only", () => {
    const s = splitSql("-- grant-lint-ignore rls-disabled, grant-order\nCREATE TABLE a ();\nCREATE TABLE b ();");
    expect(s[0].ignore).toEqual(new Set(["rls-disabled", "grant-order"]));
    expect(s[1].ignore).toBeNull();
    expect(splitSql("-- grant-lint-ignore\nCREATE TABLE a ();")[0].ignore).toBe("all");
  });

  it("expands grant-lint-as directives in place", () => {
    const s = splitSql("CREATE TABLE a ();\n-- grant-lint-as: REVOKE ALL ON a FROM anon; GRANT SELECT ON a TO authenticated;\nDO $$ BEGIN END $$;");
    expect(s.map((x) => [x.text, x.line])).toEqual([
      ["CREATE TABLE a ()", 1],
      ["REVOKE ALL ON a FROM anon", 2],
      ["GRANT SELECT ON a TO authenticated", 2],
      ["DO $$ $$", 3],
    ]);
  });
});

describe("function signatures", () => {
  it("drops names, defaults, OUT parameters and typmods", () => {
    expect(argTypes("p_id uuid, p_note varchar(200) DEFAULT 'x', OUT ok boolean, IN n int = 3")).toEqual([
      "uuid",
      "character varying",
      "integer",
    ]);
  });

  it("recognises multi-word types with and without a name", () => {
    expect(argTypes("timestamp with time zone, at time without time zone, double precision")).toEqual([
      "timestamp with time zone",
      "time without time zone",
      "double precision",
    ]);
  });

  it("treats a parameter named like a type keyword as a name", () => {
    expect(argTypes("time timestamptz")).toEqual(["timestamp with time zone"]);
  });

  it("normalises aliases, schemas and arrays", () => {
    expect(normalizeType("INT4")).toBe("integer");
    expect(normalizeType("public.my_enum")).toBe("my_enum");
    expect(normalizeType("int [ ]")).toBe("integer[]");
    expect(normalizeType("numeric(10, 2)")).toBe("numeric");
    expect(argTypes("VARIADIC ids bigint[]")).toEqual(["bigint[]"]);
  });
});
