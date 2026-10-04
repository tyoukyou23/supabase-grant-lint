/**
 * Function signatures — so that `REVOKE ... ON FUNCTION f(int)` is matched to
 * `CREATE FUNCTION f(p_id integer)` but NOT to `CREATE FUNCTION f(p_id uuid, p_note text)`.
 *
 * PostgreSQL identifies a function by its name and its input argument types.
 * Argument names, defaults, OUT parameters and type modifiers are not part of it.
 * A REVOKE that names a different overload is applied to that overload and
 * leaves the one you meant callable — a mistake that is easy to make after a
 * function gains a parameter and is re-created.
 */
import { splitTopLevel } from "./sql";

const ALIASES: Record<string, string> = {
  int: "integer",
  int4: "integer",
  int2: "smallint",
  int8: "bigint",
  bool: "boolean",
  float8: "double precision",
  float: "double precision",
  float4: "real",
  varchar: "character varying",
  "char varying": "character varying",
  char: "character",
  bpchar: "character",
  decimal: "numeric",
  timestamptz: "timestamp with time zone",
  timestamp: "timestamp without time zone",
  timetz: "time with time zone",
  time: "time without time zone",
  varbit: "bit varying",
};

/** Placeholder for `table.column%TYPE`: the real type is unknown statically, so it matches anything. */
export const ANY_TYPE = "?";

/** Whole-argument patterns that are a type with no parameter name in front. */
const BARE_TYPE =
  /^(double precision|character varying|char varying|bit varying|national character( varying)?|(timestamp|time)( \(\d+\))?( with(out)? time zone)?|interval( \w+( to \w+)?)?)(\[\])*$/i;

const MODES = new Set(["in", "out", "inout", "variadic"]);

export function normalizeType(raw: string): string {
  let t = raw.trim().toLowerCase();
  if (/%\s*type$/.test(t)) return ANY_TYPE;
  t = t.replace(/"/g, "");
  t = t.replace(/\s*\(\s*[\d\s,]*\)/g, ""); // typmods: varchar(10), numeric(10, 2)
  t = t.replace(/\s+/g, " ");
  let arr = "";
  const m = /((?:\s*\[\s*\d*\s*\])+)$/.exec(t);
  if (m) {
    arr = "[]".repeat((m[1].match(/\[/g) || []).length);
    t = t.slice(0, m.index).trim();
  }
  t = t.replace(/^(public|pg_catalog)\s*\.\s*/, "");
  return (ALIASES[t] || t) + arr;
}

/**
 * Input argument types of a parenthesised argument list (without the parentheses).
 * Returns e.g. ["uuid", "text"] for `p_id uuid, p_note text DEFAULT NULL, OUT ok boolean`.
 */
export function argTypes(list: string): string[] {
  const types: string[] = [];
  for (const rawArg of splitTopLevel(list)) {
    let arg = rawArg.replace(/(\s+default\b|\s*=)[\s\S]*$/i, "").trim();
    if (!arg) continue;
    const first = arg.split(/\s+/)[0].toLowerCase();
    let mode = "in";
    if (MODES.has(first) && arg.split(/\s+/).length > 1) {
      mode = first;
      arg = arg.slice(first.length).trim();
    }
    if (mode === "out") continue;
    const tokens = arg.split(/\s+/);
    const type = tokens.length > 1 && !BARE_TYPE.test(arg) ? tokens.slice(1).join(" ") : arg;
    types.push(normalizeType(type));
  }
  return types;
}

/** Do two argument-type lists denote the same signature? `%TYPE` arguments match anything. */
export function sameTypes(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((t, i) => t === b[i] || t === ANY_TYPE || b[i] === ANY_TYPE);
}

export function signature(schema: string, name: string, types: string[]): string {
  const prefix = schema === "public" ? "" : `${schema}.`;
  return `${prefix}${name}(${types.join(", ")})`;
}
