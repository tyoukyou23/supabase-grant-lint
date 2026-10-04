/**
 * A tiny SQL statement splitter — just enough lexing to analyse migrations safely.
 *
 * It understands the things that would otherwise fool a regex:
 *   - `-- line` and nested block comments
 *   - 'strings' (with '' escapes) and E'strings' (with backslash escapes)
 *   - "quoted identifiers"
 *   - $$dollar$$ / $tag$quoted$tag$ bodies (function bodies, DO blocks)
 *
 * Comments, string contents and dollar-quoted bodies are blanked out of the
 * returned statement text, so a `GRANT` written inside a function body or a
 * comment is never mistaken for a real one. Quoted identifiers are kept.
 *
 * Two comment directives are recognised (both apply to the next statement):
 *   -- grant-lint-ignore [rule, rule...]   suppress rules (all if none listed)
 *   -- grant-lint-as: <SQL>                analyse <SQL> as if it were written here
 * The second one exists for DO blocks that issue GRANT/REVOKE dynamically,
 * which no static tool can see through.
 */

export type IgnoreSpec = "all" | Set<string>;

export interface Statement {
  /** Statement text with comments, string contents and dollar bodies removed, whitespace collapsed. */
  text: string;
  /** 1-based line where the statement starts. */
  line: number;
  /** Rules suppressed by a preceding `-- grant-lint-ignore` comment. */
  ignore: IgnoreSpec | null;
}

const IDENT_CHAR = /[A-Za-z0-9_$]/;
const DOLLAR_TAG = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/;

function parseIgnore(rest: string): IgnoreSpec {
  const rules = rest
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return rules.length ? new Set(rules) : "all";
}

export function splitSql(sql: string): Statement[] {
  const out: Statement[] = [];
  const n = sql.length;
  let i = 0;
  let line = 1;

  let cur = "";
  let curLine = 0; // 0 = no statement started yet
  let curIgnore: IgnoreSpec | null = null;
  let pendingIgnore: IgnoreSpec | null = null;

  const start = () => {
    if (curLine === 0) {
      curLine = line;
      curIgnore = pendingIgnore;
      pendingIgnore = null;
    }
  };
  const flush = () => {
    const text = cur.replace(/\s+/g, " ").trim();
    if (text) out.push({ text, line: curLine, ignore: curIgnore });
    cur = "";
    curLine = 0;
    curIgnore = null;
  };
  const advance = (to: number) => {
    for (let k = i; k < to && k < n; k++) if (sql.charCodeAt(k) === 10) line++;
    i = to;
  };

  while (i < n) {
    const ch = sql[i];
    const next = sql[i + 1];

    // -- line comment (and directives)
    if (ch === "-" && next === "-") {
      let end = sql.indexOf("\n", i);
      if (end === -1) end = n;
      const body = sql.slice(i + 2, end).trim();
      const ign = /^grant-lint-ignore\b(.*)$/i.exec(body);
      const as = /^grant-lint-as:\s*(.*)$/i.exec(body);
      if (ign) pendingIgnore = parseIgnore(ign[1]);
      if (as) {
        for (const s of splitSql(as[1])) out.push({ ...s, line });
      }
      cur += " ";
      advance(end);
      continue;
    }

    // /* block comment */ (PostgreSQL allows nesting)
    if (ch === "/" && next === "*") {
      let depth = 1;
      let k = i + 2;
      while (k < n && depth > 0) {
        if (sql[k] === "/" && sql[k + 1] === "*") {
          depth++;
          k += 2;
        } else if (sql[k] === "*" && sql[k + 1] === "/") {
          depth--;
          k += 2;
        } else k++;
      }
      cur += " ";
      advance(k);
      continue;
    }

    // 'string' / E'string'
    if (ch === "'") {
      start();
      const prev = sql[i - 1] || "";
      const escapes = (prev === "E" || prev === "e") && !IDENT_CHAR.test(sql[i - 2] || "");
      let k = i + 1;
      while (k < n) {
        if (escapes && sql[k] === "\\") {
          k += 2;
          continue;
        }
        if (sql[k] === "'") {
          if (sql[k + 1] === "'") {
            k += 2;
            continue;
          }
          break;
        }
        k++;
      }
      cur += "''";
      advance(k + 1);
      continue;
    }

    // "quoted identifier" — kept verbatim
    if (ch === '"') {
      start();
      let k = i + 1;
      while (k < n) {
        if (sql[k] === '"') {
          if (sql[k + 1] === '"') {
            k += 2;
            continue;
          }
          break;
        }
        k++;
      }
      cur += sql.slice(i, k + 1);
      advance(k + 1);
      continue;
    }

    // $tag$ dollar-quoted body $tag$
    if (ch === "$" && !IDENT_CHAR.test(sql[i - 1] || "")) {
      const m = DOLLAR_TAG.exec(sql.slice(i, i + 64));
      if (m) {
        start();
        const tag = m[0];
        const close = sql.indexOf(tag, i + tag.length);
        const end = close === -1 ? n : close + tag.length;
        cur += "$$ $$";
        advance(end);
        continue;
      }
    }

    if (ch === ";") {
      advance(i + 1);
      flush();
      continue;
    }

    if (!/\s/.test(ch)) start();
    cur += ch;
    advance(i + 1);
  }
  flush();
  return out;
}

// ───────── identifiers ─────────

/** One identifier: "Quoted ""Name""" or bare_name. */
export const IDENT = `(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`;
/** Optionally schema-qualified name. */
export const QNAME = `${IDENT}(?:\\s*\\.\\s*${IDENT})?`;

/** Bare identifiers fold to lower case; quoted ones keep their case. */
export function normIdent(raw: string): string {
  const s = raw.trim();
  if (s.startsWith('"')) return s.slice(1, -1).replace(/""/g, '"');
  return s.toLowerCase();
}

/** Split a possibly-qualified name into schema + name (schema defaults to `public`). */
export function splitQName(raw: string, defaultSchema = "public"): { schema: string; name: string } {
  const parts: string[] = [];
  let buf = "";
  let quoted = false;
  for (let k = 0; k < raw.length; k++) {
    const c = raw[k];
    if (c === '"') {
      if (quoted && raw[k + 1] === '"') {
        buf += '""';
        k++;
        continue;
      }
      quoted = !quoted;
      buf += c;
      continue;
    }
    if (c === "." && !quoted) {
      parts.push(buf);
      buf = "";
      continue;
    }
    buf += c;
  }
  parts.push(buf);
  if (parts.length >= 2) return { schema: normIdent(parts[parts.length - 2]), name: normIdent(parts[parts.length - 1]) };
  return { schema: defaultSchema, name: normIdent(parts[0]) };
}

/** Index of the parenthesis that closes the one at `open`, or -1. */
export function matchParen(s: string, open: number): number {
  let depth = 0;
  for (let k = open; k < s.length; k++) {
    if (s[k] === "(") depth++;
    else if (s[k] === ")") {
      depth--;
      if (depth === 0) return k;
    }
  }
  return -1;
}

/** Split on commas that are not inside parentheses or brackets. */
export function splitTopLevel(s: string, sep = ","): string[] {
  const out: string[] = [];
  let depth = 0;
  let buf = "";
  let quoted = false;
  for (const c of s) {
    if (c === '"') quoted = !quoted;
    if (!quoted) {
      if (c === "(" || c === "[") depth++;
      else if (c === ")" || c === "]") depth--;
      else if (c === sep && depth === 0) {
        out.push(buf);
        buf = "";
        continue;
      }
    }
    buf += c;
  }
  if (buf.trim()) out.push(buf);
  return out.map((x) => x.trim());
}

/** Lower-cased role names from a `TO a, "B", PUBLIC` list. */
export function parseRoles(list: string): string[] {
  return splitTopLevel(list)
    .map((r) => r.replace(/^GROUP\s+/i, "").trim())
    .filter(Boolean)
    .map(normIdent);
}
