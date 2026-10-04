/**
 * The analyser: replays every migration in order and tracks, per table / view /
 * sequence / function, which role ends up holding which privilege.
 *
 * Supabase projects live in one of two worlds, and a migration has to be right in both:
 *   auto-expose     new tables are granted to anon, authenticated and service_role
 *                   (projects created before 2026-05-30; tables created before 2026-10-30)
 *   no-auto-expose  new tables get no SELECT/INSERT/UPDATE/DELETE for those roles
 *                   (new projects, `supabase db reset` with auto_expose_new_tables = false,
 *                   and every table created after 2026-10-30)
 * By default each rule is checked in the world where it can fail: "too open" rules in
 * auto-expose, "not granted" rules in no-auto-expose.
 *
 * Pure — no file system access — so it runs in Node and in the browser playground.
 */
import { IDENT, QNAME, matchParen, normIdent, parseRoles, splitQName, splitSql, splitTopLevel } from "./sql";
import type { IgnoreSpec } from "./sql";
import { argTypes, sameTypes, signature } from "./signature";
import { RULES, resolveSeverities } from "./rules";
import type { Preset, RuleId, Severity } from "./rules";

export interface MigrationFile {
  /** File name, e.g. `20260101000000_create_posts.sql`. Used in messages. */
  name: string;
  sql: string;
}

export type DefaultsMode = "both" | "auto-expose" | "no-auto-expose";

export interface AnalyzeOptions {
  preset?: Preset;
  /** Per-rule overrides: `{ "anon-table-access": "off" }`. */
  rules?: Partial<Record<string, Severity>>;
  /** Schemas exposed through the Data API. Objects elsewhere are ignored. Default `["public"]`. */
  schemas?: string[];
  /**
   * Which Supabase default privileges to assume for objects created in `public`.
   * `"both"` (default) checks every rule in the world where it can fail. See the file header.
   */
  defaults?: DefaultsMode;
  /** Role that runs your migrations. `ALTER DEFAULT PRIVILEGES FOR ROLE x` only counts for this role. Default `postgres`. */
  migrationRole?: string;
  /** Tables/views the browser client reads (`posts` or `schema.posts`). Enables `client-table-no-grant`. */
  clientTables?: Iterable<string>;
}

export interface Violation {
  rule: RuleId;
  severity: "error" | "warn";
  file: string;
  line: number;
  /** Table, view, sequence or function signature — schema-qualified unless in `public`. */
  object: string;
  message: string;
  fix: string;
  /** Extra context, e.g. a REVOKE that targeted a different overload. */
  note?: string;
  /** Stable key used by the baseline: `schema.object::rule`. Survives squashing and file renames. */
  key: string;
}

export interface AnalyzeResult {
  violations: Violation[];
  stats: { files: number; tables: number; views: number; functions: number };
}

// ───────── privilege bookkeeping ─────────

type PrivMap = Map<string, Set<string>>;
type Kind = "tables" | "sequences" | "functions";

const TABLE_PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"];
const SEQ_PRIVS = ["USAGE", "SELECT", "UPDATE"];
const FN_PRIVS = ["EXECUTE"];
const CRUD = ["SELECT", "INSERT", "UPDATE", "DELETE"];
const CLIENT_ROLES = ["anon", "authenticated"];
const SUPABASE_ROLES = ["anon", "authenticated", "service_role"];
const ALL_OF: Record<Kind, string[]> = { tables: TABLE_PRIVS, sequences: SEQ_PRIVS, functions: FN_PRIVS };

function clone(m: PrivMap): PrivMap {
  const out: PrivMap = new Map();
  for (const [r, s] of m) out.set(r, new Set(s));
  return out;
}

function applyTo(map: PrivMap, kind: "GRANT" | "REVOKE", roles: string[], privs: string[]) {
  for (const role of roles) {
    if (!map.has(role)) map.set(role, new Set());
    const held = map.get(role)!;
    for (const p of privs) kind === "GRANT" ? held.add(p) : held.delete(p);
  }
}

/** Privileges `role` effectively holds, including those granted to PUBLIC. */
function effective(map: PrivMap, role: string): Set<string> {
  return new Set([...(map.get(role) || []), ...(map.get("public") || [])]);
}

const hasAny = (held: Set<string>, wanted: string[]) => wanted.some((p) => held.has(p));

function parsePrivs(raw: string, kind: Kind): string[] {
  const list = raw
    .replace(/\([^)]*\)/g, " ") // column lists: SELECT (id, name)
    .split(",")
    .map((p) => p.trim().toUpperCase().replace(/\s+/g, " "))
    .filter(Boolean);
  if (list.some((p) => p === "ALL" || p === "ALL PRIVILEGES")) return [...ALL_OF[kind]];
  return list;
}

// ───────── records ─────────

interface Loc {
  file: string;
  line: number;
  ignore: IgnoreSpec | null;
}

interface PrivEvent extends Loc {
  kind: "GRANT" | "REVOKE";
  roles: string[];
  privs: string[];
  revokeAll: boolean;
}

interface RelRec extends Loc {
  kind: "table" | "view" | "matview";
  schema: string;
  name: string;
  rls: boolean;
  securityInvoker: boolean;
  privs: PrivMap;
  events: PrivEvent[];
  /** Serial sequences, by name (they keep their name when the table is renamed). */
  sequences: string[];
}

interface FnRec extends Loc {
  schema: string;
  name: string;
  types: string[];
  sig: string;
  definer: boolean;
  trigger: boolean;
  privs: PrivMap;
  /** The author explicitly granted EXECUTE to anon/PUBLIC on this very function (last word on it). */
  explicitlyOpen: boolean;
}

interface FnRef {
  schema: string;
  name: string;
  types: string[] | null;
}

interface State {
  rels: Map<string, RelRec>;
  sequences: Map<string, PrivMap>;
  functions: Map<string, FnRec>;
  fnRevokes: Map<string, { sig: string; file: string; line: number }[]>;
}

const qkey = (schema: string, name: string) => `${schema}.${name}`;
const display = (schema: string, name: string) => (schema === "public" ? name : `${schema}.${name}`);

/** Parse `a(int), b.c, d(uuid, text)` into function references. */
function parseFnRefs(s: string): FnRef[] {
  const out: FnRef[] = [];
  const re = new RegExp(`\\s*(${QNAME})\\s*`, "y");
  let pos = 0;
  while (pos < s.length) {
    re.lastIndex = pos;
    const m = re.exec(s);
    if (!m) break;
    const { schema, name } = splitQName(m[1]);
    pos = re.lastIndex;
    let types: string[] | null = null;
    if (s[pos] === "(") {
      const close = matchParen(s, pos);
      if (close === -1) break;
      types = argTypes(s.slice(pos + 1, close));
      pos = close + 1;
    }
    out.push({ schema, name, types });
    const comma = /^\s*,/.exec(s.slice(pos));
    if (!comma) break;
    pos += comma[0].length;
  }
  return out;
}

function cutRoleTail(s: string): string {
  return s.split(/\s+(?:WITH\s+GRANT\s+OPTION|GRANTED\s+BY|CASCADE|RESTRICT)\b/i)[0];
}

/** Replace "quoted identifiers" with a neutral token, so their contents never look like keywords. */
// Same length as the original, so offsets found in the blanked text stay valid in the original.
const blankQuoted = (s: string) => s.replace(/"(?:[^"]|"")*"/g, (q) => "_".repeat(q.length));

/**
 * GRANT / REVOKE, parsed by scanning for keywords instead of one big regex
 * (a single regex with several lazy groups backtracks quadratically on large inputs).
 */
function parseGrant(t: string) {
  const head = /^(GRANT|REVOKE)\s+(GRANT\s+OPTION\s+FOR\s+)?/i.exec(t);
  if (!head) return null;
  const plain = blankQuoted(t);
  const on = /\sON\s/i.exec(plain.slice(head[0].length));
  if (!on) return null; // role membership: GRANT anon TO authenticator
  const privEnd = head[0].length + on.index;
  const targetStart = privEnd + on[0].length;
  const toFrom = /\s(TO|FROM)\s/i.exec(plain.slice(targetStart));
  if (!toFrom) return null;
  return {
    verb: head[1].toUpperCase() as "GRANT" | "REVOKE",
    grantOptionOnly: !!head[2],
    privs: t.slice(head[0].length, privEnd),
    target: t.slice(targetStart, targetStart + toFrom.index).trim(),
    roles: parseRoles(cutRoleTail(t.slice(targetStart + toFrom.index + toFrom[0].length))),
  };
}

function viewInvoker(options: string): boolean | null {
  const m = /\bsecurity_invoker\b\s*(?:=\s*([^,)]+))?/i.exec(options);
  if (!m) return null;
  const v = (m[1] || "true").trim().toLowerCase();
  // string values are blanked by the lexer (''), so a quoted value counts as "set"
  return !["false", "off", "0", "no"].includes(v);
}

// ───────── statement patterns ─────────

const REL_KEYWORD = `(TABLE|VIEW|MATERIALIZED\\s+VIEW|FOREIGN\\s+TABLE)`;
const RE = {
  createTable: new RegExp(
    `^CREATE\\s+(?:(GLOBAL|LOCAL)\\s+)?(?:(TEMP|TEMPORARY)\\s+)?(?:UNLOGGED\\s+)?TABLE\\s+(IF\\s+NOT\\s+EXISTS\\s+)?(${QNAME})`,
    "i"
  ),
  createView: new RegExp(
    `^CREATE\\s+(OR\\s+REPLACE\\s+)?(?:(TEMP|TEMPORARY)\\s+)?(?:RECURSIVE\\s+)?VIEW\\s+(${QNAME})([\\s\\S]*)$`,
    "i"
  ),
  createMatView: new RegExp(`^CREATE\\s+MATERIALIZED\\s+VIEW\\s+(IF\\s+NOT\\s+EXISTS\\s+)?(${QNAME})`, "i"),
  dropRel: new RegExp(`^DROP\\s+${REL_KEYWORD}\\s+(?:IF\\s+EXISTS\\s+)?(.+?)(?:\\s+(?:CASCADE|RESTRICT))?$`, "i"),
  alterRel: new RegExp(`^ALTER\\s+${REL_KEYWORD}\\s+(?:IF\\s+EXISTS\\s+)?(?:ONLY\\s+)?(${QNAME})\\s*\\*?\\s+([\\s\\S]*)$`, "i"),
  serialCol: new RegExp(`(?:^|[(,]|ADD\\s+(?:COLUMN\\s+)?(?:IF\\s+NOT\\s+EXISTS\\s+)?)\\s*(${IDENT})\\s+(?:small|big)?serial[248]?\\b`, "gi"),
  createFn: new RegExp(`^CREATE\\s+(OR\\s+REPLACE\\s+)?FUNCTION\\s+(${QNAME})\\s*\\(`, "i"),
  triggerReturn: /\bRETURNS\s+(?:"?pg_catalog"?\s*\.\s*)?"?(?:event_)?trigger"?(?=\s|$)/i,
  alterFn: /^ALTER\s+(?:FUNCTION|ROUTINE)\s+([\s\S]+)$/i,
  dropFn: /^DROP\s+(?:FUNCTION|ROUTINE)\s+(?:IF\s+EXISTS\s+)?([\s\S]+?)(?:\s+(?:CASCADE|RESTRICT))?$/i,
  createSeq: new RegExp(`^CREATE\\s+(?:(?:TEMP|TEMPORARY|UNLOGGED)\\s+)?SEQUENCE\\s+(IF\\s+NOT\\s+EXISTS\\s+)?(${QNAME})`, "i"),
  dropSeq: /^DROP\s+SEQUENCE\s+(?:IF\s+EXISTS\s+)?(.+?)(?:\s+(?:CASCADE|RESTRICT))?$/i,
  alterDefault:
    /^ALTER\s+DEFAULT\s+PRIVILEGES\s+(?:FOR\s+(?:ROLE|USER)\s+([\s\S]+?)\s+)?(?:IN\s+SCHEMA\s+([\s\S]+?)\s+)?(GRANT|REVOKE)\s+(GRANT\s+OPTION\s+FOR\s+)?([\s\S]+?)\s+ON\s+(TABLES|SEQUENCES|FUNCTIONS|ROUTINES|TYPES|SCHEMAS|LARGE\s+OBJECTS)\s+(TO|FROM)\s+([\s\S]+)$/i,
};

// ───────── replay ─────────

interface ReplayOptions {
  world: "auto-expose" | "no-auto-expose";
  migrationRole: string;
}

function replay(files: MigrationFile[], o: ReplayOptions): State {
  // Default privileges: global + per schema, per object kind (as pg_default_acl keeps them).
  const global: Record<Kind, PrivMap> = { tables: new Map(), sequences: new Map(), functions: new Map() };
  const perSchema = new Map<string, Record<Kind, PrivMap>>();
  const schemaDefaults = (s: string) => {
    if (!perSchema.has(s)) perSchema.set(s, { tables: new Map(), sequences: new Map(), functions: new Map() });
    return perSchema.get(s)!;
  };
  // Built into PostgreSQL: EXECUTE on new functions for PUBLIC. A global (no IN SCHEMA)
  // ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC removes it.
  applyTo(global.functions, "GRANT", ["public"], ["EXECUTE"]);
  // Supabase grants these in `public` for the migration role.
  const pub = schemaDefaults("public");
  applyTo(pub.functions, "GRANT", SUPABASE_ROLES, FN_PRIVS);
  applyTo(pub.tables, "GRANT", SUPABASE_ROLES, TABLE_PRIVS);
  applyTo(pub.sequences, "GRANT", SUPABASE_ROLES, SEQ_PRIVS);
  if (o.world === "no-auto-expose") {
    // What Supabase's change revokes: table CRUD and sequence USAGE/SELECT.
    applyTo(pub.tables, "REVOKE", SUPABASE_ROLES, CRUD);
    applyTo(pub.sequences, "REVOKE", SUPABASE_ROLES, ["USAGE", "SELECT"]);
  }
  const initialPrivs = (kind: Kind, schema: string): PrivMap => {
    const out = clone(global[kind]);
    for (const [r, s] of schemaDefaults(schema)[kind]) {
      if (!out.has(r)) out.set(r, new Set());
      for (const p of s) out.get(r)!.add(p);
    }
    return out;
  };

  const st: State = { rels: new Map(), sequences: new Map(), functions: new Map(), fnRevokes: new Map() };
  const { rels, sequences, functions, fnRevokes } = st;

  const addSequence = (schema: string, name: string) => sequences.set(qkey(schema, name), initialPrivs("sequences", schema));
  const fnMatches = (ref: FnRef): FnRec[] =>
    [...functions.values()].filter(
      (f) => f.schema === ref.schema && f.name === ref.name && (!ref.types || sameTypes(f.types, ref.types))
    );
  const newRel = (kind: RelRec["kind"], schema: string, name: string, loc: Loc): RelRec => ({
    ...loc,
    kind,
    schema,
    name,
    rls: false,
    securityInvoker: false,
    privs: initialPrivs("tables", schema),
    events: [],
    sequences: [],
  });

  for (const file of files) {
    for (const s of splitSql(file.sql)) {
      const t = s.text;
      const loc: Loc = { file: file.name, line: s.line, ignore: s.ignore };
      let m: RegExpExecArray | null;

      if ((m = RE.createTable.exec(t))) {
        if (m[2]) continue; // temporary tables live in a session-private schema
        const { schema, name } = splitQName(m[4]);
        const k = qkey(schema, name);
        if (rels.has(k) && m[3]) continue; // IF NOT EXISTS on an existing table is a no-op
        const rec = newRel("table", schema, name, loc);
        for (const c of t.matchAll(RE.serialCol)) {
          const seq = `${name}_${normIdent(c[1])}_seq`.slice(0, 63);
          rec.sequences.push(seq);
          addSequence(schema, seq);
        }
        rels.set(k, rec);
        continue;
      }

      if ((m = RE.createView.exec(t))) {
        if (m[2]) continue;
        const { schema, name } = splitQName(m[3]);
        const k = qkey(schema, name);
        const opts = /^\s*(?:\([^)]*\)\s*)?WITH\s*\(([^)]*)\)/i.exec(m[4]);
        const invoker = opts ? viewInvoker(opts[1]) : null;
        const existing = m[1] ? rels.get(k) : undefined;
        if (existing && existing.kind === "view") {
          // CREATE OR REPLACE keeps the ACL; options are replaced by the new WITH clause
          existing.securityInvoker = !!invoker;
          continue;
        }
        const rec = newRel("view", schema, name, loc);
        rec.securityInvoker = !!invoker;
        rels.set(k, rec);
        continue;
      }

      if ((m = RE.createMatView.exec(t))) {
        const { schema, name } = splitQName(m[2]);
        const k = qkey(schema, name);
        if (rels.has(k) && m[1]) continue;
        rels.set(k, newRel("matview", schema, name, loc));
        continue;
      }

      if ((m = RE.dropRel.exec(t))) {
        for (const item of splitTopLevel(m[2])) {
          const { schema, name } = splitQName(item);
          rels.delete(qkey(schema, name));
        }
        continue;
      }

      if ((m = RE.alterRel.exec(t))) {
        const { schema, name } = splitQName(m[2]);
        const rec = rels.get(qkey(schema, name));
        if (!rec) continue;
        const rest = m[3];
        const plain = blankQuoted(rest);
        if (/\bENABLE\s+ROW\s+LEVEL\s+SECURITY\b/i.test(plain)) rec.rls = true;
        if (/\bDISABLE\s+ROW\s+LEVEL\s+SECURITY\b/i.test(plain)) rec.rls = false;
        const opts = /\bSET\s*\(([^)]*)\)/i.exec(plain);
        if (opts) {
          const v = viewInvoker(opts[1]);
          if (v !== null) rec.securityInvoker = v;
        }
        if (/\bRESET\s*\([^)]*\bsecurity_invoker\b/i.test(plain)) rec.securityInvoker = false;
        const ren = new RegExp(`^RENAME\\s+TO\\s+(${IDENT})$`, "i").exec(rest.trim());
        const mv = new RegExp(`^SET\\s+SCHEMA\\s+(${IDENT})$`, "i").exec(rest.trim());
        if (ren || mv) {
          rels.delete(qkey(schema, name));
          if (ren) rec.name = normIdent(ren[1]);
          if (mv) {
            const to = normIdent(mv[1]);
            // owned sequences move with the table
            for (const seq of rec.sequences) {
              const privs = sequences.get(qkey(rec.schema, seq));
              sequences.delete(qkey(rec.schema, seq));
              if (privs) sequences.set(qkey(to, seq), privs);
            }
            rec.schema = to;
          }
          rels.set(qkey(rec.schema, rec.name), rec);
        }
        for (const c of rest.matchAll(RE.serialCol)) {
          const seq = `${rec.name}_${normIdent(c[1])}_seq`.slice(0, 63);
          rec.sequences.push(seq);
          addSequence(rec.schema, seq);
        }
        continue;
      }

      if ((m = RE.createSeq.exec(t))) {
        const { schema, name } = splitQName(m[2]);
        if (!(m[1] && sequences.has(qkey(schema, name)))) addSequence(schema, name);
        continue;
      }

      if ((m = RE.dropSeq.exec(t))) {
        for (const item of splitTopLevel(m[1])) {
          const { schema, name } = splitQName(item);
          sequences.delete(qkey(schema, name));
        }
        continue;
      }

      if ((m = RE.createFn.exec(t))) {
        const { schema, name } = splitQName(m[2]);
        const open = m[0].length - 1;
        const close = matchParen(t, open);
        if (close === -1) continue;
        const types = argTypes(t.slice(open + 1, close));
        const rest = t.slice(close + 1);
        const sig = signature(schema, name, types);
        const existing = functions.get(sig);
        const ignore =
          existing?.ignore === "all" || s.ignore === "all"
            ? "all"
            : existing?.ignore || s.ignore
              ? new Set([...(existing?.ignore || []), ...(s.ignore || [])])
              : null;
        functions.set(sig, {
          ...loc,
          ignore,
          schema,
          name,
          types,
          sig,
          definer: /\bSECURITY\s+DEFINER\b/i.test(blankQuoted(rest)),
          trigger: RE.triggerReturn.test(rest),
          // CREATE OR REPLACE keeps the existing ACL
          privs: existing ? existing.privs : initialPrivs("functions", schema),
          explicitlyOpen: existing ? existing.explicitlyOpen : false,
        });
        continue;
      }

      if ((m = RE.alterFn.exec(t))) {
        const [ref] = parseFnRefs(m[1]);
        if (!ref) continue;
        const rest = blankQuoted(m[1]);
        for (const f of fnMatches(ref)) {
          if (/\bSECURITY\s+DEFINER\b/i.test(rest)) f.definer = true;
          if (/\bSECURITY\s+INVOKER\b/i.test(rest)) f.definer = false;
          const ren = new RegExp(`\\bRENAME\\s+TO\\s+(${IDENT})\\s*$`, "i").exec(m[1]);
          const mv = new RegExp(`\\bSET\\s+SCHEMA\\s+(${IDENT})\\s*$`, "i").exec(m[1]);
          if (ren || mv) {
            functions.delete(f.sig);
            if (ren) f.name = normIdent(ren[1]);
            if (mv) f.schema = normIdent(mv[1]);
            f.sig = signature(f.schema, f.name, f.types);
            functions.set(f.sig, f);
          }
        }
        continue;
      }

      if ((m = RE.dropFn.exec(t))) {
        for (const ref of parseFnRefs(m[1])) for (const f of fnMatches(ref)) functions.delete(f.sig);
        continue;
      }

      if ((m = RE.alterDefault.exec(t))) {
        if (m[4]) continue; // GRANT OPTION FOR
        if (m[1] && !parseRoles(m[1]).includes(o.migrationRole)) continue; // defaults of some other role
        const objKind = m[6].toUpperCase();
        const kind: Kind | null =
          objKind === "TABLES" ? "tables" : objKind === "SEQUENCES" ? "sequences" : /FUNCTIONS|ROUTINES/.test(objKind) ? "functions" : null;
        if (!kind) continue;
        const roles = parseRoles(cutRoleTail(m[8]));
        const privs = parsePrivs(m[5], kind);
        const targets = m[2] ? splitTopLevel(m[2]).map((x) => schemaDefaults(normIdent(x))[kind]) : [global[kind]];
        for (const map of targets) applyTo(map, m[3].toUpperCase() as "GRANT" | "REVOKE", roles, privs);
        continue;
      }

      const g = parseGrant(t);
      if (g) {
        if (g.grantOptionOnly) continue; // REVOKE GRANT OPTION FOR keeps the privilege itself
        const { verb, roles, target } = g;

        const all = /^ALL\s+(TABLES|SEQUENCES|FUNCTIONS|ROUTINES|PROCEDURES)\s+IN\s+SCHEMA\s+([\s\S]+)$/i.exec(target);
        if (all) {
          const schemas = new Set(splitTopLevel(all[2]).map(normIdent));
          const what = all[1].toUpperCase();
          if (what === "TABLES") {
            // ALL TABLES includes views and materialized views
            const privs = parsePrivs(g.privs, "tables");
            for (const rec of rels.values()) {
              if (!schemas.has(rec.schema)) continue;
              applyTo(rec.privs, verb, roles, privs);
              rec.events.push({ ...loc, kind: verb, roles, privs, revokeAll: privs.length === TABLE_PRIVS.length });
            }
          } else if (what === "SEQUENCES") {
            const privs = parsePrivs(g.privs, "sequences");
            for (const [k, seq] of sequences) if (schemas.has(k.slice(0, k.indexOf(".")))) applyTo(seq, verb, roles, privs);
          } else if (what !== "PROCEDURES") {
            const privs = parsePrivs(g.privs, "functions");
            for (const f of functions.values()) {
              if (!schemas.has(f.schema)) continue;
              applyTo(f.privs, verb, roles, privs);
              if (verb === "REVOKE" && roles.some((r) => r === "anon" || r === "public")) f.explicitlyOpen = false;
            }
          }
          continue;
        }

        const seq = /^SEQUENCE\s+([\s\S]+)$/i.exec(target);
        if (seq) {
          const privs = parsePrivs(g.privs, "sequences");
          for (const item of splitTopLevel(seq[1])) {
            const { schema, name } = splitQName(item);
            const rec = sequences.get(qkey(schema, name));
            if (rec) applyTo(rec, verb, roles, privs);
          }
          continue;
        }

        const fn = /^(?:FUNCTION|ROUTINE)\s+([\s\S]+)$/i.exec(target);
        if (fn) {
          const privs = parsePrivs(g.privs, "functions");
          const opensToAnon = roles.some((r) => r === "anon" || r === "public");
          for (const ref of parseFnRefs(fn[1])) {
            if (ref.types && verb === "REVOKE" && opensToAnon) {
              const k = qkey(ref.schema, ref.name);
              if (!fnRevokes.has(k)) fnRevokes.set(k, []);
              fnRevokes.get(k)!.push({ sig: signature(ref.schema, ref.name, ref.types), file: loc.file, line: loc.line });
            }
            for (const f of fnMatches(ref)) {
              applyTo(f.privs, verb, roles, privs);
              if (opensToAnon && privs.includes("EXECUTE")) f.explicitlyOpen = verb === "GRANT";
            }
          }
          continue;
        }

        if (/^(PROCEDURE|SCHEMA|DATABASE|TYPE|DOMAIN|LANGUAGE|LARGE\s+OBJECT|FOREIGN\s+(DATA|SERVER)|TABLESPACE|PARAMETER)\b/i.test(target)) continue;

        const privs = parsePrivs(g.privs, "tables");
        for (const item of splitTopLevel(target.replace(/^TABLE\s+/i, ""))) {
          const { schema, name } = splitQName(item);
          const rec = rels.get(qkey(schema, name));
          if (!rec) continue;
          applyTo(rec.privs, verb, roles, privs);
          rec.events.push({ ...loc, kind: verb, roles, privs, revokeAll: privs.length === TABLE_PRIVS.length });
        }
      }
    }
  }
  return st;
}

/** The REVOKE ALL that wipes privileges granted earlier in the same migration (and not granted again). */
function wipingRevoke(events: PrivEvent[]): PrivEvent | undefined {
  const byFile = new Map<string, PrivEvent[]>();
  for (const e of events) {
    if (!byFile.has(e.file)) byFile.set(e.file, []);
    byFile.get(e.file)!.push(e);
  }
  for (const list of byFile.values()) {
    for (const role of ["anon", "authenticated", "service_role", "public"]) {
      const mine = list.filter((e) => e.roles.includes(role));
      const lastWipe = mine.map((e) => e.kind === "REVOKE" && e.revokeAll).lastIndexOf(true);
      if (lastWipe <= 0) continue;
      const before = new Set(mine.slice(0, lastWipe).filter((e) => e.kind === "GRANT").flatMap((e) => e.privs));
      const after = new Set(mine.slice(lastWipe + 1).filter((e) => e.kind === "GRANT").flatMap((e) => e.privs));
      if ([...before].some((p) => !after.has(p))) return mine[lastWipe];
    }
  }
  return undefined;
}

// ───────── analyse ─────────

export function analyze(files: MigrationFile[], options: AnalyzeOptions = {}): AnalyzeResult {
  const severities = resolveSeverities(options.preset, options.rules);
  const mode = options.defaults || "both";
  if (!["both", "auto-expose", "no-auto-expose"].includes(mode)) {
    throw new Error(`defaults must be "both", "auto-expose" or "no-auto-expose" (got "${mode}")`);
  }
  const exposed = new Set(options.schemas || ["public"]);
  const migrationRole = normIdent(options.migrationRole || "postgres");
  const clientTables = new Set([...(options.clientTables || [])].map((t) => (t.includes(".") ? t : `public.${t}`)));

  const open = replay(files, { world: mode === "no-auto-expose" ? "no-auto-expose" : "auto-expose", migrationRole });
  const closed = mode === "both" ? replay(files, { world: "no-auto-expose", migrationRole }) : open;

  const violations: Violation[] = [];
  const emit = (rule: RuleId, owner: Loc, schema: string, object: string, at?: Loc, note?: string) => {
    const severity = severities[rule];
    if (severity === "off") return;
    const ignored = (l?: Loc) => !!l && (l.ignore === "all" || (!!l.ignore && l.ignore.has(rule)));
    if (ignored(owner) || ignored(at)) return;
    const where = at || owner;
    const shown = display(schema, object);
    violations.push({
      rule,
      severity,
      file: where.file,
      line: where.line,
      object: shown,
      message: RULES[rule].summary,
      fix: RULES[rule].fix.replace(/\{name\}/g, shown),
      note,
      key: `${schema}.${object}::${rule}`,
    });
  };

  let tables = 0;
  let views = 0;
  // Objects in every schema are tracked (they can be moved with SET SCHEMA); only exposed ones are checked.
  for (const rec of open.rels.values()) {
    if (!exposed.has(rec.schema)) continue;
    const k = qkey(rec.schema, rec.name);
    const shut = closed.rels.get(k) || rec;

    if (rec.kind !== "table") {
      views++;
      const readable = CLIENT_ROLES.some((r) => effective(rec.privs, r).has("SELECT"));
      if (readable && (rec.kind === "matview" || !rec.securityInvoker)) {
        emit(
          "view-bypasses-rls",
          rec,
          rec.schema,
          rec.name,
          undefined,
          rec.kind === "matview"
            ? "Materialized views cannot use security_invoker: REVOKE SELECT from anon/authenticated, or expose the data through an RLS-protected table instead."
            : undefined
        );
      }
      if (clientTables.has(k) && !CLIENT_ROLES.some((r) => hasAny(effective(shut.privs, r), CRUD))) {
        emit("client-table-no-grant", rec, rec.schema, rec.name);
      }
      continue;
    }
    tables++;

    if (!rec.rls) emit("rls-disabled", rec, rec.schema, rec.name);

    const wipe = wipingRevoke(rec.events);
    if (wipe) emit("grant-order", rec, rec.schema, rec.name, wipe);

    if (clientTables.has(k) && !CLIENT_ROLES.some((r) => hasAny(effective(shut.privs, r), CRUD))) {
      emit("client-table-no-grant", rec, rec.schema, rec.name);
    }

    if (!hasAny(effective(shut.privs, "service_role"), CRUD)) emit("missing-service-role-grant", rec, rec.schema, rec.name);

    for (const seqName of shut.sequences) {
      const seq = closed.sequences.get(qkey(shut.schema, seqName));
      if (!seq) continue;
      const role = CLIENT_ROLES.find(
        (r) => effective(shut.privs, r).has("INSERT") && !hasAny(effective(seq, r), ["USAGE", "UPDATE"])
      );
      if (role) emit("serial-sequence-grant", rec, rec.schema, seqName, undefined, `${role} can INSERT into ${display(rec.schema, rec.name)}`);
    }

    if (!rec.events.some((e) => e.kind === "REVOKE" && e.roles.some((r) => CLIENT_ROLES.includes(r)))) {
      emit("missing-explicit-revoke", rec, rec.schema, rec.name);
    }
    if (hasAny(effective(rec.privs, "anon"), CRUD)) emit("anon-table-access", rec, rec.schema, rec.name);
  }

  let functionCount = 0;
  for (const f of open.functions.values()) {
    if (!exposed.has(f.schema)) continue;
    functionCount++;
    if (!f.definer || f.trigger || f.explicitlyOpen) continue;
    const holders = ["public", "anon"].filter((r) => f.privs.get(r)?.has("EXECUTE"));
    if (!holders.length) continue;
    const others = (open.fnRevokes.get(qkey(f.schema, f.name)) || []).filter((r) => r.sig !== f.sig);
    const note = others.length
      ? `A REVOKE was written for ${others[0].sig} (${others[0].file}:${others[0].line}), a different overload, so it does not cover ${f.sig}.`
      : `Still executable by: ${holders.map((r) => (r === "public" ? "PUBLIC" : r)).join(", ")}.`;
    emit("definer-public-execute", f, f.schema, f.sig.slice(f.schema === "public" ? 0 : f.schema.length + 1), undefined, note);
  }

  violations.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.rule.localeCompare(b.rule));
  return { violations, stats: { files: files.length, tables, views, functions: functionCount } };
}
