/**
 * Node entry point: reads migrations and source files from disk, applies the
 * config file and the baseline, and returns what the CLI prints.
 */
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, normalize, relative, resolve, sep } from "node:path";
import { analyze } from "./analyze";
import type { AnalyzeOptions, Violation } from "./analyze";
import { PRESETS, RULE_IDS, SEVERITIES } from "./rules";
import type { Preset, Severity } from "./rules";

export interface ClientConfig {
  /**
   * Regular expression a file must match to count as browser code — usually the
   * import of your browser client, e.g. `"lib/supabaseClient"` or `"createBrowserClient"`.
   */
  marker: string;
  /** Directories to scan. Default: src, app, pages, components, hooks, lib. */
  include?: string[];
  /** Path prefixes to skip (server-only code). Default: pages/api, app/api, supabase. */
  exclude?: string[];
}

export interface Config {
  /** Migrations directory. Default `supabase/migrations`. */
  migrations?: string;
  preset?: Preset;
  rules?: Partial<Record<string, Severity>>;
  /** Exposed schemas. Default: `[api] schemas` from supabase/config.toml, else `["public"]`. */
  schemas?: string[];
  defaults?: AnalyzeOptions["defaults"];
  migrationRole?: string;
  /** Baseline file. Default `supabase-grant-lint.baseline.json`; `false` disables it. */
  baseline?: string | false;
  /** Enables `client-table-no-grant` by finding `.from("table")` in browser code. */
  client?: ClientConfig;
}

export const CONFIG_FILE = "supabase-grant-lint.config.json";
export const DEFAULT_BASELINE = "supabase-grant-lint.baseline.json";

const KEYS: (keyof Config)[] = ["migrations", "preset", "rules", "schemas", "defaults", "migrationRole", "baseline", "client"];

/** Throws a readable error for anything that would otherwise silently weaken the lint. */
export function validateConfig(c: unknown, where: string): Config {
  const fail = (msg: string): never => {
    throw new Error(`${where}: ${msg}`);
  };
  if (typeof c !== "object" || c === null || Array.isArray(c)) fail("must be a JSON object");
  const cfg = c as Record<string, unknown>;
  for (const k of Object.keys(cfg)) if (!KEYS.includes(k as keyof Config)) fail(`unknown option "${k}". Known: ${KEYS.join(", ")}`);
  const str = (k: string) => cfg[k] === undefined || typeof cfg[k] === "string" || fail(`"${k}" must be a string`);
  str("migrations");
  str("migrationRole");
  if (cfg.preset !== undefined && !PRESETS.includes(cfg.preset as Preset)) fail(`"preset" must be ${PRESETS.join(" or ")}`);
  if (cfg.defaults !== undefined && !["both", "auto-expose", "no-auto-expose"].includes(cfg.defaults as string)) {
    fail(`"defaults" must be "both", "auto-expose" or "no-auto-expose"`);
  }
  if (cfg.schemas !== undefined && (!Array.isArray(cfg.schemas) || !cfg.schemas.every((s) => typeof s === "string") || !cfg.schemas.length)) {
    fail(`"schemas" must be a non-empty array of strings`);
  }
  if (cfg.baseline !== undefined && cfg.baseline !== false && typeof cfg.baseline !== "string") fail(`"baseline" must be a path or false`);
  if (cfg.rules !== undefined) {
    if (typeof cfg.rules !== "object" || cfg.rules === null || Array.isArray(cfg.rules)) fail(`"rules" must be an object`);
    for (const [id, sev] of Object.entries(cfg.rules as object)) {
      if (!RULE_IDS.includes(id as never)) fail(`unknown rule "${id}". Known: ${RULE_IDS.join(", ")}`);
      if (!SEVERITIES.includes(sev)) fail(`rule "${id}" must be ${SEVERITIES.join(", ")}`);
    }
  }
  if (cfg.client !== undefined) {
    const cl = cfg.client as Record<string, unknown>;
    if (typeof cl !== "object" || cl === null) fail(`"client" must be an object`);
    if (typeof cl.marker !== "string" || !cl.marker) fail(`"client.marker" is required (a regular expression matching your browser client import)`);
    try {
      new RegExp(cl.marker as string);
    } catch (e) {
      fail(`"client.marker" is not a valid regular expression: ${(e as Error).message}`);
    }
    for (const k of ["include", "exclude"]) {
      const v = cl[k];
      if (v !== undefined && (!Array.isArray(v) || !v.every((x) => typeof x === "string"))) fail(`"client.${k}" must be an array of paths`);
    }
  }
  return cfg as Config;
}

function readJson(path: string, cwd: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`Could not parse ${relative(cwd, path)}: ${(e as Error).message}`);
  }
}

export function loadConfig(cwd: string, explicit?: string): { config: Config; path: string | null } {
  const path = explicit ? resolve(cwd, explicit) : join(cwd, CONFIG_FILE);
  if (existsSync(path)) return { config: validateConfig(readJson(path, cwd), relative(cwd, path)), path };
  if (explicit) throw new Error(`Config file not found: ${explicit}`);
  const pkg = join(cwd, "package.json");
  if (existsSync(pkg)) {
    const json = readJson(pkg, cwd) as Record<string, unknown>;
    if (json.supabaseGrantLint !== undefined) return { config: validateConfig(json.supabaseGrantLint, "package.json supabaseGrantLint"), path: pkg };
  }
  return { config: {}, path: null };
}

/** Drop a `# comment`, leaving `#` inside "strings" and 'strings' alone. */
function stripTomlComment(line: string): string {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === "\\" && quote === '"') i++;
      else if (c === quote) quote = "";
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#") return line.slice(0, i);
  }
  return line;
}

/** `[api] schemas = [...]` from supabase/config.toml — the schemas the Data API actually exposes. */
export function readExposedSchemas(cwd: string): string[] | null {
  const path = join(cwd, "supabase", "config.toml");
  if (!existsSync(path)) return null;
  const toml = readFileSync(path, "utf8").split("\n").map(stripTomlComment).join("\n");
  const api = /^\s*\[api\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(toml);
  if (!api) return null;
  const m = /^\s*schemas\s*=\s*\[([\s\S]*?)\]/m.exec(api[1]);
  if (!m) return null;
  const list = [...m[1].matchAll(/"([^"]+)"|'([^']+)'/g)].map((x) => x[1] || x[2]);
  return list.length ? list : null;
}

const CODE_FILE = /\.(c|m)?(j|t)sx?$/;
const SKIP_DIRS = new Set(["node_modules", ".next", ".git", "dist", "build", ".vercel", ".turbo", ".output", ".svelte-kit"]);
const cleanPrefix = (p: string) => normalize(p).replace(/[\\/]+$/, "");

/** Table names passed to `.from("...")` in files that look like browser code. */
export function collectClientTables(cwd: string, client: ClientConfig): Set<string> {
  const include = client.include || ["src", "app", "pages", "components", "hooks", "lib"];
  const exclude = (client.exclude || ["pages/api", "app/api", "supabase"]).map(cleanPrefix);
  const marker = new RegExp(client.marker);
  const tables = new Set<string>();

  const walk = (dir: string) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(dir, e);
      const rel = relative(cwd, p);
      if (exclude.some((x) => rel === x || rel.startsWith(x + sep))) continue;
      let isDir: boolean;
      try {
        isDir = statSync(p).isDirectory();
      } catch {
        continue; // broken symlink
      }
      if (isDir) {
        if (!SKIP_DIRS.has(e)) walk(p);
        continue;
      }
      if (!CODE_FILE.test(e)) continue;
      let src = readFileSync(p, "utf8");
      if (!marker.test(src)) continue;
      // Storage buckets are not tables: supabase.storage.from("avatars")
      src = src.replace(/\.storage\s*\.from\s*\(/g, ".storage.__bucket__(");
      // Array.from("…") / Buffer.from("…") are not queries either
      for (const m of src.matchAll(/(?<![A-Z][A-Za-z0-9_$]*)\.from\s*(?:<[^>()]*>)?\(\s*["'`]([A-Za-z_][A-Za-z0-9_]*)["'`]/g)) tables.add(m[1]);
    }
  };
  for (const dir of include) walk(join(cwd, cleanPrefix(dir)));
  return tables;
}

export function readMigrations(dir: string) {
  if (!existsSync(dir)) throw new Error(`Migrations directory not found: ${dir}`);
  const files = readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((name) => ({ name, sql: readFileSync(join(dir, name), "utf8") }));
  if (!files.length) throw new Error(`No .sql files in ${dir}`);
  return files;
}

// ───────── baseline ─────────

export interface Baseline {
  version: 1;
  entries: string[];
}

export function readBaseline(path: string, cwd = process.cwd()): Set<string> {
  if (!existsSync(path)) return new Set();
  const json = readJson(path, cwd) as Baseline | string[];
  const entries = Array.isArray(json) ? json : json && Array.isArray(json.entries) ? json.entries : null;
  if (!entries) throw new Error(`${relative(cwd, path)}: expected { "version": 1, "entries": [...] }`);
  return new Set(entries);
}

export function writeBaseline(path: string, keys: Iterable<string>) {
  const body: Baseline = { version: 1, entries: [...new Set(keys)].sort() };
  writeFileSync(path, JSON.stringify(body, null, 2) + "\n");
}

// ───────── run ─────────

export interface LintOptions {
  cwd?: string;
  configPath?: string;
  /** Overrides on top of the config file. */
  overrides?: Partial<Config>;
}

export interface LintResult {
  /** Violations not covered by the baseline. */
  violations: Violation[];
  /** Violations covered by the baseline (still present). */
  baselined: Violation[];
  /** Baseline entries that no longer occur — fixed, can be removed. */
  stale: string[];
  baselinePath: string | null;
  migrationsDir: string;
  schemas: string[];
  clientScan: boolean;
  stats: { files: number; tables: number; views: number; functions: number };
}

export function lintProject(opts: LintOptions = {}): LintResult {
  const cwd = resolve(opts.cwd || process.cwd());
  const { config: fileConfig } = loadConfig(cwd, opts.configPath);
  const config: Config = { ...fileConfig, ...opts.overrides };

  const migrationsDir = resolve(cwd, config.migrations || "supabase/migrations");
  const files = readMigrations(migrationsDir);
  const schemas = config.schemas || readExposedSchemas(cwd) || ["public"];
  const clientTables = config.client ? collectClientTables(cwd, config.client) : undefined;
  const result = analyze(files, {
    preset: config.preset,
    rules: config.rules,
    schemas,
    defaults: config.defaults,
    migrationRole: config.migrationRole,
    clientTables,
  });

  const baselinePath = config.baseline === false ? null : resolve(cwd, config.baseline || DEFAULT_BASELINE);
  const known = baselinePath ? readBaseline(baselinePath, cwd) : new Set<string>();
  const seen = new Set<string>();
  const violations: Violation[] = [];
  const baselined: Violation[] = [];
  for (const v of result.violations) {
    seen.add(v.key);
    (known.has(v.key) ? baselined : violations).push(v);
  }
  return {
    violations,
    baselined,
    stale: [...known].filter((k) => !seen.has(k)).sort(),
    baselinePath,
    migrationsDir,
    schemas,
    clientScan: !!clientTables,
    stats: result.stats,
  };
}
