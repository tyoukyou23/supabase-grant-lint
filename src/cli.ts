import { existsSync } from "node:fs";
import { relative } from "node:path";
import { lintProject, writeBaseline, DEFAULT_BASELINE } from "./node";
import { formatGithub, formatText } from "./format";
import { RULES, RULE_IDS } from "./rules";
import type { Preset } from "./rules";

declare const __VERSION__: string;

const HELP = `supabase-grant-lint — catch missing RLS, GRANT and REVOKE in Supabase migrations

Usage: supabase-grant-lint [options]

Options:
  --dir <path>          Migrations directory (default: supabase/migrations)
  --config <path>       Config file (default: supabase-grant-lint.config.json, or "supabaseGrantLint" in package.json)
  --preset <name>       recommended | strict (default: recommended)
  --format <name>       text | json | github (default: text)
  --no-baseline         Ignore the baseline file
  --write-baseline      Record all current violations as the baseline (adopting on an existing project)
  --force               With --write-baseline: allow adding entries to an existing baseline
  --prune-baseline      Remove baseline entries that are fixed (the baseline only ever shrinks)
  --fail-on-stale       Exit 1 if the baseline has entries that are already fixed
  --list-rules          Show the rules and their severity per preset
  -h, --help            Show this help
  -v, --version         Show the version

Exit codes: 0 no new errors · 1 new errors (or stale baseline entries with --fail-on-stale) · 2 usage or config error
`;

const VALUE_FLAGS = ["dir", "config", "preset", "format"];
const BOOL_FLAGS = ["no-baseline", "write-baseline", "force", "prune-baseline", "fail-on-stale", "list-rules", "help", "version"];

function parseArgs(argv: string[]) {
  const args: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h") args.help = true;
    else if (a === "-v") args.version = true;
    else if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const k = eq === -1 ? a.slice(2) : a.slice(2, eq);
      if (VALUE_FLAGS.includes(k)) {
        const val = eq === -1 ? argv[++i] : a.slice(eq + 1);
        if (val === undefined || val === "" || val.startsWith("--")) throw new Error(`--${k} needs a value`);
        args[k] = val;
      } else if (BOOL_FLAGS.includes(k) && eq === -1) {
        args[k] = true;
      } else throw new Error(`Unknown option: ${a}`);
    } else throw new Error(`Unknown argument: ${a}`);
  }
  return args;
}

const plural = (n: number, one: string, many = one + "s") => `${n} ${n === 1 ? one : many}`;

function main(): number {
  let args: Record<string, string | boolean>;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error((e as Error).message + "\n\n" + HELP);
    return 2;
  }
  if (args.help) {
    console.log(HELP);
    return 0;
  }
  if (args.version) {
    console.log(__VERSION__);
    return 0;
  }
  if (args["list-rules"]) {
    for (const id of RULE_IDS) {
      const r = RULES[id];
      console.log(`${id}\n  recommended: ${r.recommended}   strict: ${r.strict}\n  ${r.summary}\n`);
    }
    return 0;
  }

  const format = (args.format as string) || "text";
  if (!["text", "json", "github"].includes(format)) {
    console.error(`Unknown format "${format}". Use text, json or github.`);
    return 2;
  }

  const cwd = process.cwd();
  let result;
  try {
    result = lintProject({
      cwd,
      configPath: args.config as string | undefined,
      overrides: {
        ...(args.dir ? { migrations: args.dir as string } : {}),
        ...(args.preset ? { preset: args.preset as Preset } : {}),
        ...(args["no-baseline"] ? { baseline: false as const } : {}),
      },
    });
  } catch (e) {
    console.error(`supabase-grant-lint: ${(e as Error).message}`);
    return 2;
  }

  const migrationsDir = relative(cwd, result.migrationsDir) || ".";
  const baselinePath = result.baselinePath || `${cwd}/${DEFAULT_BASELINE}`;
  const baselineRel = relative(cwd, baselinePath);

  if (args["write-baseline"]) {
    const all = [...result.violations, ...result.baselined].map((v) => v.key);
    if (existsSync(baselinePath) && result.violations.length && !args.force) {
      console.error(
        `${baselineRel} already exists and ${plural(result.violations.length, "new violation")} would be added.\n` +
          `The baseline is meant to shrink. Fix them, or re-run with --force to add them anyway.`
      );
      return 1;
    }
    writeBaseline(baselinePath, all);
    console.log(`Wrote ${plural(all.length, "entry", "entries")} to ${baselineRel}. From now on only new violations fail.`);
    return 0;
  }
  if (args["prune-baseline"]) {
    if (!result.baselinePath) {
      console.error("No baseline configured.");
      return 2;
    }
    const keep = result.baselined.map((v) => v.key);
    writeBaseline(result.baselinePath, keep);
    console.log(`Removed ${plural(result.stale.length, "fixed entry", "fixed entries")} from ${baselineRel} (${keep.length} left).`);
    return 0;
  }

  const errors = result.violations.filter((v) => v.severity === "error");
  const warns = result.violations.filter((v) => v.severity === "warn");

  if (format === "json") {
    console.log(JSON.stringify(result, null, 2));
  } else if (format === "github") {
    const out = formatGithub(result.violations, migrationsDir);
    if (out) console.log(out);
  } else {
    if (result.violations.length) console.log(formatText(result.violations, migrationsDir));
    if (result.stale.length) {
      console.log(`${plural(result.stale.length, "baseline entry is", "baseline entries are")} fixed — run with --prune-baseline to remove:`);
      for (const k of result.stale) console.log(`  ${k}`);
      console.log("");
    }
    const { files, tables, views, functions } = result.stats;
    const scope = [plural(files, "migration"), plural(tables, "table"), plural(views, "view"), plural(functions, "function")].join(", ");
    const tail = result.baselined.length ? `, ${result.baselined.length} known in baseline` : "";
    const notes = [
      `schemas: ${result.schemas.join(", ")}`,
      result.clientScan ? null : 'client-table-no-grant is off (no "client" in config)',
    ].filter(Boolean);
    const head = errors.length || warns.length ? `${plural(errors.length, "error")}, ${plural(warns.length, "warning")} in` : "✔ No new problems in";
    console.log(`${head} ${scope}${tail}.\n  ${notes.join(" · ")}`);
  }

  if (errors.length) return 1;
  if (args["fail-on-stale"] && result.stale.length) return 1;
  return 0;
}

process.exitCode = main();
