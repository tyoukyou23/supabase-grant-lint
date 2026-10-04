import type { Violation } from "./analyze";

const useColor = () => !!process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: number) => (s: string) => (useColor() ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = paint(31);
const yellow = paint(33);
const dim = paint(2);
const bold = paint(1);

export function formatText(violations: Violation[], migrationsDir: string): string {
  const lines: string[] = [];
  for (const v of violations) {
    const tag = v.severity === "error" ? red("error") : yellow("warn ");
    lines.push(`${tag}  ${bold(v.object)}  ${dim(v.rule)}`);
    lines.push(`       ${migrationsDir}/${v.file}:${v.line}`);
    lines.push(`       ${v.message}`);
    if (v.note) lines.push(`       ${v.note}`);
    lines.push(`       ${dim("fix:")} ${v.fix}`);
    lines.push("");
  }
  return lines.join("\n");
}

/** GitHub Actions workflow commands — shows up as annotations on the PR diff. */
export function formatGithub(violations: Violation[], migrationsDir: string): string {
  const esc = (s: string) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
  return violations
    .map((v) => {
      const body = [v.message, v.note, `fix: ${v.fix}`].filter(Boolean).join("\n");
      const level = v.severity === "error" ? "error" : "warning";
      return `::${level} file=${migrationsDir}/${v.file},line=${v.line},title=${esc(`${v.rule}: ${v.object}`)}::${esc(body)}`;
    })
    .join("\n");
}
