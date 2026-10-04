import { analyze } from "../src/analyze";
import type { MigrationFile, Violation } from "../src/analyze";
import { EXAMPLES } from "./examples";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const sqlEl = $<HTMLTextAreaElement>("sql");
const presetEl = $<HTMLSelectElement>("preset");
const defaultsEl = $<HTMLSelectElement>("defaults");
const clientEl = $<HTMLInputElement>("client");
const resultsEl = $("results");
const summaryEl = $("summary");
const tabsEl = $("tabs");
const blurbEl = $("blurb");

/** Split the editor contents into files on `-- file: name.sql` lines. */
function toFiles(text: string): MigrationFile[] {
  const files: MigrationFile[] = [];
  let name = "migration.sql";
  let buf: string[] = [];
  const push = () => {
    if (buf.join("").trim()) files.push({ name, sql: buf.join("\n") });
  };
  for (const line of text.split("\n")) {
    const m = /^\s*--\s*file:\s*(\S+)/i.exec(line);
    if (m) {
      push();
      name = m[1];
      buf = []; // line 1 of the file is the line after the marker
      continue;
    }
    buf.push(line);
  }
  push();
  return files;
}

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

function card(v: Violation): string {
  return `<article class="card ${v.severity}">
    <div class="card-head">
      <span class="sev">${v.severity === "error" ? "error" : "warning"}</span>
      <strong class="obj">${esc(v.object)}</strong>
      <code class="rule">${v.rule}</code>
    </div>
    <div class="loc">${esc(v.file)}:${v.line}</div>
    <p>${esc(v.message)}</p>
    ${v.note ? `<p class="note">${esc(v.note)}</p>` : ""}
    <pre class="fix"><code>${esc(v.fix)}</code></pre>
  </article>`;
}

function run() {
  let violations: Violation[] = [];
  let stats = { files: 0, tables: 0, views: 0, functions: 0 };
  try {
    const res = analyze(toFiles(sqlEl.value), {
      preset: presetEl.value as "recommended" | "strict",
      defaults: defaultsEl.value as "both" | "auto-expose" | "no-auto-expose",
      clientTables: clientEl.value
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    });
    violations = res.violations;
    stats = res.stats;
  } catch (e) {
    resultsEl.innerHTML = `<div class="empty">Could not analyse: ${esc((e as Error).message)}</div>`;
    return;
  }
  const errors = violations.filter((v) => v.severity === "error").length;
  const warns = violations.length - errors;
  const n = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;
  summaryEl.textContent = [n(stats.files, "file"), n(stats.tables, "table"), n(stats.views, "view"), n(stats.functions, "function")].join(" · ");
  resultsEl.innerHTML = violations.length
    ? `<div class="tally"><span class="n-err">${errors} error${errors === 1 ? "" : "s"}</span>${warns ? `<span class="n-warn">${warns} warning${warns === 1 ? "" : "s"}</span>` : ""}</div>` +
      violations.map(card).join("")
    : `<div class="empty ok"><span class="tick" aria-hidden="true">✓</span>No problems found.</div>`;
}

function select(id: string) {
  const ex = EXAMPLES.find((e) => e.id === id) || EXAMPLES[0];
  for (const b of tabsEl.querySelectorAll("button")) b.setAttribute("aria-selected", String(b.dataset.id === ex.id));
  blurbEl.textContent = ex.blurb;
  sqlEl.value = ex.sql;
  presetEl.value = ex.preset || "recommended";
  defaultsEl.value = "both";
  clientEl.value = ex.clientTables || "";
  try {
    history.replaceState(null, "", `#${ex.id}`);
  } catch {
    /* sandboxed iframes may forbid it; the page still works */
  }
  run();
}

tabsEl.innerHTML = EXAMPLES.map(
  (e) => `<button role="tab" data-id="${e.id}" aria-selected="false">${esc(e.title)}</button>`
).join("");
tabsEl.addEventListener("click", (e) => {
  const b = (e.target as HTMLElement).closest("button");
  if (b?.dataset.id) select(b.dataset.id);
});

let timer = 0;
const schedule = () => {
  clearTimeout(timer);
  timer = window.setTimeout(run, 120);
};
sqlEl.addEventListener("input", schedule);
clientEl.addEventListener("input", schedule);
presetEl.addEventListener("change", run);
defaultsEl.addEventListener("change", run);
sqlEl.addEventListener("keydown", (e) => {
  if (e.key === "Tab" && !e.shiftKey) {
    e.preventDefault();
    sqlEl.setRangeText("  ", sqlEl.selectionStart, sqlEl.selectionEnd, "end");
    schedule();
  }
});

window.addEventListener("hashchange", () => select(location.hash.slice(1)));
select(location.hash.slice(1));
