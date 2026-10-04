import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { collectClientTables, readExposedSchemas } from "../src/node";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
function project(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "sgl-node-"));
  dirs.push(dir);
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(join(dir, path), body);
  }
  return dir;
}

describe("collectClientTables", () => {
  const imp = `import { supabase } from "@/lib/supabaseClient";\n`;

  it("collects .from() tables in browser files only", () => {
    const dir = project({
      "components/Feed.tsx": imp + `supabase.from("posts").select(); supabase.from<Row>('likes'); supabase.storage.from("avatars");`,
      "components/Other.tsx": `db.from("not_browser")`,
      "pages/api/admin.ts": imp + `supabase.from("secrets")`,
      "lib/util.ts": imp + `Array.from("abc"); Buffer.from("xyz"); Uint8Array.from("q");`,
    });
    expect([...collectClientTables(dir, { marker: "supabaseClient" })].sort()).toEqual(["likes", "posts"]);
  });

  it("normalises exclude prefixes and include paths", () => {
    const dir = project({ "pages/api/admin.ts": imp + `supabase.from("secrets")`, "pages/index.tsx": imp + `supabase.from("posts")` });
    for (const exclude of ["pages/api", "pages/api/", "./pages/api", "./pages/api/"]) {
      expect([...collectClientTables(dir, { marker: "supabaseClient", exclude: [exclude], include: ["./pages/"] })].sort(), exclude).toEqual(["posts"]);
    }
  });

  it("survives broken symlinks", () => {
    const dir = project({ "src/a.ts": imp + `supabase.from("posts")` });
    symlinkSync(join(dir, "nowhere"), join(dir, "src", "dangling.ts"));
    expect([...collectClientTables(dir, { marker: "supabaseClient" })]).toEqual(["posts"]);
  });
});

describe("readExposedSchemas", () => {
  it("reads [api] schemas, ignoring comments and other sections", () => {
    const dir = project({
      "supabase/config.toml": `[db]\nschemas = ["wrong"]\n\n[api]\nenabled = true\n# schemas = ["nope"]\nschemas = [\n  "public", # was "api" before\n  "with#hash",\n  'content',\n]\nextra_search_path = ["public", "extensions"]\n`,
    });
    expect(readExposedSchemas(dir)).toEqual(["public", "with#hash", "content"]);
  });

  it("returns null without config.toml or without the key", () => {
    expect(readExposedSchemas(project({}))).toBeNull();
    expect(readExposedSchemas(project({ "supabase/config.toml": "[api]\nenabled = true\n" }))).toBeNull();
  });
});
