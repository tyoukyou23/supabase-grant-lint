import { defineConfig } from "tsup";
import pkg from "./package.json";

export default defineConfig([
  {
    entry: ["src/index.ts", "src/node.ts"],
    format: ["esm", "cjs"],
    dts: true,
    sourcemap: true,
    clean: true,
    target: "node20",
  },
  {
    entry: ["src/cli.ts"],
    format: ["esm"],
    target: "node20",
    banner: { js: "#!/usr/bin/env node" },
    define: { __VERSION__: JSON.stringify(pkg.version) },
  },
]);
