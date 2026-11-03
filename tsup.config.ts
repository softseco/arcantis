// SPDX-License-Identifier: BUSL-1.1
//
// Build config. Two builds of src/index.ts, dependencies left external:
//
// - Node: dual ESM (.mjs) + CJS (.js) in dist/. Uses @solana/zk-sdk's Node build, which reads its
//   WebAssembly from disk.
// - Browser: ESM in dist/browser/. The same source, with src/internal/zk.ts swapped for
//   zk.web.ts, which uses @solana/zk-sdk's web build and fetches the WebAssembly on first use.
//   package.json points the "browser" export condition here, so bundlers (Vite, webpack, esbuild,
//   Next.js) pick it up with no alias.
//
// Type declarations are emitted separately via `tsc --emitDeclarationOnly` (more reliable than
// tsup's bundled dts for the dependency types this SDK re-exports); both builds share them.
import path from "node:path";
import { defineConfig, type Options } from "tsup";

const zkWebBuild: NonNullable<Options["esbuildPlugins"]>[number] = {
  name: "zk-web-build",
  setup(build) {
    // "./internal/zk" (from src/) and "./zk" (from src/internal/) -> src/internal/zk.web.ts
    build.onResolve({ filter: /^\.\.?\/(internal\/)?zk$/ }, (args) => {
      const target = path.resolve(args.resolveDir, args.path) + ".web.ts";
      if (target !== path.resolve("src/internal/zk.web.ts")) return undefined;
      return { path: target };
    });
  },
};

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    sourcemap: true,
  },
  {
    // The `arcantis` command (package.json "bin"), for Node.
    entry: { cli: "src/cli.ts" },
    format: ["cjs"],
    platform: "node",
    banner: { js: "#!/usr/bin/env node" },
  },
  {
    entry: { index: "src/index.ts" },
    outDir: "dist/browser",
    format: ["esm"],
    platform: "browser",
    target: "es2022",
    sourcemap: true,
    esbuildPlugins: [zkWebBuild],
    outExtension: () => ({ js: ".mjs" }),
  },
]);
