import { defineConfig } from "vite";

export default defineConfig({
  // @solana/zk-sdk loads its WebAssembly from a file next to its own module. Vite's dev server
  // pre-bundles dependencies into another folder, where that file is not, so leave this one alone.
  // (`vite build` handles it either way.)
  optimizeDeps: { exclude: ["@solana/zk-sdk"] },
  resolve: {
    // This example uses the SDK from this repository (file:../..), which has its own node_modules.
    // Make the app and the SDK share one copy of these. Not needed with the SDK from npm.
    dedupe: [
      "@solana/kit",
      "@solana/zk-sdk",
      "@solana-program/token-2022",
      "@solana-program/zk-elgamal-proof",
    ],
  },
  // The dev server only serves files inside this folder. The linked SDK's dependencies (and the
  // .wasm file) live in the repository's node_modules, two levels up. Not needed with the SDK from npm.
  server: { fs: { allow: ["../.."] } },
  build: { target: "es2022" },
});
