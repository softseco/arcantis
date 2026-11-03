// Builds the playground into ../docs, which GitHub Pages serves as-is.
//
//   npm install && npm run build
//
// The page is softseco.com's: index.html has placeholders for the site's icon symbols, header and footer, which come
// from site/ (copied from the site by import-site.mjs), with the site's styles and script next to it.
//
// esbuild picks the SDK's browser build (the "browser" export condition), which uses
// @solana/zk-sdk's web build. esbuild does not copy the WebAssembly that build loads, so it is
// copied next to the bundle here and app.js passes its URL to initConfidentialTransfers().
import { build } from "esbuild";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(here, "../docs");
await mkdir(path.join(out, "assets"), { recursive: true });

await build({
  entryPoints: [path.join(here, "src/app.js")],
  outfile: path.join(out, "app.js"),
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: true,
  sourcemap: false,
  legalComments: "eof",
  logLevel: "info",
});

let page = await readFile(path.join(here, "index.html"), "utf8");
for (const part of ["defs", "header", "footer"]) {
  const mark = `<!-- site:${part} -->`;
  if (page.split(mark).length !== 2) throw new Error(`index.html needs exactly one ${mark}`);
  const html = (await readFile(path.join(here, "site", `${part}.html`), "utf8")).replace(/^<!--[^]*?-->\n/, "");
  page = page.replace(mark, () => html.trimEnd());
}
await writeFile(path.join(out, "index.html"), page);

await copyFile(path.join(here, "node_modules/@solana/zk-sdk/dist/web/index_bg.wasm"), path.join(out, "zk_sdk_bg.wasm"));
for (const [from, to] of [
  ["site/site.css", "site.css"],
  ["site/site.js", "site.js"],
  ["assets/hero.jpg", "assets/hero.jpg"],
  ["assets/hero-m.jpg", "assets/hero-m.jpg"],
  ["softseco-logo.svg", "softseco-logo.svg"],
  ["softseco-mark.svg", "softseco-mark.svg"],
  ["og.png", "og.png"],
]) {
  await copyFile(path.join(here, from), path.join(out, to));
}
await writeFile(path.join(out, ".nojekyll"), "");

console.log(`built ${path.relative(process.cwd(), out) || "."}`);
