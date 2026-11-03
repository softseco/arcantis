// Copies the parts of softseco.com the playground shares with it into site/: the header with its menus, the footer, the
// icon symbols they use, the shared and page-kit styles, and the site script. Links to the site's pages become links to
// softseco.com, and the Arcantis and Vigilantis entries, which the site still shows as "Soon", point at their
// repositories. The hero picture is the playground's own (assets/), not the site's. Run it again when the site changes,
// then rebuild:
//
//   npm run import-site -- "<path to the site v2 folder>"
//   npm run build
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const site = process.argv[2];
if (!site) {
  console.error('usage: npm run import-site -- "<path to the site v2 folder>"');
  process.exit(2);
}
const read = (p) => readFileSync(path.join(site, p), "utf8");
const page = read("payments.html"); // any content page: they share the header, the footer and the symbols
const css = read("css/style.css");

function between(text, start, end, what) {
  const i = text.indexOf(start);
  const j = text.indexOf(end, i + start.length);
  if (i < 0 || j < 0) throw new Error(`${what}: not found in the site; has its markup changed?`);
  return text.slice(i, j);
}

/** Replace `from` with `to`, and fail unless it was there exactly `count` times. */
function swap(text, from, to, count, what) {
  const n = text.split(from).length - 1;
  if (n !== count) throw new Error(`${what}: expected ${count}, found ${n}; has the site's markup changed?`);
  return text.split(from).join(to);
}

const toSite = (html) =>
  html
    .replace(/href="index\.html"/g, 'href="https://softseco.com/"')
    .replace(/href="([a-z0-9-]+)\.html(#[^"]*)?"/g, (_, name, hash = "") => `href="https://softseco.com/${name}${hash}"`);

const repo = { Arcantis: "https://github.com/softseco/arcantis", Vigilantis: "https://github.com/softseco/vigilantis" };
const ext =
  '<svg class="ft-ext" viewBox="0 0 24 24" aria-hidden="true"><path d="m4.5 19.5 15-15m0 0H8.25m11.25 0v11.25"/></svg>';

const defs = between(page, '<svg width="0" height="0"', "</svg>\n", "the icon symbols") + "</svg>\n";

let header = between(page, '<header class="hdr"', "</header>", "the header") + "</header>";
for (const [name, url] of Object.entries(repo)) {
  const icon = name === "Arcantis" ? "i-braces" : "i-shield-check";
  // the mega menu
  header = swap(
    header,
    `<a class="mm-i is-off" role="link" aria-disabled="true"><svg class="mi" aria-hidden="true"><use href="#${icon}"/></svg><b>${name} <em>Soon</em></b>`,
    `<a class="mm-i" href="${url}"><svg class="mi" aria-hidden="true"><use href="#${icon}"/></svg><b>${name}</b>`,
    1,
    `the ${name} entry of the mega menu`,
  );
  // the phone menu
  header = swap(
    header,
    `<a class="is-off" role="link" aria-disabled="true"><svg class="mi" aria-hidden="true"><use href="#${icon}"/></svg><span>${name} <em>Soon</em></span></a>`,
    `<a href="${url}"><svg class="mi" aria-hidden="true"><use href="#${icon}"/></svg><span>${name}</span></a>`,
    1,
    `the ${name} entry of the phone menu`,
  );
}
header = toSite(header);

let footer = between(page, '<footer class="footer">', "</footer>", "the footer") + "</footer>";
for (const [name, url] of Object.entries(repo)) {
  footer = swap(
    footer,
    `<a class="is-off" role="link" aria-disabled="true"><span data-tw>${name}</span> <em>Soon</em></a>`,
    `<a href="${url}" target="_blank" rel="noopener"><span data-tw>${name}</span>${ext}</a>`,
    1,
    `the ${name} link in the footer`,
  );
}
footer = swap(
  footer,
  'href="https://softseco.github.io/confidential-sdk"',
  'href="https://softseco.github.io/arcantis/"',
  1,
  "the playground link in the footer",
);
footer = toSite(footer);

// The shared styles (colours, type, buttons, header, menus, footer) and the page kit; not the homepage's or the other
// pages' own styles.
const shared = between(css, "/* ===== 1. shared", "/* ===== 2. homepage", "the shared styles");
const kit = between(css, "/* ===== 3. page kit", "/* ===== 4.", "the page kit");
const tail = css.slice(css.indexOf("/* ===== reduced motion"));
if (!tail.startsWith("/* ===== reduced motion")) throw new Error("the reduced-motion section: not found");

const out = path.join(here, "site");
mkdirSync(out, { recursive: true });
const note = "Copied from softseco.com (site v2) by import-site.mjs; do not edit here.";
writeFileSync(path.join(out, "defs.html"), `<!-- ${note} -->\n${defs}`);
writeFileSync(path.join(out, "header.html"), `<!-- ${note} -->\n${header}\n`);
writeFileSync(path.join(out, "footer.html"), `<!-- ${note} -->\n${footer}\n`);
writeFileSync(path.join(out, "site.css"), `/* ${note} */\n${shared}${kit}${tail}`);
writeFileSync(path.join(out, "site.js"), `/* ${note} */\n${read("js/site.js")}`);
console.log("imported the header, footer, symbols, styles and script from", site);
