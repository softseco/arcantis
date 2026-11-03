// Checks that src/vigilantis-idl.json, the copy of the Vigilantis IDL the playground encodes its
// instructions from, matches a Vigilantis IDL: same program address, version, instructions
// (discriminators, accounts, arguments) and errors. Doc comments are left out of the copy.
//
//   npm run check -- ../../vigilantis/sdk/src/idl/vigilantis.json           compare
//   npm run check -- ../../vigilantis/sdk/src/idl/vigilantis.json --write   update the copy
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const write = process.argv.includes("--write");
const source = process.argv.slice(2).find((a) => a !== "--write") ?? process.env.VIGILANTIS_IDL;
if (!source) {
  console.error("usage: npm run check -- <path to vigilantis.json from the vigilantis repository>");
  process.exit(2);
}
const strip = (o) =>
  Array.isArray(o) ? o.map(strip) : o && typeof o === "object" ? Object.fromEntries(Object.entries(o).filter(([k]) => k !== "docs").map(([k, v]) => [k, strip(v)])) : o;
const pick = (o, keys) => Object.fromEntries(keys.filter((k) => k in o).map((k) => [k, o[k]]));

const full = JSON.parse(readFileSync(source, "utf8"));
const expected = {
  address: full.address,
  metadata: pick(full.metadata, ["name", "version"]),
  instructions: full.instructions.map((i) => ({
    name: i.name,
    discriminator: i.discriminator,
    accounts: i.accounts.map((a) => pick(a, ["name", "writable", "signer", "optional", "address"])),
    args: strip(i.args),
  })),
  errors: full.errors.map((e) => ({ code: e.code, name: e.name, msg: e.msg ?? "" })),
};
const target = path.join(here, "src/vigilantis-idl.json");
if (write) {
  writeFileSync(target, JSON.stringify(expected));
  console.log(`src/vigilantis-idl.json written from ${source}`);
  process.exit(0);
}
const copy = JSON.parse(readFileSync(target, "utf8"));
if (JSON.stringify(copy) !== JSON.stringify(expected)) {
  console.error(`src/vigilantis-idl.json does not match ${source}. Update it with --write, then rebuild.`);
  process.exit(1);
}
console.log(`src/vigilantis-idl.json matches ${source}: Vigilantis ${copy.metadata.version}, ${copy.instructions.length} instructions, ${copy.errors.length} errors`);
