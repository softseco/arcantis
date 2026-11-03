// SPDX-License-Identifier: BUSL-1.1
//
// Command line for auditors:
//
//   npx @softseco/arcantis audit-report --mint <address> --keypair <auditor wallet.json> \
//       --rpc <url> [--out report.csv] [--format csv|json] [--since 2026-10-01] [--until 2026-11-01]
//
// Writes every deposit, confidential transfer and withdraw of the mint as CSV or as a versioned
// JSON report, with the transferred amounts decrypted with the auditor key derived from the given
// wallet.
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";

import { address, createSolanaRpc } from "@solana/kit";

import { deriveAuditorElgamalKeypair, getAuditorElgamalPubkey } from "./auditor";
import { confidentialActivityToCsv, confidentialActivityToJson, listConfidentialActivity } from "./auditorReport";
import { readMint } from "./internal/accounts";
import { keypairFromFile, parsePositiveInteger, parseUtcTime } from "./internal/cliInput";

const USAGE = `Usage:
  arcantis audit-report --mint <address> --keypair <auditor wallet keypair.json> --rpc <url>
      [--out <file>] [--format csv|json] [--since <date>] [--until <date>] [--max <transactions>]
      [--concurrency <n>] [--skip-auditor-key-check]

  Lists every deposit, confidential transfer and withdraw of the mint, with the amounts of the
  confidential transfers decrypted with the auditor key (to --out, or to standard output).

  --keypair   the auditor's Solana wallet keypair file (the JSON array the Solana CLI writes); the
              auditor's ElGamal key is derived from it, as deriveAuditorElgamalKeypair does
  --rpc       RPC endpoint (or set RPC_URL); it must serve getSignaturesForAddress and getTransaction
  --format    csv (the default, or when --out ends in .csv) or json (when --out ends in .json): a
              report that names its format and version, read back by parseConfidentialActivityJson
  --since, --until   ISO dates or times, e.g. 2026-10-01 or 2026-10-01T12:00:00Z (UTC unless the
              time names another offset)
  --max, --concurrency   whole numbers, 1 or more

  The report file is created readable by its owner only (mode 600); it holds decrypted amounts.
`;

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command !== "audit-report") {
    process.stderr.write(USAGE);
    return command === undefined || command === "--help" || command === "-h" ? 0 : 1;
  }
  const { values } = parseArgs({
    args: rest,
    options: {
      mint: { type: "string" },
      keypair: { type: "string" },
      rpc: { type: "string" },
      out: { type: "string" },
      format: { type: "string" },
      since: { type: "string" },
      until: { type: "string" },
      max: { type: "string" },
      concurrency: { type: "string" },
      "skip-auditor-key-check": { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) {
    process.stderr.write(USAGE);
    return 0;
  }
  const rpcUrl = values.rpc ?? process.env.RPC_URL;
  if (!values.mint || !values.keypair || !rpcUrl) {
    process.stderr.write(`--mint, --keypair and --rpc (or RPC_URL) are required.\n\n${USAGE}`);
    return 1;
  }
  const format = values.format ?? (values.out?.toLowerCase().endsWith(".json") ? "json" : "csv");
  if (format !== "csv" && format !== "json") {
    process.stderr.write(`--format takes csv or json, not ${format}.\n\n${USAGE}`);
    return 1;
  }
  // Every argument is checked before the keypair is read or the RPC asked anything.
  const since = values.since === undefined ? undefined : parseUtcTime(values.since, "since");
  const until = values.until === undefined ? undefined : parseUtcTime(values.until, "until");
  const maxTransactions = values.max === undefined ? undefined : parsePositiveInteger(values.max, "max");
  const concurrency = values.concurrency === undefined ? undefined : parsePositiveInteger(values.concurrency, "concurrency");

  const rpc = createSolanaRpc(rpcUrl);
  const mint = address(values.mint);
  const wallet = await keypairFromFile(readFileSync(values.keypair, "utf8"), values.keypair);
  const auditorKeypair = await deriveAuditorElgamalKeypair(wallet);
  // The origin only: an API key in the query string is never printed.
  process.stderr.write(`RPC:         ${new URL(rpcUrl).origin}\nmint:        ${mint}\nauditor key: ${getAuditorElgamalPubkey(auditorKeypair)}\n`);

  const decimals = (await readMint(rpc, mint, "audit-report")).data.decimals;
  const activity = await listConfidentialActivity({
    rpc,
    mint,
    auditorKeypair,
    since,
    until,
    maxTransactions,
    concurrency,
    skipAuditorKeyCheck: values["skip-auditor-key-check"],
  });
  const output =
    format === "json"
      ? confidentialActivityToJson(activity, { mint, auditorElgamalPubkey: getAuditorElgamalPubkey(auditorKeypair), decimals })
      : confidentialActivityToCsv(activity, { decimals });

  const count = (kind: string) => activity.filter((a) => a.kind === kind).length;
  const unreadable = activity.filter((a) => a.amount === null).length;
  process.stderr.write(
    `found:       ${count("deposit")} deposits, ${count("transfer") + count("transfer-with-fee")} confidential transfers, ${count("withdraw")} withdraws` +
      (unreadable ? ` (${unreadable} amounts could not be decrypted; see the note column)` : "") +
      "\n",
  );
  if (values.out) {
    // Decrypted amounts: a new file is readable by its owner only. (An existing file keeps its mode.)
    writeFileSync(values.out, output, { mode: 0o600 });
    process.stderr.write(`written:     ${values.out}\n`);
  } else {
    process.stdout.write(output);
  }
  return 0;
}

// The exit code is set, not forced with process.exit(): Node then exits once standard output has
// been written out, which into a pipe can take longer than the write call.
main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(`error: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 1;
  },
);
