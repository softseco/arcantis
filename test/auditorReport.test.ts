// SPDX-License-Identifier: BUSL-1.1
//
// Integration test for the auditor's report: a mint with an auditor key, deposits, confidential
// transfers both ways and a withdraw; the report has to list exactly those, with the transferred
// amounts decrypted, and the CLI has to write the same as CSV. Requires a CT-capable validator:
//   TOKEN_2022_SO=test/fixtures/spl_token_2022.so npm run validator
//   CT_LOCAL_PROGRAM=1 npm test
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { ed25519 } from "@noble/curves/ed25519";
import { TOKEN_2022_PROGRAM_ADDRESS, getConfidentialDepositInstructionDataEncoder } from "@solana-program/token-2022";
import { ElGamalKeypair } from "@solana/zk-sdk/node";
import { createKeyPairSignerFromBytes, getBase58Decoder, type Address, type Signature } from "@solana/kit";
import { expect } from "chai";

import {
  applyPendingBalance,
  configureAccount,
  confidentialActivityToCsv,
  deposit,
  deriveAuditorElgamalKeypair,
  getAuditorElgamalPubkey,
  isConfidentialTransfersError,
  listConfidentialActivity,
  parseConfidentialActivityJson,
  transfer,
  withdraw,
} from "../src/index";
import { RPC_URL, createConfidentialMint, fundedSigner, mintPublicTokens, rpc, rpcSubscriptions } from "./_helpers";

describe("auditor report from an RPC that is not trusted to be complete", () => {
  const MINT = "So11111111111111111111111111111111111111112" as Address;
  const TOKEN = "SysvarC1ock11111111111111111111111111111111" as Address;
  const OWNER = "Vote111111111111111111111111111111111111111" as Address;
  const sig = () => getBase58Decoder().decode(randomBytes(64)) as Signature;
  const deposit = getBase58Decoder().decode(getConfidentialDepositInstructionDataEncoder().encode({ amount: 5n, decimals: 2 }));
  const depositOf = (token: string, owner: unknown) => ({
    slot: 10n,
    blockTime: null,
    transaction: { message: { accountKeys: [token, MINT, TOKEN_2022_PROGRAM_ADDRESS], instructions: [{ programIdIndex: 2, accounts: [0, 1], data: deposit }] } },
    meta: { err: null, preTokenBalances: [{ accountIndex: 0, owner }] },
  });
  /** An RPC whose history of the mint is these transactions (null: listed, but not returned). */
  const history = (transactions: Map<Signature, unknown>) =>
    ({
      getSignaturesForAddress: () => ({
        send: async () => [...transactions.keys()].map((signature) => ({ signature, blockTime: null, err: null, slot: 10n })),
      }),
      getTransaction: (signature: Signature) => ({ send: async () => transactions.get(signature) ?? null }),
    }) as never;
  const list = (rpc: never, more = {}) =>
    listConfidentialActivity({ rpc, mint: MINT, auditorKeypair: new ElGamalKeypair(), skipAuditorKeyCheck: true, ...more });
  const failure = async (promise: Promise<unknown>) => {
    try {
      await promise;
    } catch (e) {
      return e;
    }
    return undefined;
  };

  it("fails, instead of leaving a gap, when the RPC cannot return a transaction it listed", async () => {
    const missing = sig();
    const error = await failure(list(history(new Map<Signature, unknown>([[sig(), depositOf(TOKEN, OWNER)], [missing, null]]))));
    expect(isConfidentialTransfersError(error, "RPC_ERROR")).to.equal(true);
    expect((error as { signature?: Signature }).signature).to.equal(missing);
    expect(String((error as Error).message)).to.contain("full transaction history");
  });

  it("takes owners and accounts from the RPC only when they are addresses", async () => {
    const [entry] = await list(history(new Map([[sig(), depositOf(TOKEN, "=HYPERLINK(\"http://x\")")]])));
    expect(entry).to.include({ kind: "deposit", fromToken: TOKEN, fromOwner: null, amount: 5n });
    const error = await failure(list(history(new Map([[sig(), depositOf("=cmd|' /C calc'!A0", OWNER)]]))));
    expect(isConfidentialTransfersError(error, "RPC_ERROR")).to.equal(true);
  });

  it("refuses a concurrency or a maximum that is not a whole number of 1 or more", async () => {
    for (const more of [{ concurrency: 0 }, { concurrency: 1.5 }, { concurrency: Number("abc") }, { maxTransactions: 0 }, { since: new Date("x") }]) {
      const error = await failure(list({} as never, more));
      expect(isConfidentialTransfersError(error, "INVALID_INPUT"), JSON.stringify(more)).to.equal(true);
    }
  });
});

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

describeOnChain("auditor report (integration)", function () {
  this.timeout(300000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("lists deposits, confidential transfers and withdraws with the amounts decrypted", async () => {
    // The auditor's wallet, also written to a file for the command-line test below.
    const seed = new Uint8Array(randomBytes(32));
    const walletBytes = new Uint8Array([...seed, ...ed25519.getPublicKey(seed)]);
    const auditorWallet = await createKeyPairSignerFromBytes(walletBytes);
    const auditorKeypair = await deriveAuditorElgamalKeypair(auditorWallet);

    const payer = await fundedSigner(5n);
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer, 2, getAuditorElgamalPubkey(auditorKeypair));
    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    const { token: bobToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });

    await mintPublicTokens({ payer, mint, token: aliceToken, mintAuthority, amount: 1000n });
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 1000n, decimals });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    // No auditorElgamalPubkey here: transfer reads it from the mint.
    await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 300n });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    await transfer({ rpc, rpcSubscriptions, payer, owner: bob, mint, destinationOwner: alice.address, amount: 50n });
    await withdraw({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 100n, decimals });

    const activity = await listConfidentialActivity({ rpc, mint, auditorKeypair });
    expect(activity.map((a) => [a.kind, a.fromOwner, a.toOwner, a.amount, a.decrypted])).to.deep.equal([
      ["deposit", alice.address, alice.address, 1000n, false],
      ["transfer", alice.address, bob.address, 300n, true],
      ["transfer", bob.address, alice.address, 50n, true],
      ["withdraw", alice.address, alice.address, 100n, false],
    ]);
    expect(activity[1].fromToken).to.equal(aliceToken);
    expect(activity[1].toToken).to.equal(bobToken);
    expect(activity.every((a) => a.blockTime instanceof Date)).to.equal(true);

    const csv = confidentialActivityToCsv(activity, { decimals });
    const lines = csv.trim().split("\r\n");
    expect(lines[0]).to.equal(
      "time_utc,slot,signature,kind,from_owner,from_account,to_owner,to_account,amount_base_units,amount,decrypted,note",
    );
    expect(lines).to.have.length(5);
    expect(lines[2]).to.contain(`,transfer,${alice.address},${aliceToken},${bob.address},${bobToken},300,3.00,yes,`);

    // Only part of the history.
    const lastTwo = await listConfidentialActivity({ rpc, mint, auditorKeypair, maxTransactions: 2 });
    expect(lastTwo.map((a) => a.kind)).to.deep.equal(["transfer", "withdraw"]);

    // Another auditor key: refused, unless asked to go on, and then nothing decrypts.
    const stranger = await deriveAuditorElgamalKeypair(await fundedSigner(1n));
    let refused: unknown;
    try {
      await listConfidentialActivity({ rpc, mint, auditorKeypair: stranger });
    } catch (e) {
      refused = e;
    }
    expect(isConfidentialTransfersError(refused, "KEYS_MISMATCH")).to.equal(true);
    const unreadable = await listConfidentialActivity({ rpc, mint, auditorKeypair: stranger, skipAuditorKeyCheck: true });
    expect(unreadable.filter((a) => a.kind === "transfer").every((a) => a.amount === null && !!a.note)).to.equal(true);

    // The command line writes the same report.
    const dir = mkdtempSync(path.join(tmpdir(), "audit-"));
    const keypairFile = path.join(dir, "auditor.json");
    writeFileSync(keypairFile, JSON.stringify(Array.from(walletBytes)));
    const outFile = path.join(dir, "report.csv");
    const cli = path.resolve(__dirname, "../src/cli.ts");
    const tsx = path.resolve(__dirname, "../node_modules/.bin/tsx");
    const { stderr } = await promisify(execFile)(tsx, [cli, "audit-report", "--mint", mint, "--keypair", keypairFile, "--rpc", RPC_URL, "--out", outFile]);
    expect(stderr).to.contain("1 deposits, 2 confidential transfers, 1 withdraws");
    const written = readFileSync(outFile, "utf8");
    expect(written.trim().split("\r\n").slice(1)).to.deep.equal(lines.slice(1));

    // And as a JSON report, which reads back to the same activity.
    const jsonFile = path.join(dir, "report.json");
    await promisify(execFile)(tsx, [cli, "audit-report", "--mint", mint, "--keypair", keypairFile, "--rpc", RPC_URL, "--out", jsonFile]);
    const report = parseConfidentialActivityJson(readFileSync(jsonFile, "utf8"));
    expect(report).to.include({ version: 1, mint, decimals, auditorElgamalPubkey: getAuditorElgamalPubkey(auditorKeypair) });
    expect(report.activity).to.deep.equal(activity);
  });
});
