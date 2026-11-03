// SPDX-License-Identifier: BUSL-1.1
//
// Devnet round trip for @softseco/arcantis: configure two accounts,
// deposit, apply, transfer confidentially, withdraw back to public, decrypt.
// Pays from the local Solana CLI wallet (~/.config/solana/id.json), which needs
// about 0.8 devnet SOL.
//
//   solana airdrop 1 --url devnet        (or https://faucet.solana.com)
//   npm run example:devnet
//
// Optional: SOLANA_KEYPAIR=/path/to/id.json, DEVNET_RPC / DEVNET_WS for your own endpoint.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";

import { getCreateAccountInstruction, getTransferSolInstruction } from "@solana-program/system";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  extension,
  getInitializeConfidentialTransferMintInstruction,
  getInitializeMint2Instruction,
  fetchToken,
  getMintSize,
  getMintToInstruction,
} from "@solana-program/token-2022";
import {
  appendTransactionMessageInstructions,
  assertIsTransactionWithBlockhashLifetime,
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  generateKeyPairSigner,
  lamports,
  none,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  some,
  type Instruction,
  type KeyPairSigner,
  type TransactionSigner,
} from "@solana/kit";

import {
  applyPendingBalance,
  configureAccount,
  decryptBalance,
  deposit,
  transfer,
  withdraw,
} from "../src/index";

// Public devnet RPC rate-limits hard (HTTP 429). Retry with the server's own backoff,
// and use DEVNET_RPC / DEVNET_WS if you have a dedicated endpoint.
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: unknown, init?: unknown) => {
  for (let attempt = 0; ; attempt++) {
    const res = await (realFetch as (i: unknown, x?: unknown) => Promise<Response>)(input, init);
    if (res.status !== 429 || attempt >= 8) return res;
    const wait = (Number(res.headers.get("retry-after") ?? 2) + attempt) * 1000;
    console.log(`   (rate limited, waiting ${wait} ms)`);
    await new Promise((r) => setTimeout(r, wait));
  }
}) as typeof fetch;

const pause = (ms = 1500) => new Promise((r) => setTimeout(r, ms));

const RPC_URL = process.env.DEVNET_RPC ?? "https://api.devnet.solana.com";
const RPC_WS_URL = process.env.DEVNET_WS ?? "wss://api.devnet.solana.com";

const rpc = createSolanaRpc(RPC_URL);
const rpcSubscriptions = createSolanaRpcSubscriptions(RPC_WS_URL);
const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions });

async function loadCliWallet(): Promise<KeyPairSigner> {
  const path = process.env.SOLANA_KEYPAIR ?? `${homedir()}/.config/solana/id.json`;
  const bytes = new Uint8Array(JSON.parse(readFileSync(path, "utf8")) as number[]);
  return createKeyPairSignerFromBytes(bytes);
}

async function sendInstructions(payer: TransactionSigner, instructions: Instruction[]): Promise<void> {
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send();
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayerSigner(payer, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstructions(instructions, tx),
  );
  const signed = await signTransactionMessageWithSigners(message);
  assertIsTransactionWithBlockhashLifetime(signed);
  await sendAndConfirm(signed, { commitment: "confirmed" });
}

async function fund(payer: TransactionSigner, destination: KeyPairSigner, sol: number): Promise<void> {
  await sendInstructions(payer, [
    getTransferSolInstruction({
      source: payer,
      destination: destination.address,
      amount: lamports(BigInt(Math.round(sol * 1_000_000_000))),
    }),
  ]);
}

async function createConfidentialMint(payer: TransactionSigner, decimals = 2) {
  const [mint, mintAuthority] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
  const ctMint = extension("ConfidentialTransferMint", {
    authority: some(mintAuthority.address),
    autoApproveNewAccounts: true,
    auditorElgamalPubkey: none(),
  });
  const space = BigInt(getMintSize([ctMint]));
  const rent = await rpc.getMinimumBalanceForRentExemption(space).send();
  await sendInstructions(payer, [
    getCreateAccountInstruction({
      payer,
      newAccount: mint,
      lamports: rent,
      space,
      programAddress: TOKEN_2022_PROGRAM_ADDRESS,
    }),
    getInitializeConfidentialTransferMintInstruction({
      mint: mint.address,
      authority: some(mintAuthority.address),
      autoApproveNewAccounts: true,
      auditorElgamalPubkey: none(),
    }),
    getInitializeMint2Instruction({
      mint: mint.address,
      decimals,
      mintAuthority: mintAuthority.address,
      freezeAuthority: none(),
    }),
  ]);
  return { mint: mint.address, mintAuthority, decimals };
}

async function main() {
  console.log("RPC:", new URL(RPC_URL).origin); // origin only, so an API key in the query string is never printed
  const payer = await loadCliWallet();
  const { value: balance } = await rpc.getBalance(payer.address).send();
  console.log("payer:", payer.address, "balance:", Number(balance) / 1e9, "SOL");
  if (Number(balance) < 0.8e9) throw new Error("payer needs at least ~0.8 SOL on devnet");

  const [alice, bob] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
  console.log("alice:", alice.address);
  console.log("bob:  ", bob.address);
  await fund(payer, alice, 0.15);
  await fund(payer, bob, 0.15);

  const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
  console.log("mint: ", mint);

  console.log("\n1) configureAccount for both wallets");
  const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
  await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });
  console.log("   ok — the ZK ElGamal proof verified on devnet");

  await pause();
  const amount = 1000n;
  console.log(`\n2) mint ${amount} public, deposit into Alice's confidential balance`);
  await sendInstructions(payer, [getMintToInstruction({ mint, token: aliceToken, mintAuthority, amount })]);
  await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount, decimals });
  await pause();
  await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });
  console.log("   alice decrypted:", (await decryptBalance({ rpc, owner: alice, mint })).toString());

  await pause();
  console.log(`\n3) confidential transfer ${amount} Alice -> Bob`);
  const { signatures } = await transfer({
    rpc,
    rpcSubscriptions,
    payer,
    owner: alice,
    mint,
    destinationOwner: bob.address,
    amount,
  });
  console.log("   transactions:", signatures.length);
  for (const s of signatures) console.log("   https://explorer.solana.com/tx/" + s + "?cluster=devnet");
  await pause();
  await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: bob, mint });

  const back = 400n;
  console.log(`\n4) withdraw ${back} of Bob's confidential balance back to public`);
  const withdrawn = await withdraw({ rpc, rpcSubscriptions, payer, owner: bob, mint, amount: back, decimals });
  console.log("   transactions:", withdrawn.signatures.length);
  for (const s of withdrawn.signatures) console.log("   https://explorer.solana.com/tx/" + s + "?cluster=devnet");
  await pause();

  console.log("\n5) final balances");
  const bobPublic = (await fetchToken(rpc, withdrawn.token)).data.amount;
  console.log("   bob confidential:", (await decryptBalance({ rpc, owner: bob, mint })).toString());
  console.log("   bob public:      ", bobPublic.toString());
  console.log("   alice:           ", (await decryptBalance({ rpc, owner: alice, mint })).toString());
  console.log("\nmint on explorer: https://explorer.solana.com/address/" + mint + "?cluster=devnet");
  console.log("RESULT: deposit, transfer and withdraw work on devnet with the SDK");
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("\nFAILED");
    console.error(err);
    const ctx = (err as { context?: unknown }).context;
    if (ctx) console.error("context:", JSON.stringify(ctx, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2));
    const cause = (err as { cause?: unknown }).cause;
    if (cause) console.error("cause:", cause);
    process.exit(1);
  },
);
