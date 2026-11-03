// SPDX-License-Identifier: BUSL-1.1
//
// The whole confidential-transfer flow on mainnet, with a test token and tiny amounts.
//
//   MAINNET_RPC=https://your-mainnet-endpoint npm run example:mainnet            # checks only
//   MAINNET_RPC=https://your-mainnet-endpoint npm run example:mainnet -- --send  # runs it
//
// Without --send it only checks: that mainnet's ZK ElGamal Proof Program accepts the proofs this
// SDK makes (a simulation, free), the payer's balance, and what the run would cost. With --send it
// creates a Token-2022 mint with confidential transfers (a test token, worth nothing), configures
// an account for the payer and for a fresh second wallet, mints 1.00, deposits it, applies it,
// sends 0.25 confidentially, withdraws 0.10, and prints every transaction.
//
// Cost: about 0.01 SOL, almost all of it rent for the mint and the two token accounts, which stays
// with those accounts. The transfer and the withdraw carry their proofs inside one transaction each,
// so no proof accounts are rented.
//
// Pays from the Solana CLI wallet (~/.config/solana/id.json, or SOLANA_KEYPAIR). Optional:
// MAINNET_WS (default: the RPC URL with wss://), PRIORITY_FEE (micro-lamports per compute unit,
// default 20000).
import { readFileSync } from "node:fs";
import { homedir } from "node:os";

import { getCreateAccountInstruction } from "@solana-program/system";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  extension,
  fetchToken,
  getInitializeConfidentialTransferMintInstruction,
  getInitializeMint2Instruction,
  getMintSize,
  getMintToInstruction,
} from "@solana-program/token-2022";
import { verifyPubkeyValidity } from "@solana-program/zk-elgamal-proof";
import { PubkeyValidityProofData } from "@solana/zk-sdk/node";
import {
  appendTransactionMessageInstructions,
  assertIsTransactionWithBlockhashLifetime,
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  generateKeyPairSigner,
  getBase64EncodedWireTransaction,
  getSignatureFromTransaction,
  none,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageComputeUnitPrice,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  some,
  type Instruction,
  type Signature,
  type TransactionSigner,
} from "@solana/kit";

import {
  applyPendingBalance,
  configureAccount,
  decryptBalance,
  deposit,
  deriveConfidentialKeys,
  transfer,
  withdraw,
} from "../src/index";

const SEND = process.argv.includes("--send");
const RPC_URL = process.env.MAINNET_RPC;
if (!RPC_URL) {
  console.error("Set MAINNET_RPC to a mainnet RPC endpoint (the public one rate-limits too hard for this).");
  process.exit(1);
}
const WS_URL = process.env.MAINNET_WS ?? RPC_URL.replace(/^http/, "ws");
const PRIORITY_FEE = BigInt(process.env.PRIORITY_FEE ?? "20000");
const DECIMALS = 2;

const rpc = createSolanaRpc(RPC_URL);
const rpcSubscriptions = createSolanaRpcSubscriptions(WS_URL);
const explorer = (s: Signature) => `   https://explorer.solana.com/tx/${s}`;

/** Build, sign and send one transaction, with the priority fee. */
async function sendInstructions(payer: TransactionSigner, instructions: Instruction[]): Promise<Signature> {
  const { value: blockhash } = await rpc.getLatestBlockhash().send();
  const signed = await signTransactionMessageWithSigners(
    pipe(
      createTransactionMessage({ version: 0 }),
      (tx) => setTransactionMessageFeePayerSigner(payer, tx),
      (tx) => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
      (tx) => setTransactionMessageComputeUnitPrice(PRIORITY_FEE, tx),
      (tx) => appendTransactionMessageInstructions(instructions, tx),
    ),
  );
  assertIsTransactionWithBlockhashLifetime(signed);
  await sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions })(signed, { commitment: "confirmed" });
  return getSignatureFromTransaction(signed);
}
const sol = (l: bigint) => (Number(l) / 1e9).toFixed(6);

async function main(): Promise<void> {
  console.log("RPC:", new URL(RPC_URL!).origin); // origin only, so an API key in the query string is never printed
  const keypairPath = process.env.SOLANA_KEYPAIR ?? `${homedir()}/.config/solana/id.json`;
  const payer = await createKeyPairSignerFromBytes(new Uint8Array(JSON.parse(readFileSync(keypairPath, "utf8"))));
  const startBalance = (await rpc.getBalance(payer.address).send()).value;
  console.log(`payer:   ${payer.address}\nbalance: ${sol(startBalance)} SOL`);

  // 1. Does mainnet's ZK ElGamal Proof Program accept today's proofs? A simulation, nothing is sent.
  const { elgamalKeypair } = await deriveConfidentialKeys({ signer: payer });
  const [verify] = await verifyPubkeyValidity({
    rpc,
    payer,
    proofData: new Uint8Array(new PubkeyValidityProofData(elgamalKeypair).toBytes()),
  });
  const { value: blockhash } = await rpc.getLatestBlockhash().send();
  const probe = await signTransactionMessageWithSigners(
    pipe(
      createTransactionMessage({ version: 0 }),
      (tx) => setTransactionMessageFeePayerSigner(payer, tx),
      (tx) => setTransactionMessageLifetimeUsingBlockhash(blockhash, tx),
      (tx) => appendTransactionMessageInstructions([verify], tx),
    ),
  );
  const simulation = await rpc
    .simulateTransaction(getBase64EncodedWireTransaction(probe), { encoding: "base64", sigVerify: false, replaceRecentBlockhash: true })
    .send();
  if (simulation.value.err) {
    console.log("\nSTOPPED: mainnet's ZK ElGamal Proof Program rejects the proof (nothing was sent):");
    console.log((simulation.value.logs ?? []).join("\n"));
    process.exit(1);
  }
  console.log("ZK proof check: mainnet accepts the proofs this SDK makes (simulated, nothing sent)");

  const needed = 15_000_000n; // 0.015 SOL: rent for a mint and two token accounts, fees, a margin
  if (startBalance < needed) {
    console.log(`\nSTOPPED: the run needs about ${sol(needed)} SOL; the payer has ${sol(startBalance)}.`);
    process.exit(1);
  }
  if (!SEND) {
    console.log(`\nChecks passed. The run costs about 0.01 SOL. Run again with --send to do it.`);
    return;
  }

  // 2. A test mint with confidential transfers; the payer is its mint authority.
  const bob = await generateKeyPairSigner();
  const mint = await generateKeyPairSigner();
  const ctMint = extension("ConfidentialTransferMint", { authority: some(payer.address), autoApproveNewAccounts: true, auditorElgamalPubkey: none() });
  const space = BigInt(getMintSize([ctMint]));
  const rent = await rpc.getMinimumBalanceForRentExemption(space).send();
  const send = { rpc, rpcSubscriptions, payer, computeUnitPrice: PRIORITY_FEE };
  const created = await sendInstructions(payer, [
    getCreateAccountInstruction({ payer, newAccount: mint, lamports: rent, space, programAddress: TOKEN_2022_PROGRAM_ADDRESS }),
    getInitializeConfidentialTransferMintInstruction({ mint: mint.address, authority: some(payer.address), autoApproveNewAccounts: true, auditorElgamalPubkey: none() }),
    getInitializeMint2Instruction({ mint: mint.address, decimals: DECIMALS, mintAuthority: payer.address, freezeAuthority: none() }),
  ]);
  console.log(`\nmint ${mint.address} (test token, ${DECIMALS} decimals)\n${explorer(created)}`);

  // 3. Both accounts. Bob is a fresh wallet; the payer pays for everything.
  const { token, signature: c1 } = await configureAccount({ ...send, owner: payer, mint: mint.address });
  const { signature: c2 } = await configureAccount({ ...send, owner: bob, mint: mint.address });
  console.log(`configured both accounts\n${explorer(c1)}\n${explorer(c2)}`);

  // 4. 1.00 in, deposited, applied.
  await sendInstructions(payer, [getMintToInstruction({ mint: mint.address, token, mintAuthority: payer, amount: 100n })]);
  const { signature: d } = await deposit({ ...send, owner: payer, mint: mint.address, amount: 100n, decimals: DECIMALS });
  const { signature: a } = await applyPendingBalance({ ...send, owner: payer, mint: mint.address });
  console.log(`minted 1.00, deposited and applied\n${explorer(d)}\n${explorer(a)}`);

  // 5. 0.25 to Bob, confidentially; 0.10 back to public.
  const t = await transfer({ ...send, owner: payer, mint: mint.address, destinationOwner: bob.address, amount: 25n });
  console.log(`sent 0.25 to Bob, confidentially (${t.signatures.length} transactions)`);
  t.signatures.forEach((s) => console.log(explorer(s)));
  const w = await withdraw({ ...send, owner: payer, mint: mint.address, amount: 10n, decimals: DECIMALS });
  console.log(`withdrew 0.10 to the public balance (${w.signatures.length} transactions)`);
  w.signatures.forEach((s) => console.log(explorer(s)));

  // 6. What each side sees.
  const payerConfidential = await decryptBalance({ rpc, owner: payer, mint: mint.address });
  const payerPublic = (await fetchToken(rpc, token)).data.amount;
  await applyPendingBalance({ ...send, owner: bob, mint: mint.address });
  const bobConfidential = await decryptBalance({ rpc, owner: bob, mint: mint.address });
  console.log(`\npayer: ${payerConfidential} confidential, ${payerPublic} public (base units)`);
  console.log(`bob:   ${bobConfidential} confidential`);

  const spent = startBalance - (await rpc.getBalance(payer.address).send()).value;
  console.log(`\nspent: ${sol(spent)} SOL (mostly rent that stays with the mint and the two accounts)`);
  console.log(`mint on explorer: https://explorer.solana.com/address/${mint.address}`);
  if (payerConfidential !== 65n || bobConfidential !== 25n) throw new Error("unexpected balances");
  console.log("RESULT: the full confidential-transfer flow works on mainnet with this SDK");
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
