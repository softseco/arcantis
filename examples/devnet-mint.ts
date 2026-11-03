// SPDX-License-Identifier: BUSL-1.1
//
// A confidential mint on devnet to try a web app with (examples/vite): creates a Token-2022 mint
// with confidential transfers and mints public tokens to your browser wallet. Pays from the local
// Solana CLI wallet (~/.config/solana/id.json), which also becomes the mint authority, so you can
// mint more later with `spl-token mint`.
//
//   npm run example:devnet-mint -- <your wallet address> [amount, default 1000]
//
// Optional: SOLANA_KEYPAIR=/path/to/id.json, DEVNET_RPC / DEVNET_WS for your own endpoint.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";

import { getCreateAccountInstruction } from "@solana-program/system";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  extension,
  findAssociatedTokenPda,
  getCreateAssociatedTokenIdempotentInstruction,
  getInitializeConfidentialTransferMintInstruction,
  getInitializeMint2Instruction,
  getMintSize,
  getMintToInstruction,
} from "@solana-program/token-2022";
import {
  address,
  appendTransactionMessageInstructions,
  assertIsTransactionWithBlockhashLifetime,
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  generateKeyPairSigner,
  none,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  some,
  type Instruction,
  type TransactionSigner,
} from "@solana/kit";

const DECIMALS = 2;
const RPC_URL = process.env.DEVNET_RPC ?? "https://api.devnet.solana.com";
const RPC_WS_URL = process.env.DEVNET_WS ?? "wss://api.devnet.solana.com";
const rpc = createSolanaRpc(RPC_URL);
const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions: createSolanaRpcSubscriptions(RPC_WS_URL) });

async function send(payer: TransactionSigner, instructions: Instruction[]): Promise<void> {
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send();
  const signed = await signTransactionMessageWithSigners(
    pipe(
      createTransactionMessage({ version: 0 }),
      (tx) => setTransactionMessageFeePayerSigner(payer, tx),
      (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
      (tx) => appendTransactionMessageInstructions(instructions, tx),
    ),
  );
  assertIsTransactionWithBlockhashLifetime(signed);
  await sendAndConfirm(signed, { commitment: "confirmed" });
}

async function main(): Promise<void> {
  const [walletArg, amountArg = "1000"] = process.argv.slice(2);
  if (!walletArg) throw new Error("usage: npm run example:devnet-mint -- <your wallet address> [amount]");
  const wallet = address(walletArg);
  const amount = BigInt(amountArg) * 10n ** BigInt(DECIMALS);

  const keypairPath = process.env.SOLANA_KEYPAIR ?? `${homedir()}/.config/solana/id.json`;
  const payer = await createKeyPairSignerFromBytes(new Uint8Array(JSON.parse(readFileSync(keypairPath, "utf8"))));
  console.log("RPC:", new URL(RPC_URL).origin); // origin only, so an API key in the query string is never printed
  console.log("paying from", payer.address);

  const mint = await generateKeyPairSigner();
  const ctMint = extension("ConfidentialTransferMint", {
    authority: some(payer.address),
    autoApproveNewAccounts: true,
    auditorElgamalPubkey: none(),
  });
  const space = BigInt(getMintSize([ctMint]));
  const rent = await rpc.getMinimumBalanceForRentExemption(space).send();
  const [token] = await findAssociatedTokenPda({ owner: wallet, mint: mint.address, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS });

  await send(payer, [
    getCreateAccountInstruction({ payer, newAccount: mint, lamports: rent, space, programAddress: TOKEN_2022_PROGRAM_ADDRESS }),
    getInitializeConfidentialTransferMintInstruction({
      mint: mint.address,
      authority: some(payer.address),
      autoApproveNewAccounts: true,
      auditorElgamalPubkey: none(),
    }),
    getInitializeMint2Instruction({ mint: mint.address, decimals: DECIMALS, mintAuthority: payer.address, freezeAuthority: none() }),
  ]);
  await send(payer, [
    getCreateAssociatedTokenIdempotentInstruction({ payer, ata: token, owner: wallet, mint: mint.address, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS }),
    getMintToInstruction({ mint: mint.address, token, mintAuthority: payer, amount }),
  ]);

  console.log(`\nmint   ${mint.address}`);
  console.log(`minted ${amountArg} public tokens to ${wallet}`);
  console.log("\nPaste the mint into the web app. Your wallet also needs a little devnet SOL for fees");
  console.log("(the whole flow costs about 0.005 SOL; https://faucet.solana.com).");
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
