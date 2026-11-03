// SPDX-License-Identifier: BUSL-1.1
//
// End-to-end example: a full confidential-transfer round trip on a local validator.
// Alice deposits public tokens into her confidential balance, then privately
// transfers them to Bob. On-chain the balances are ElGamal-encrypted — only the
// owner of an account can decrypt their own balance.
//
// Prerequisites — a local validator running a client-matching Token-2022 build:
//   Terminal 1:  TOKEN_2022_SO=/path/to/spl_token_2022.so npm run validator
//   Terminal 2:  npm run example
//
// In your own app, install the package and import from it instead of "../src":
//   import { configureAccount, deposit, applyPendingBalance, decryptBalance, transfer }
//     from "@softseco/arcantis";
import { getCreateAccountInstruction } from "@solana-program/system";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  extension,
  getInitializeConfidentialTransferMintInstruction,
  getInitializeMint2Instruction,
  getMintSize,
  getMintToInstruction,
} from "@solana-program/token-2022";
import {
  airdropFactory,
  appendTransactionMessageInstructions,
  assertIsTransactionWithBlockhashLifetime,
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
} from "../src/index";

const RPC_URL = "http://127.0.0.1:8899";
const RPC_WS_URL = "ws://127.0.0.1:8900";

const rpc = createSolanaRpc(RPC_URL);
const rpcSubscriptions = createSolanaRpcSubscriptions(RPC_WS_URL);
const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions });
const airdrop = airdropFactory({ rpc, rpcSubscriptions });

async function fundedSigner(sol = 5n): Promise<KeyPairSigner> {
  const signer = await generateKeyPairSigner();
  await airdrop({
    recipientAddress: signer.address,
    lamports: lamports(sol * 1_000_000_000n),
    commitment: "confirmed",
  });
  return signer;
}

async function sendInstructions(
  payer: TransactionSigner,
  instructions: Instruction[],
): Promise<void> {
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

/** Create a fresh mint configured for confidential transfers (auto-approve, no auditor). */
async function createConfidentialMint(payer: TransactionSigner, decimals = 2) {
  const [mint, mintAuthority] = await Promise.all([
    generateKeyPairSigner(),
    generateKeyPairSigner(),
  ]);
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
  console.log("Connecting to local validator at", RPC_URL);

  // --- app setup (boilerplate): fund wallets and create a CT-enabled mint ---
  const payer = await fundedSigner();
  const alice = await fundedSigner();
  const bob = await fundedSigner();
  const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
  console.log("Mint:", mint);
  console.log("Alice:", alice.address);
  console.log("Bob:  ", bob.address);

  // --- 1. configure both accounts for confidential transfers ---
  console.log("\n1) Configuring Alice & Bob for confidential transfers...");
  const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
  await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });

  // --- 2. give Alice a confidential balance: mint public -> deposit -> apply ---
  const amount = 1000n;
  console.log(`\n2) Minting ${amount} public tokens to Alice, then depositing into her confidential balance...`);
  await sendInstructions(payer, [
    getMintToInstruction({ mint, token: aliceToken, mintAuthority, amount }),
  ]);
  await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount, decimals });
  await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });
  console.log("   Alice confidential balance (decrypted):", (await decryptBalance({ rpc, owner: alice, mint })).toString());

  // --- 3. confidentially transfer everything to Bob (3 ZK proofs under the hood) ---
  console.log(`\n3) Confidentially transferring ${amount} from Alice -> Bob...`);
  const { signatures } = await transfer({
    rpc,
    rpcSubscriptions,
    payer,
    owner: alice,
    mint,
    destinationOwner: bob.address,
    amount,
  });
  console.log(`   transfer landed in ${signatures.length} transaction(s)`);
  await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: bob, mint });

  // --- 4. result: balances are encrypted on-chain, decrypted only by their owners ---
  console.log("\n4) Final decrypted balances:");
  console.log("   Bob  :", (await decryptBalance({ rpc, owner: bob, mint })).toString());
  console.log("   Alice:", (await decryptBalance({ rpc, owner: alice, mint })).toString());
  console.log("\nDone. On-chain these balances are ElGamal-encrypted — only each owner can read their own.");
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
