// SPDX-License-Identifier: BUSL-1.1
//
// withdraw(): move tokens from the owner's confidential AVAILABLE balance back to
// the public balance of the same account. The withdrawn amount is public (it is
// an instruction argument); the balance that remains stays encrypted. Two
// zero-knowledge proofs are required (ciphertext-commitment equality and a range
// proof on the remaining balance). By default they travel inside the withdraw's own
// v1 transaction. With `singleTransaction: false`, or when that does not fit, each
// is verified into a context-state account, the withdraw runs, and the proof
// accounts are closed; those transactions are signed together and sent in order
// (see internal/send.ts). Apply the pending balance first: only the available
// balance can be withdrawn.
import {
  type Address,
  type Rpc,
  type RpcSubscriptions,
  type Signature,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
  type TransactionSigner,
} from "@solana/kit";
import { TOKEN_2022_PROGRAM_ADDRESS, findAssociatedTokenPda } from "@solana-program/token-2022";

import { ConfidentialTransfersError } from "./errors";
import { assertMintAllows, assertNotFrozen, readConfiguredAccount, readMint } from "./internal/accounts";
import { getConfidentialWithdrawInlineInstructions, getConfidentialWithdrawProofFlow } from "./internal/confidentialTransferProof";
import { assertKeysMatchAccount, ownerKeys } from "./internal/ownerKeys";
import { executeProofFlow, sendSingleTransaction, withRetries, type SendOptions } from "./internal/send";
import type { ConfidentialKeypairs } from "./keys";

export type WithdrawInput = SendOptions & {
  /** RPC client, e.g. `createSolanaRpc(url)`. */
  rpc: Rpc<SolanaRpcApi>;
  /** Used to confirm the transaction(s). */
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
  /** Pays the transaction fees, and the rent of proof accounts if any (refunded when they close). */
  payer: TransactionSigner;
  /** Owner of the token account: the withdraw authority, and the key source unless `keys` is given. */
  owner: TransactionSigner;
  /** Mint configured for confidential transfers. */
  mint: Address;
  /** Amount (base units) to move from the confidential available balance to the public balance. */
  amount: number | bigint;
  /** Mint decimals (must match the mint). */
  decimals: number;
  /** Token account to withdraw from (defaults to the owner's ATA). */
  token?: Address;
  /** The owner's keys from {@link deriveConfidentialKeys}; skips the message signature. */
  keys?: ConfidentialKeypairs;
  /** Token program. Default: Token-2022. */
  programAddress?: Address;
  /**
   * Send the withdraw as one transaction with its proofs inside (default `true`). That needs a v1
   * transaction (up to 4,096 bytes), which Solana accepts since September 2026. Set `false` for a
   * wallet or RPC that cannot handle v1 transactions: the proofs then go into proof accounts, as
   * before 1.0.0. The SDK falls back to proof accounts by itself when the one transaction would be
   * too large.
   */
  singleTransaction?: boolean;
};

export type WithdrawResult = {
  token: Address;
  /** The transactions sent, in order: one, or four when proof accounts were used. */
  signatures: Signature[];
  /** Proof accounts left open although the withdraw went through (normally empty). */
  proofAccountsLeftOpen: Address[];
};

/**
 * Move tokens from the confidential available balance back to the public balance of the same
 * account. The withdrawn amount is public; the remaining balance stays encrypted. Builds two
 * proofs and sends them inside one transaction with the withdraw. With `singleTransaction: false`,
 * or when that would be too large, it verifies them into proof accounts, withdraws and closes the
 * proof accounts: four transactions, signed together and sent in order.
 */
export async function withdraw(input: WithdrawInput): Promise<WithdrawResult> {
  const operation = "withdraw";
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const amount = BigInt(input.amount);
  if (amount <= 0n) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `withdraw amount must be greater than zero, got ${amount}`, { operation });
  }

  const token =
    input.token ??
    (await findAssociatedTokenPda({ owner: input.owner.address, tokenProgram: programAddress, mint: input.mint }))[0];

  let keys = input.keys;
  const result = await withRetries(input.retries, async () => {
    const [{ data }, mint] = await Promise.all([
      readConfiguredAccount(input.rpc, token, operation, "your"),
      readMint(input.rpc, input.mint, operation),
    ]);
    // What Token-2022 would refuse anyway, refused before any proof is built or anything signed.
    assertMintAllows(mint.data, input.mint, operation, "withdraw");
    assertNotFrozen(data, token, operation, "your");
    keys ??= await ownerKeys(input.owner, undefined, operation);
    assertKeysMatchAccount(keys, data, token, operation);

    const proofInput = {
      payer: input.payer,
      rpc: input.rpc,
      token,
      mint: input.mint,
      tokenAccount: data,
      authority: input.owner,
      amount,
      decimals: input.decimals,
      elgamalKeypair: keys.elgamalKeypair,
      aesKey: keys.aesKey,
      programAddress,
    };
    const ctx = { rpc: input.rpc, rpcSubscriptions: input.rpcSubscriptions, payer: input.payer, operation, computeUnitPrice: input.computeUnitPrice };
    if (input.singleTransaction !== false) {
      const sent = await sendSingleTransaction(ctx, await getConfidentialWithdrawInlineInstructions(proofInput));
      if (sent) return sent;
    }
    return executeProofFlow(ctx, await getConfidentialWithdrawProofFlow(proofInput), operation);
  });

  return { token, ...result };
}
