// SPDX-License-Identifier: BUSL-1.1
//
// transfer(): confidentially move tokens from the owner's AVAILABLE balance to a
// destination account. This generates the three required zero-knowledge proofs
// (ciphertext-commitment equality, batched grouped-ciphertext validity, and
// batched range). By default they travel inside the transfer's own transaction,
// a v1 transaction of up to 4,096 bytes, and the transfer reads them there. When
// that does not fit, or `singleTransaction: false` asks for it, each proof is
// verified into a context-state account, the transfer references those accounts,
// and they are closed again: five transactions, signed together (one wallet
// prompt) and sent in order; if a step fails before the transfer lands, the proof
// accounts are closed again (see internal/send.ts).
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
import { isSome } from "@solana/kit";

import { ConfidentialTransfersError } from "./errors";
import {
  assertCanReceive,
  assertMintAllows,
  assertNotFrozen,
  mintExtension,
  readConfiguredAccount,
  readMint,
} from "./internal/accounts";
import { getConfidentialTransferInlineInstructions, getConfidentialTransferProofFlow } from "./internal/confidentialTransferProof";
import { assertKeysMatchAccount, ownerKeys } from "./internal/ownerKeys";
import { pendingToApply, retryWhilePendingChanges } from "./internal/pendingBalance";
import { executeProofFlow, sendSingleTransaction, withRetries, type SendOptions } from "./internal/send";
import { assertHookAccountsAreNotSigners, resolveTransferHookAccounts } from "./internal/transferHook";
import type { ConfidentialKeypairs } from "./keys";

export type TransferInput = SendOptions & {
  /** RPC client, e.g. `createSolanaRpc(url)`. */
  rpc: Rpc<SolanaRpcApi>;
  /** Used to confirm the transaction(s). */
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
  /** Pays the transaction fees, and the rent of proof accounts if any (refunded when they close). */
  payer: TransactionSigner;
  /**
   * Source account owner: the transfer authority, and the key source unless `keys` is given.
   */
  owner: TransactionSigner;
  mint: Address;
  /**
   * Owner of the destination account: the transfer goes to its associated token account, unless
   * `destinationToken` is given. Given with `destinationToken`, it must be that account's owner.
   */
  destinationOwner?: Address;
  /** Amount in base units. Up to 2^48 - 1 per transfer. */
  amount: bigint;
  /** Source token account (defaults to the owner's ATA). */
  sourceToken?: Address;
  /**
   * Destination token account; must be configured for confidential transfers. Takes the place of
   * `destinationOwner`'s associated token account; if both are given, the call is refused
   * (INVALID_INPUT) unless `destinationOwner` owns this account.
   */
  destinationToken?: Address;
  /**
   * The mint's auditor ElGamal key; the amount is also encrypted to it. Read from the mint when not
   * given (since 3.3.0), so it is only needed to override that.
   */
  auditorElgamalPubkey?: Address;
  /**
   * The recipient's ElGamal key as the application knows it (from its own records of the recipient,
   * not from this RPC). When given, the transfer is refused (RECIPIENT_KEY_MISMATCH) before anything
   * is encrypted or signed if the RPC reports another key for the recipient's account: an RPC that
   * substituted its own key would otherwise receive the amount encrypted to that key.
   */
  destinationElgamalPubkey?: Address;
  /**
   * Spend what is pending too (default `true`): when incoming transfers or deposits wait in the
   * pending balance, the one-transaction transfer applies them first, in the same transaction, so
   * the recipient of earlier payments never has to call applyPendingBalance. If another credit lands
   * while the transaction is on its way, Token-2022 refuses it as a whole and the call builds it
   * again (up to three times). With proof accounts (`singleTransaction: false`, or a transaction too
   * large) only the available balance is spent.
   */
  applyPending?: boolean;
  /** The owner's keys from {@link deriveConfidentialKeys}; skips the message signature. */
  keys?: ConfidentialKeypairs;
  /** Token program. Default: Token-2022. */
  programAddress?: Address;
  /**
   * Send the transfer as one transaction with its proofs inside (default `true`). That needs a v1
   * transaction (up to 4,096 bytes), which Solana accepts since September 2026. Set `false` for a
   * wallet or RPC that cannot handle v1 transactions: the proofs then go into proof accounts, as
   * before 1.0.0. The SDK falls back to proof accounts by itself when the one transaction would be
   * too large, e.g. with a transfer hook that asks for many accounts.
   */
  singleTransaction?: boolean;
};

export type TransferResult = {
  sourceToken: Address;
  destinationToken: Address;
  /** The transactions sent, in order: one, or five when proof accounts were used. */
  signatures: Signature[];
  /**
   * Proof accounts left open although the transfer went through (only if closing them failed;
   * normally empty). `recoverProofAccounts` closes them.
   */
  proofAccountsLeftOpen: Address[];
};

/**
 * Send a confidential amount from the owner's available balance to another account. Builds the
 * three zero-knowledge proofs and sends them inside one transaction with the transfer (with the
 * mint's transfer-hook accounts, if it has a hook). With `singleTransaction: false`, or when that
 * transaction would be too large, it verifies them into proof accounts, runs the transfer and
 * closes the proof accounts: five transactions, signed together (a wallet asks once) and sent in
 * order. If a step fails before the transfer itself lands, the proof accounts are closed and a
 * ConfidentialTransfersError says which step failed.
 *
 * @example
 * ```ts
 * await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 600n });
 * ```
 */
export async function transfer(input: TransferInput): Promise<TransferResult> {
  const operation = "transfer";
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const amount = BigInt(input.amount);
  if (amount <= 0n) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `${operation}: the amount must be greater than zero, got ${amount}.`, { operation });
  }

  const sourceToken =
    input.sourceToken ??
    (await findAssociatedTokenPda({ owner: input.owner.address, tokenProgram: programAddress, mint: input.mint }))[0];

  let destinationToken = input.destinationToken;
  if (destinationToken == null) {
    if (input.destinationOwner == null) {
      throw new ConfidentialTransfersError("INVALID_INPUT", "transfer requires either destinationToken or destinationOwner", { operation });
    }
    destinationToken = (
      await findAssociatedTokenPda({ owner: input.destinationOwner, tokenProgram: programAddress, mint: input.mint })
    )[0];
  }
  const destination = destinationToken;

  let keys = input.keys;
  const result = await withRetries(input.retries, () => retryWhilePendingChanges(async () => {
    const [source, dest, mint] = await Promise.all([
      readConfiguredAccount(input.rpc, sourceToken, operation, "your"),
      readConfiguredAccount(input.rpc, destination, operation, "the recipient's"),
      readMint(input.rpc, input.mint, operation),
    ]);
    // What Token-2022 would refuse anyway, refused before any proof is built or anything signed.
    assertMintAllows(mint.data, input.mint, operation, "transfer");
    assertNotFrozen(source.data, sourceToken, operation, "your");
    assertNotFrozen(dest.data, destination, operation, "the recipient's");
    assertCanReceive(dest.ct, destination, operation, "the recipient's");
    if (input.destinationToken != null && input.destinationOwner != null && dest.data.owner !== input.destinationOwner) {
      throw new ConfidentialTransfersError(
        "INVALID_INPUT",
        `${operation}: destinationToken ${destination} belongs to ${dest.data.owner}, not to destinationOwner ` +
          `${input.destinationOwner}. Pass only one of them, or both for the same recipient.`,
        { operation },
      );
    }
    if (input.destinationElgamalPubkey != null && dest.ct.elgamalPubkey !== input.destinationElgamalPubkey) {
      throw new ConfidentialTransfersError(
        "RECIPIENT_KEY_MISMATCH",
        `${operation}: the RPC reports ElGamal key ${dest.ct.elgamalPubkey} for the recipient's account ${destination}, ` +
          `not the pinned ${input.destinationElgamalPubkey}. Nothing was encrypted or signed. Check the RPC, or the ` +
          "recipient's key if the recipient set up a new account.",
        { operation },
      );
    }

    // Token-2022 calls the mint's transfer hook on a confidential transfer too, and the hook's
    // accounts have to travel with the instruction or the transfer fails with MissingAccount.
    const transferHookAccounts = await resolveTransferHookAccounts({
      rpc: input.rpc,
      mint: input.mint,
      sourceToken,
      destinationToken: destination,
      owner: input.owner.address,
      programAddress,
    });
    // Checked here before the key message is signed, and again by executeProofFlow against
    // everything that signs the transfer's transaction.
    assertHookAccountsAreNotSigners(transferHookAccounts, [input.payer.address, input.owner.address], operation);

    keys ??= await ownerKeys(input.owner, undefined, operation);
    assertKeysMatchAccount(keys, source.data, sourceToken, operation);

    // Token-2022 refuses a transfer whose amount is not also encrypted to the mint's auditor key.
    const auditorElgamalPubkey = input.auditorElgamalPubkey ?? auditorKeyOf(mint.data);

    const proofInput = {
      payer: input.payer,
      rpc: input.rpc,
      sourceToken,
      mint: input.mint,
      destinationToken: destination,
      sourceTokenAccount: source.data,
      destinationTokenAccount: dest.data,
      authority: input.owner,
      amount,
      sourceElgamalKeypair: keys.elgamalKeypair,
      aesKey: keys.aesKey,
      auditorElgamalPubkey,
      transferHookAccounts,
      programAddress,
    };
    const ctx = { rpc: input.rpc, rpcSubscriptions: input.rpcSubscriptions, payer: input.payer, operation, computeUnitPrice: input.computeUnitPrice };
    if (input.singleTransaction !== false) {
      const applied = input.applyPending === false ? undefined : pendingToApply(source.ct, keys, sourceToken, operation);
      const sent = await sendSingleTransaction(
        ctx,
        await getConfidentialTransferInlineInstructions({ ...proofInput, applied }),
        transferHookAccounts.map((account) => account.address),
      );
      if (sent) return sent;
    }
    return executeProofFlow(ctx, await getConfidentialTransferProofFlow(proofInput), operation);
  }));

  return { sourceToken, destinationToken: destination, ...result };
}

function auditorKeyOf(mint: Parameters<typeof mintExtension>[0]): Address | undefined {
  const ct = mintExtension(mint, "ConfidentialTransferMint");
  return ct && isSome(ct.auditorElgamalPubkey) ? ct.auditorElgamalPubkey.value : undefined;
}

