// SPDX-License-Identifier: BUSL-1.1
//
// applyPendingBalance(): move an account's confidential PENDING balance into its
// AVAILABLE balance. The pending balance (ElGamal-encrypted) is decrypted locally
// with the owner's ElGamal secret key, added to the current available balance,
// and the new available balance is re-encrypted (AES) into the account's
// decryptable balance. Keys are derived from the owner's wallet signer, or passed
// in as `keys`.
//
// By default the apply is checked: a withdraw of zero follows it in the same transaction, with a
// proof about the exact balance the apply should leave. A deposit or transfer that lands between
// reading the account and the transaction makes Token-2022 refuse both, so the account's two copies
// of its balance can no longer drift apart; the call reads the account again and retries
// (internal/pendingBalance.ts). transfer() and withdraw() apply what is pending by themselves, so
// most applications never need to call this.
import {
  type Address,
  type ReadonlyUint8Array,
  type Rpc,
  type RpcSubscriptions,
  type Signature,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
  type TransactionSigner,
} from "@solana/kit";
import { AccountState, TOKEN_2022_PROGRAM_ADDRESS, findAssociatedTokenPda } from "@solana-program/token-2022";

import { mintExtension, readConfiguredAccount, readMint } from "./internal/accounts";
import { getConfidentialWithdrawInlineInstructions } from "./internal/confidentialTransferProof";
import { assertKeysMatchAccount, ownerKeys } from "./internal/ownerKeys";
import { applyPendingLocally, getApplyInstruction, retryWhilePendingChanges } from "./internal/pendingBalance";
import { sendInstructions, sendSingleTransaction, withRetries, type SendOptions } from "./internal/send";
import type { ConfidentialKeypairs } from "./keys";

export type ApplyPendingBalanceInput = SendOptions & {
  /** RPC client, e.g. `createSolanaRpc(url)`. */
  rpc: Rpc<SolanaRpcApi>;
  /** Used to confirm the transaction(s). */
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
  /** Pays the transaction fee. */
  payer: TransactionSigner;
  /** Signs the instruction, and the key-derivation message unless `keys` is given. */
  owner: TransactionSigner;
  mint: Address;
  /** Token account (defaults to the owner's ATA). */
  token?: Address;
  /** The owner's keys from {@link deriveConfidentialKeys}; skips the message signature. */
  keys?: ConfidentialKeypairs;
  /** Token program. Default: Token-2022. */
  programAddress?: Address;
  /**
   * Check the apply with a withdraw of zero in the same transaction (default `true`), so that a
   * credit landing meanwhile cannot leave the account's balance copies apart (see the top of this
   * file). It needs a v1 transaction and costs about 130,000 compute units more. `false` sends the
   * apply alone, as before 1.0.0-rc.3. A frozen account or a paused mint, which can receive nothing,
   * gets the apply alone either way.
   */
  verify?: boolean;
};

export type ApplyPendingBalanceResult = { token: Address; signature: Signature };

/**
 * Move the incoming (pending) confidential balance into the available balance, which can be
 * transferred or withdrawn. Decrypts the pending amounts locally and writes the new available
 * balance, encrypted, in one transaction.
 */
export async function applyPendingBalance(input: ApplyPendingBalanceInput): Promise<ApplyPendingBalanceResult> {
  const operation = "applyPendingBalance";
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const token =
    input.token ??
    (await findAssociatedTokenPda({ owner: input.owner.address, tokenProgram: programAddress, mint: input.mint }))[0];

  let keys = input.keys;
  const signature = await withRetries(input.retries, () => retryWhilePendingChanges(async () => {
    // Read the account on every attempt: the pending balance and its credit counter change with
    // each incoming transfer, and the instruction has to match them.
    const [{ data, ct }, mint] = await Promise.all([
      readConfiguredAccount(input.rpc, token, operation, "your"),
      readMint(input.rpc, input.mint, operation),
    ]);
    keys ??= await ownerKeys(input.owner, undefined, operation);
    assertKeysMatchAccount(keys, data, token, operation);
    // The AES copy, or the corrected value if an earlier apply left the copy behind; the copy written
    // here then repairs it (internal/availableBalance.ts).
    const applied = applyPendingLocally(ct, keys, token, operation);
    const ctx = { rpc: input.rpc, rpcSubscriptions: input.rpcSubscriptions, payer: input.payer, operation, computeUnitPrice: input.computeUnitPrice };

    const canReceive = data.state !== AccountState.Frozen && !mintExtension(mint.data, "PausableConfig")?.paused;
    if (input.verify !== false && canReceive) {
      const instructions = await getConfidentialWithdrawInlineInstructions({
        payer: input.payer,
        rpc: input.rpc,
        token,
        mint: input.mint,
        tokenAccount: data,
        authority: input.owner,
        amount: 0n,
        allowZero: true,
        decimals: mint.data.decimals,
        elgamalKeypair: keys.elgamalKeypair,
        aesKey: keys.aesKey,
        programAddress,
        applied,
      });
      const sent = await sendSingleTransaction(ctx, instructions);
      if (sent) return sent.signatures[0]!;
    }
    return sendInstructions(ctx, [getApplyInstruction(token, input.owner, applied, programAddress)]);
  }));

  return { token, signature };
}
