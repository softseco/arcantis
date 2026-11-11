// SPDX-License-Identifier: BUSL-1.1
//
// The pending balance, and an apply that travels inside the transaction that needs it.
//
// Incoming transfers and deposits land in an account's pending balance; only the available
// balance can be spent. ApplyPendingBalance moves everything that is pending when it runs, but the
// owner writes the new AES copy of the balance from what it read beforehand. A credit that lands in
// between is applied without being in that copy, and the account's two copies drift apart
// (internal/availableBalance.ts).
//
// Two things here avoid that. Both put the apply in the same transaction as an instruction whose
// zero-knowledge proof is about the exact ElGamal balance after the apply, computed locally with the
// same point arithmetic as Token-2022 (add_with_lo_hi):
//
//   - transfer() and withdraw() apply whatever is pending in their own transaction, so a recipient
//     never has to apply first;
//   - applyPendingBalance() adds a withdraw of zero after the apply.
//
// If a credit lands between the read and the transaction, the balance on chain is no longer the
// one the proof is about, Token-2022 refuses the whole transaction (ConfidentialTransferBalanceMismatch,
// 0x1b) and nothing changes: the call reads the account again and builds the transaction afresh.
import { type Address, type Instruction, type ReadonlyUint8Array, type TransactionSigner } from "@solana/kit";
import { getApplyConfidentialPendingBalanceInstruction } from "@solana-program/token-2022";

import { ConfidentialTransfersError, isConfidentialTransfersError } from "../errors";
import type { ConfidentialKeypairs } from "../keys";
import { readAvailableBalance } from "./availableBalance";
import { addWithLoHiCiphertexts } from "./confidentialTransferArithmetic";
import { ElGamalCiphertext } from "./zk";

const PENDING_BALANCE_LO_BIT_LENGTH = 16n;

/** The account fields the pending balance is read from, as Token-2022 stores them. */
export type BalanceCiphertexts = {
  availableBalance: ReadonlyUint8Array;
  decryptableAvailableBalance: ReadonlyUint8Array;
  pendingBalanceLow: ReadonlyUint8Array;
  pendingBalanceHigh: ReadonlyUint8Array;
  pendingBalanceCreditCounter: number | bigint;
};

/** The available balance as it will stand once the pending balance is applied. */
export type AppliedBalance = {
  /** Available plus pending, in base units. */
  value: bigint;
  /** The ElGamal ciphertext of the available balance after the apply. */
  availableBalance: Uint8Array;
  /** The apply's arguments. */
  expectedPendingBalanceCreditCounter: bigint;
  newDecryptableAvailableBalance: Uint8Array;
};

/** True if transfers or deposits are waiting in the pending balance. */
export function hasPendingCredits(ct: Pick<BalanceCiphertexts, "pendingBalanceCreditCounter">): boolean {
  return BigInt(ct.pendingBalanceCreditCounter) > 0n;
}

/** The pending balance in base units, decrypted locally (the low and the high part). */
export function decryptPendingBalance(
  ct: Pick<BalanceCiphertexts, "pendingBalanceLow" | "pendingBalanceHigh">,
  keys: ConfidentialKeypairs,
  token: Address,
  operation: string,
): bigint {
  const secret = keys.elgamalKeypair.secret();
  const decrypt = (what: string, bytes: ReadonlyUint8Array) => {
    const ciphertext = ElGamalCiphertext.fromBytes(new Uint8Array(bytes as Uint8Array));
    if (!ciphertext) {
      throw new ConfidentialTransfersError("DECRYPTION_FAILED", `${operation}: failed to parse the ${what} of ${token}`, { operation });
    }
    try {
      return secret.decrypt(ciphertext);
    } catch (e) {
      throw new ConfidentialTransfersError(
        "DECRYPTION_FAILED",
        `${operation}: could not decrypt the ${what} of ${token}. ` +
          (what === "pending balance (high part)"
            ? "Incoming amounts add up to more than can be decrypted at once (about 2^48 base units); " +
              "the pending balance cannot be applied with this SDK. "
            : "") +
          String(e),
        { operation, cause: e },
      );
    }
  };
  const low = decrypt("pending balance (low part)", ct.pendingBalanceLow);
  const high = decrypt("pending balance (high part)", ct.pendingBalanceHigh);
  return (high << PENDING_BALANCE_LO_BIT_LENGTH) + low;
}

/**
 * The available balance after applying what is pending now: its value, the ElGamal ciphertext
 * Token-2022 will hold, and the apply's arguments. The AES copy written is the full new value, so an
 * apply also repairs a copy that had fallen behind (internal/availableBalance.ts).
 */
export function applyPendingLocally(
  ct: BalanceCiphertexts,
  keys: ConfidentialKeypairs,
  token: Address,
  operation: string,
): AppliedBalance {
  const value = readAvailableBalance(ct, keys, token, operation) + decryptPendingBalance(ct, keys, token, operation);
  return {
    value,
    availableBalance: addWithLoHiCiphertexts(
      ct.availableBalance,
      ct.pendingBalanceLow,
      ct.pendingBalanceHigh,
      PENDING_BALANCE_LO_BIT_LENGTH,
    ),
    expectedPendingBalanceCreditCounter: BigInt(ct.pendingBalanceCreditCounter),
    newDecryptableAvailableBalance: keys.aesKey.encrypt(value).toBytes(),
  };
}

/** The ApplyPendingBalance instruction for an {@link AppliedBalance}. */
export function getApplyInstruction(
  token: Address,
  authority: Address | TransactionSigner,
  applied: AppliedBalance,
  programAddress: Address,
  multiSigners?: TransactionSigner[],
): Instruction {
  return getApplyConfidentialPendingBalanceInstruction(
    {
      token,
      authority: authority as TransactionSigner,
      expectedPendingBalanceCreditCounter: applied.expectedPendingBalanceCreditCounter,
      newDecryptableAvailableBalance: applied.newDecryptableAvailableBalance,
      multiSigners,
    },
    { programAddress },
  );
}

/** Token-2022's ConfidentialTransferBalanceMismatch: the balance changed after the proof was built. */
const BALANCE_MISMATCH = /custom program error: 0x1b\b|ConfidentialTransferBalanceMismatch/;

/**
 * True if Token-2022 refused a transaction because the balance its proof is about changed in the
 * meantime, which is what a credit landing during an apply does. Such a transaction changed nothing.
 */
export function isBalanceChangedError(e: unknown): boolean {
  if (!isConfidentialTransfersError(e) || e.code !== "TRANSACTION_FAILED") return false;
  return BALANCE_MISMATCH.test(e.message) || (e.logs ?? []).some((line) => BALANCE_MISMATCH.test(line));
}

/** How often an operation that applies the pending balance builds its transaction again. */
export const PENDING_CHANGED_ATTEMPTS = 3;

/**
 * Run `attempt` again when the balance changed under it (see the top of this file), up to
 * {@link PENDING_CHANGED_ATTEMPTS} times in all. Each attempt reads the account afresh.
 */
export async function retryWhilePendingChanges<T>(attempt: () => Promise<T>): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await attempt();
    } catch (e) {
      if (!isBalanceChangedError(e) || i >= PENDING_CHANGED_ATTEMPTS) throw e;
    }
  }
}

/**
 * The pending balance to apply with the operation, or `undefined` when nothing is pending or the
 * pending total cannot be decrypted here (the operation then spends the available balance only).
 */
export function pendingToApply(
  ct: BalanceCiphertexts,
  keys: ConfidentialKeypairs,
  token: Address,
  operation: string,
): AppliedBalance | undefined {
  if (!hasPendingCredits(ct)) return undefined;
  try {
    return applyPendingLocally(ct, keys, token, operation);
  } catch (e) {
    if (isConfidentialTransfersError(e, "DECRYPTION_FAILED")) return undefined;
    throw e;
  }
}
