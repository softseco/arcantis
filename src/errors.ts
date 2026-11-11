// SPDX-License-Identifier: BUSL-1.1
//
// Errors the SDK throws on purpose. Every one is a ConfidentialTransfersError with a `code`, so an
// app can react to the case (ask the user to apply the pending balance, retry, pick another
// wallet) without matching on message text. Messages stay human-readable.
import type { Address, Signature } from "@solana/kit";

export type ConfidentialTransfersErrorCode =
  /** An argument is invalid (zero amount, missing destination, malformed address). */
  | "INVALID_INPUT"
  /** A token account the call needs does not exist. */
  | "ACCOUNT_NOT_FOUND"
  /** The token account has no confidential-transfer extension; run configureAccount first. */
  | "ACCOUNT_NOT_CONFIGURED"
  /** configureAccount on an account that is already configured. */
  | "ACCOUNT_ALREADY_CONFIGURED"
  /** The account is configured but not approved by the mint's confidential-transfer authority. */
  | "ACCOUNT_NOT_APPROVED"
  /** The recipient's account does not accept confidential transfers (`allowConfidentialCredits` off). */
  | "RECIPIENT_REJECTS_CONFIDENTIAL"
  /**
   * The account has taken as many incoming deposits and transfers as it allows before
   * applyPendingBalance. The owner must apply the pending balance first.
   */
  | "PENDING_BALANCE_LIMIT"
  /** More than the available (or public, for a deposit) balance. */
  | "INSUFFICIENT_FUNDS"
  /** Above what one deposit or transfer can carry: 2^48 - 1 base units. */
  | "AMOUNT_TOO_LARGE"
  /** The keys passed are not the keys the account is configured with. */
  | "KEYS_MISMATCH"
  /**
   * The recipient's ElGamal key, as the RPC returned it, is not the one the caller pinned with
   * `destinationElgamalPubkey`. Nothing was encrypted to it or signed.
   */
  | "RECIPIENT_KEY_MISMATCH"
  /** A balance could not be decrypted (wrong keys, or a pending total beyond what can be decrypted). */
  | "DECRYPTION_FAILED"
  /**
   * The AES copy of the available balance has fallen behind the encrypted balance by more than the
   * SDK can recover (2^32 base units or more). Happens when credits arrive during an apply.
   */
  | "BALANCE_OUT_OF_SYNC"
  /**
   * Data in a format or version this release does not know, refused rather than misread: an
   * auditor report written by a newer release, or a cryptography library that would derive keys
   * from a message other than `solana-conf-bal/v1`. See docs/formats.md.
   */
  | "UNSUPPORTED_FORMAT"
  /** The signer cannot sign messages, which the confidential keys come from. */
  | "CANNOT_SIGN_MESSAGES"
  /** The wallet changed the message it was asked to sign, or returned a signature that does not verify. */
  | "BAD_MESSAGE_SIGNATURE"
  /** The zk-sdk WebAssembly could not be loaded (browser). */
  | "CRYPTO_UNAVAILABLE"
  /**
   * A transaction failed in simulation or on chain, or the RPC node refused it; `logs` has the
   * program logs.
   */
  | "TRANSACTION_FAILED"
  /**
   * A transaction was not confirmed before its blockhash expired, and the RPC confirms it did not
   * land. Safe to retry.
   */
  | "TRANSACTION_EXPIRED"
  /**
   * A transaction was sent, but whether it landed could not be found out: no confirmation arrived
   * and its status could not be read, even after its blockhash expired. It may have landed. Look
   * up `signature` before running the call again. Never retried.
   */
  | "TRANSACTION_OUTCOME_UNKNOWN"
  /**
   * The RPC node did not serve something the call needs, for example a transaction that its own
   * history lists. Use an RPC that keeps the full history. (Other failed requests reach the caller
   * as `@solana/kit` errors.)
   */
  | "RPC_ERROR";

export type ConfidentialTransfersErrorDetails = {
  /** The SDK function that failed, e.g. "transfer". */
  operation?: string;
  /** For multi-transaction operations: "proofs" (setting up the proof accounts) or the main step. */
  step?: string;
  /** Program logs of the failed transaction, when there are any. */
  logs?: readonly string[];
  /** Transactions of this call that did land before the failure. */
  signatures?: readonly Signature[];
  /**
   * The transaction this error is about, when there is one: the one that failed on chain or
   * expired, the one to look up (TRANSACTION_OUTCOME_UNKNOWN), or the one the RPC could not
   * return (RPC_ERROR).
   */
  signature?: Signature;
  /**
   * Proof accounts of a failed transfer or withdraw. The SDK closes the ones it created (their
   * rent goes back to the payer); any it could not close are in `leftOpen`, and
   * `recoverProofAccounts` closes them later. When the outcome of the transfer or withdraw itself
   * is unknown (TRANSACTION_OUTCOME_UNKNOWN), none is closed: they are all in `leftOpen`.
   */
  proofAccounts?: { readonly closed: readonly Address[]; readonly leftOpen: readonly Address[] };
  /** True when running the same call again can succeed as is (for example an expired blockhash). */
  retryable?: boolean;
  cause?: unknown;
};

export class ConfidentialTransfersError extends Error {
  readonly code: ConfidentialTransfersErrorCode;
  readonly operation?: string;
  readonly step?: string;
  readonly logs?: readonly string[];
  readonly signatures?: readonly Signature[];
  readonly signature?: Signature;
  readonly proofAccounts?: { readonly closed: readonly Address[]; readonly leftOpen: readonly Address[] };
  readonly retryable: boolean;
  readonly cause?: unknown;

  constructor(code: ConfidentialTransfersErrorCode, message: string, details: ConfidentialTransfersErrorDetails = {}) {
    super(message);
    this.name = "ConfidentialTransfersError";
    if (details.cause !== undefined) this.cause = details.cause;
    this.code = code;
    this.operation = details.operation;
    this.step = details.step;
    this.logs = details.logs;
    this.signatures = details.signatures;
    this.signature = details.signature;
    this.proofAccounts = details.proofAccounts;
    this.retryable = details.retryable ?? code === "TRANSACTION_EXPIRED";
  }
}

/** True if `error` is a ConfidentialTransfersError, optionally with the given code. */
export function isConfidentialTransfersError(
  error: unknown,
  code?: ConfidentialTransfersErrorCode,
): error is ConfidentialTransfersError {
  return error instanceof ConfidentialTransfersError && (code === undefined || error.code === code);
}
