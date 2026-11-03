// SPDX-License-Identifier: BUSL-1.1
//
// Reading token accounts before acting on them, so that a missing account, a missing extension or
// a full pending balance fails with a clear error before anything is signed or sent.
import { isSome, type Address, type Rpc, type SolanaRpcApi } from "@solana/kit";
import { AccountState, fetchMaybeToken, fetchMint, type Extension, type Mint, type Token } from "@solana-program/token-2022";

import { ConfidentialTransfersError } from "../errors";

export type ConfidentialTransferAccountState = Extract<Extension, { __kind: "ConfidentialTransferAccount" }>;

/** Most a single deposit or transfer can carry: 2^48 - 1 base units (16 + 32 bits). */
export const MAX_DEPOSIT_OR_TRANSFER_AMOUNT = (1n << 48n) - 1n;

export function confidentialState(account: Pick<Token, "extensions">): ConfidentialTransferAccountState | undefined {
  if (!isSome(account.extensions)) return undefined;
  return account.extensions.value.find(
    (e): e is ConfidentialTransferAccountState => e.__kind === "ConfidentialTransferAccount",
  );
}

/**
 * Fetch a token account that must exist and be configured for confidential transfers.
 * `whose` goes into the error message: "your", "the recipient's".
 */
export async function readConfiguredAccount(
  rpc: Rpc<SolanaRpcApi>,
  token: Address,
  operation: string,
  whose = "the",
): Promise<{ data: Token; ct: ConfidentialTransferAccountState }> {
  const account = await fetchMaybeToken(rpc, token);
  if (!account.exists) {
    throw new ConfidentialTransfersError(
      "ACCOUNT_NOT_FOUND",
      `${operation}: ${whose} token account ${token} does not exist. It is created by configureAccount.`,
      { operation },
    );
  }
  const ct = confidentialState(account.data);
  if (!ct) {
    throw new ConfidentialTransfersError(
      "ACCOUNT_NOT_CONFIGURED",
      `${operation}: ${whose} token account ${token} is missing the ConfidentialTransferAccount extension; ` +
        "it has to be set up with configureAccount first.",
      { operation },
    );
  }
  return { data: account.data, ct };
}

/** The mint account, or a clear error when the address is not a Token-2022 mint. */
export async function readMint(rpc: Rpc<SolanaRpcApi>, mint: Address, operation: string) {
  try {
    return await fetchMint(rpc, mint);
  } catch (e) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `${operation}: ${mint} is not a Token-2022 mint (or does not exist).`, {
      operation,
      cause: e,
    });
  }
}

/** One extension of a mint, if it has it. */
export function mintExtension<K extends Extension["__kind"]>(mint: Pick<Mint, "extensions">, kind: K) {
  if (!isSome(mint.extensions)) return undefined;
  return mint.extensions.value.find((e): e is Extract<Extension, { __kind: K }> => e.__kind === kind);
}

/**
 * Throws, before any proof is built, when Token-2022 would refuse the operation on this mint: the
 * mint is paused, or, for a transfer, it has a transfer fee. Token-2022 then takes only
 * TransferWithFee, which needs two more proofs, and this SDK does not build it.
 */
export function assertMintAllows(
  mint: Pick<Mint, "extensions">,
  address: Address,
  operation: string,
  kind: "transfer" | "withdraw",
): void {
  if (mintExtension(mint, "PausableConfig")?.paused) {
    throw new ConfidentialTransfersError(
      "INVALID_INPUT",
      `${operation}: mint ${address} is paused; Token-2022 refuses its transfers and withdrawals until its pause authority resumes it.`,
      { operation },
    );
  }
  if (kind === "transfer" && mintExtension(mint, "TransferFeeConfig")) {
    throw new ConfidentialTransfersError(
      "INVALID_INPUT",
      `${operation}: mint ${address} has a transfer fee (TransferFeeConfig). Token-2022 then takes only a confidential ` +
        "TransferWithFee, with two more proofs, which this SDK does not build.",
      { operation },
    );
  }
}

/** Throws when the token account is frozen: Token-2022 refuses confidential transfers from or to it. */
export function assertNotFrozen(account: Pick<Token, "state">, token: Address, operation: string, whose: string): void {
  if (account.state === AccountState.Frozen) {
    throw new ConfidentialTransfersError(
      "INVALID_INPUT",
      `${operation}: ${whose} token account ${token} is frozen; Token-2022 refuses it until the mint's freeze authority thaws it.`,
      { operation },
    );
  }
}

/** Throws unless the account can take one more incoming deposit or transfer. */
export function assertCanReceive(
  ct: ConfidentialTransferAccountState,
  token: Address,
  operation: string,
  whose: "your" | "the recipient's",
): void {
  if (!ct.approved) {
    throw new ConfidentialTransfersError(
      "ACCOUNT_NOT_APPROVED",
      `${operation}: ${whose} token account ${token} has not been approved for confidential transfers by the mint's confidential-transfer authority.`,
      { operation },
    );
  }
  if (!ct.allowConfidentialCredits) {
    throw new ConfidentialTransfersError(
      "RECIPIENT_REJECTS_CONFIDENTIAL",
      `${operation}: ${whose} token account ${token} does not accept confidential credits.`,
      { operation },
    );
  }
  if (ct.pendingBalanceCreditCounter >= ct.maximumPendingBalanceCreditCounter) {
    throw new ConfidentialTransfersError(
      "PENDING_BALANCE_LIMIT",
      `${operation}: ${whose} token account ${token} has received ${ct.pendingBalanceCreditCounter} deposits or ` +
        "transfers since its pending balance was last applied, the most it takes. " +
        (whose === "your" ? "Run applyPendingBalance first." : "The recipient has to run applyPendingBalance first."),
      { operation },
    );
  }
}
