// SPDX-License-Identifier: BUSL-1.1
//
// deposit(): move tokens from the public balance into the confidential
// pending balance of a Token-2022 account. No zero-knowledge proof is
// required — the amount is publicly debited and credited to the encrypted
// pending balance. The account must already be configured for confidential
// transfers (see configureAccount) and hold a public token balance.
import {
  type Address,
  type Rpc,
  type RpcSubscriptions,
  type Signature,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
  type TransactionSigner,
} from "@solana/kit";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  findAssociatedTokenPda,
  getConfidentialDepositInstruction,
} from "@solana-program/token-2022";

import { ConfidentialTransfersError } from "./errors";
import { MAX_DEPOSIT_OR_TRANSFER_AMOUNT, assertCanReceive, readConfiguredAccount } from "./internal/accounts";
import { sendInstructions, withRetries, type SendOptions } from "./internal/send";

export type DepositInput = SendOptions & {
  /** RPC client, e.g. `createSolanaRpc(url)`. */
  rpc: Rpc<SolanaRpcApi>;
  /** Used to confirm the transaction(s). */
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
  /** Pays the transaction fee. */
  payer: TransactionSigner;
  /** Owner of the token account (signs the deposit). */
  owner: TransactionSigner;
  /** Mint configured for confidential transfers. */
  mint: Address;
  /** Amount of public tokens to move into the confidential pending balance (at most 2^48 - 1). */
  amount: number | bigint;
  /** Mint decimals (must match the mint). */
  decimals: number;
  /** Token account to deposit into (defaults to the owner's ATA). */
  token?: Address;
  /** Token program. Default: Token-2022. */
  programAddress?: Address;
};

export type DepositResult = {
  token: Address;
  signature: Signature;
};

/**
 * Move tokens from the account's public balance into its confidential pending balance. No proof
 * and no keys are needed; the amount is public in this step. Call {@link applyPendingBalance}
 * afterwards to make it spendable.
 */
export async function deposit(input: DepositInput): Promise<DepositResult> {
  const operation = "deposit";
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const amount = BigInt(input.amount);
  if (amount <= 0n) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `${operation}: the amount must be greater than zero, got ${amount}.`, { operation });
  }
  if (amount > MAX_DEPOSIT_OR_TRANSFER_AMOUNT) {
    throw new ConfidentialTransfersError(
      "AMOUNT_TOO_LARGE",
      `${operation}: ${amount} is more than one deposit can carry (${MAX_DEPOSIT_OR_TRANSFER_AMOUNT}, 2^48 - 1). Split it.`,
      { operation },
    );
  }
  const token =
    input.token ??
    (await findAssociatedTokenPda({ owner: input.owner.address, tokenProgram: programAddress, mint: input.mint }))[0];

  const signature = await withRetries(input.retries, async () => {
    const { data, ct } = await readConfiguredAccount(input.rpc, token, operation, "your");
    if (data.amount < amount) {
      throw new ConfidentialTransfersError(
        "INSUFFICIENT_FUNDS",
        `${operation}: the public balance of ${token} is ${data.amount}, less than ${amount}.`,
        { operation },
      );
    }
    assertCanReceive(ct, token, operation, "your");
    return sendInstructions(
      { rpc: input.rpc, rpcSubscriptions: input.rpcSubscriptions, payer: input.payer, operation, computeUnitPrice: input.computeUnitPrice },
      [
        getConfidentialDepositInstruction(
          { token, mint: input.mint, authority: input.owner, amount, decimals: input.decimals },
          { programAddress },
        ),
      ],
    );
  });

  return { token, signature };
}
