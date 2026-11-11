// SPDX-License-Identifier: BUSL-1.1
//
// closeAccount(): close an empty confidential token account and return its rent deposit.
//
// Token-2022 closes a token account only when its public balance is zero, and one with the
// confidential-transfer extension only when its encrypted balances are all-zero ciphertexts. An
// account that held tokens has an available balance that encrypts zero but is not the all-zero
// ciphertext, so EmptyAccount first proves, with a zero-ciphertext proof, that it encrypts zero and
// clears it. Everything goes in one transaction: an apply (only if something is pending, which must
// then add up to zero), the proof, EmptyAccount and CloseAccount.
import {
  type Address,
  type Rpc,
  type RpcSubscriptions,
  type Signature,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
  type TransactionSigner,
  address,
} from "@solana/kit";
import {
  AccountState,
  TOKEN_2022_PROGRAM_ADDRESS,
  findAssociatedTokenPda,
  getCloseAccountInstruction,
  getEmptyConfidentialTransferAccountInstruction,
} from "@solana-program/token-2022";
import { verifyZeroCiphertext } from "@solana-program/zk-elgamal-proof";

import { ConfidentialTransfersError } from "./errors";
import { readConfiguredAccount } from "./internal/accounts";
import { assertKeysMatchAccount, ownerKeys } from "./internal/ownerKeys";
import { applyPendingLocally, getApplyInstruction, hasPendingCredits, retryWhilePendingChanges } from "./internal/pendingBalance";
import { sendInstructions, withRetries, type SendOptions } from "./internal/send";
import { ElGamalCiphertext, ZeroCiphertextProofData, ensureZk } from "./internal/zk";
import type { ConfidentialKeypairs } from "./keys";

const SYSVAR_INSTRUCTIONS_ADDRESS = address("Sysvar1nstructions1111111111111111111111111");

export type CloseAccountInput = SendOptions & {
  /** RPC client, e.g. `createSolanaRpc(url)`. */
  rpc: Rpc<SolanaRpcApi>;
  /** Used to confirm the transaction. */
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
  /** Pays the transaction fee. */
  payer: TransactionSigner;
  /** Owner of the token account: signs the close, and the key-derivation message unless `keys` is given. */
  owner: TransactionSigner;
  mint: Address;
  /** Token account to close (defaults to the owner's ATA). */
  token?: Address;
  /** Where the rent deposit goes (defaults to the owner). */
  destination?: Address;
  /** The owner's keys from {@link deriveConfidentialKeys}; skips the message signature. */
  keys?: ConfidentialKeypairs;
  /** Token program. Default: Token-2022. */
  programAddress?: Address;
};

export type CloseAccountResult = { token: Address; signature: Signature };

/**
 * Close the owner's confidential token account and send its rent deposit to `destination` (the
 * owner by default). The account must be empty: no public balance, and nothing available or
 * pending in its confidential balance. Move everything out first, with transfer() or withdraw()
 * and an ordinary token transfer. A frozen account cannot be closed.
 */
export async function closeAccount(input: CloseAccountInput): Promise<CloseAccountResult> {
  const operation = "closeAccount";
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const token =
    input.token ??
    (await findAssociatedTokenPda({ owner: input.owner.address, tokenProgram: programAddress, mint: input.mint }))[0];
  await ensureZk();

  let keys = input.keys;
  const signature = await withRetries(input.retries, () => retryWhilePendingChanges(async () => {
    const { data, ct } = await readConfiguredAccount(input.rpc, token, operation, "your");
    if (data.state === AccountState.Frozen) {
      throw new ConfidentialTransfersError(
        "INVALID_INPUT",
        `${operation}: your token account ${token} is frozen; Token-2022 does not close it until the mint's freeze authority thaws it.`,
        { operation },
      );
    }
    if (data.amount > 0n) {
      throw new ConfidentialTransfersError(
        "INVALID_INPUT",
        `${operation}: your token account ${token} still has a public balance; transfer it out before closing the account.`,
        { operation },
      );
    }
    keys ??= await ownerKeys(input.owner, undefined, operation);
    assertKeysMatchAccount(keys, data, token, operation);

    // What the available balance will hold once anything pending is applied; it has to be zero.
    const applied = applyPendingLocally(ct, keys, token, operation);
    if (applied.value !== 0n) {
      throw new ConfidentialTransfersError(
        "INVALID_INPUT",
        `${operation}: your token account ${token} still has a confidential balance (available or pending); ` +
          "transfer or withdraw it before closing the account.",
        { operation },
      );
    }
    const pending = hasPendingCredits(ct);
    const balance = ElGamalCiphertext.fromBytes(pending ? applied.availableBalance : new Uint8Array(ct.availableBalance));
    if (!balance) {
      throw new ConfidentialTransfersError("DECRYPTION_FAILED", `${operation}: failed to parse the available balance of ${token}`, { operation });
    }
    const [proof] = await verifyZeroCiphertext({
      rpc: input.rpc,
      payer: input.payer,
      proofData: new ZeroCiphertextProofData(keys.elgamalKeypair, balance).toBytes(),
    });

    return sendInstructions(
      { rpc: input.rpc, rpcSubscriptions: input.rpcSubscriptions, payer: input.payer, operation, computeUnitPrice: input.computeUnitPrice },
      [
        ...(pending ? [getApplyInstruction(token, input.owner, applied, programAddress)] : []),
        proof!,
        getEmptyConfidentialTransferAccountInstruction(
          { token, instructionsSysvarOrContextState: SYSVAR_INSTRUCTIONS_ADDRESS, authority: input.owner, proofInstructionOffset: -1 },
          { programAddress },
        ),
        getCloseAccountInstruction(
          { account: token, destination: input.destination ?? input.owner.address, owner: input.owner },
          { programAddress },
        ),
      ],
    );
  }));

  return { token, signature };
}
