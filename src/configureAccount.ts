// SPDX-License-Identifier: BUSL-1.1
//
// configureAccount(): configure a Token-2022 account for confidential transfers.
//
// Sends a single transaction that (1) creates the owner's associated token
// account if needed, (2) reallocates it for the confidential-transfer
// extension, (3) configures it with the owner's ElGamal public key and an
// encrypted zero balance, and (4) verifies the ZK pubkey-validity proof.
// Encryption keys are derived deterministically from the owner's wallet signer
// (see ./keys), so they are recoverable and never stored. Pass `keys` to reuse
// keys derived earlier instead of asking the wallet to sign again.
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
  ExtensionType,
  TOKEN_2022_PROGRAM_ADDRESS,
  fetchMaybeToken,
  findAssociatedTokenPda,
  getConfigureConfidentialTransferAccountInstruction,
  getCreateAssociatedTokenIdempotentInstruction,
  getReallocateInstruction,
} from "@solana-program/token-2022";
import { verifyPubkeyValidity } from "@solana-program/zk-elgamal-proof";

import { ConfidentialTransfersError } from "./errors";
import { confidentialState } from "./internal/accounts";
import { ownerKeys } from "./internal/ownerKeys";
import { sendInstructions, withRetries, type SendOptions } from "./internal/send";
import { PubkeyValidityProofData } from "./internal/zk";
import type { ConfidentialKeypairs } from "./keys";

/**
 * Default, and highest allowed, cap on un-applied incoming confidential credits (2^16). The low
 * part of the pending balance adds up 16 bits per credit and is decrypted with a 32-bit discrete
 * log, so with more than 2^16 credits it could no longer be decrypted, nor the balance applied.
 */
const MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER = 1n << 16n;

export type ConfigureAccountInput = SendOptions & {
  /** RPC client, e.g. `createSolanaRpc(url)`. */
  rpc: Rpc<SolanaRpcApi>;
  /** Used to confirm the transaction(s). */
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
  /** Pays transaction fees and account rent. */
  payer: TransactionSigner;
  /**
   * The token-account owner. Signs the configure instruction, and also the key-derivation message
   * unless `keys` is given (a keypair signer, or a wallet that supports signMessage).
   */
  owner: TransactionSigner;
  /**
   * The owner's keys from {@link deriveConfidentialKeys}, to configure the account without asking
   * the wallet to sign the key message again.
   */
  keys?: ConfidentialKeypairs;
  /** A mint already configured for confidential transfers. */
  mint: Address;
  /**
   * How many incoming deposits and transfers the account accepts before `applyPendingBalance`
   * must be called: 1 to 65536 (2^16; above it the pending balance might not be decryptable).
   * Default: 65536.
   */
  maximumPendingBalanceCreditCounter?: number | bigint;
  /** Token program. Default: Token-2022. */
  programAddress?: Address;
};

/** The configured account, the keys it was configured with, and the transaction signature. */
export type ConfigureAccountResult = ConfidentialKeypairs & {
  /** The configured associated token account. */
  token: Address;
  /** Signature of the configure transaction. */
  signature: Signature;
};

/**
 * Configure the owner's token account for confidential transfers, in one transaction: create the
 * associated token account if needed, make room for the extension, set the owner's ElGamal key
 * and an encrypted zero balance, and verify the pubkey-validity proof.
 *
 * @example
 * ```ts
 * const { token } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
 * ```
 */
export async function configureAccount(input: ConfigureAccountInput): Promise<ConfigureAccountResult> {
  const operation = "configureAccount";
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const maximumPendingBalanceCreditCounter = input.maximumPendingBalanceCreditCounter ?? MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER;
  const counter = maximumPendingBalanceCreditCounter;
  const inRange =
    typeof counter === "bigint"
      ? counter >= 1n && counter <= MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER
      : Number.isInteger(counter) && counter >= 1 && counter <= Number(MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER);
  if (!inRange) {
    throw new ConfidentialTransfersError(
      "INVALID_INPUT",
      `${operation}: maximumPendingBalanceCreditCounter must be a whole number from 1 to 65536 (2^16), got ${counter}. ` +
        "Above 2^16 credits the pending balance might not be decryptable, and could not be applied.",
      { operation },
    );
  }

  const [token] = await findAssociatedTokenPda({
    owner: input.owner.address,
    tokenProgram: programAddress,
    mint: input.mint,
  });
  const existing = await fetchMaybeToken(input.rpc, token);
  if (existing.exists && confidentialState(existing.data)) {
    throw new ConfidentialTransfersError(
      "ACCOUNT_ALREADY_CONFIGURED",
      `${operation}: token account ${token} is already configured for confidential transfers.`,
      { operation },
    );
  }

  // The account's encryption keys: given, or derived deterministically from the owner.
  const { elgamalKeypair, aesKey } = await ownerKeys(input.owner, input.keys, operation);

  const signature = await withRetries(input.retries, async () => {
    // The pubkey-validity proof and its on-chain verify instruction; configure's
    // proofInstructionOffset = 1 points to the verify instruction that follows it.
    const proofData = new PubkeyValidityProofData(elgamalKeypair);
    const [verifyProofInstruction] = await verifyPubkeyValidity({
      rpc: input.rpc,
      payer: input.payer,
      proofData: new Uint8Array(proofData.toBytes()),
    });
    return sendInstructions(
      { rpc: input.rpc, rpcSubscriptions: input.rpcSubscriptions, payer: input.payer, operation, computeUnitPrice: input.computeUnitPrice },
      [
        getCreateAssociatedTokenIdempotentInstruction({
          ata: token,
          mint: input.mint,
          owner: input.owner.address,
          payer: input.payer,
          tokenProgram: programAddress,
        }),
        getReallocateInstruction(
          { token, payer: input.payer, owner: input.owner, newExtensionTypes: [ExtensionType.ConfidentialTransferAccount] },
          { programAddress },
        ),
        getConfigureConfidentialTransferAccountInstruction(
          {
            token,
            mint: input.mint,
            authority: input.owner,
            decryptableZeroBalance: aesKey.encrypt(0n).toBytes(),
            maximumPendingBalanceCreditCounter,
            proofInstructionOffset: 1,
          },
          { programAddress },
        ),
        verifyProofInstruction,
      ],
    );
  });

  return { token, elgamalKeypair, aesKey, signature };
}
