// SPDX-License-Identifier: BUSL-1.1
//
// Token accounts owned by a program: the client prepares, the program signs through CPI.
//
// The owner of such an account is a PDA. Nobody can sign for it but its program, so these
// functions build the Token-2022 instructions with the PDA as their authority and leave the
// signing to the program: it checks each instruction and calls Token-2022 with `invoke_signed`.
// The keys come from deriveConfidentialKeysWithSeed with pdaWalletPublicSeed, signed by whoever
// runs the program's proof service.
//
// The proofs travel inside the transaction (a v1 transaction, up to 4,096 bytes), right before
// the Token-2022 instruction, which finds them by their offset. A program that wraps a Token-2022
// instruction in one of its own keeps it at the same position, so the offsets stay right: the
// instructions sysvar counts top-level instructions.
//
// The Rust crate offers the same with `prepare_configure`, `prepare_transfer` and
// `prepare_withdraw`, with the proofs in proof accounts.
import { type Address, type Instruction, type Rpc, type SolanaRpcApi, type TransactionSigner, isSome } from "@solana/kit";
import {
  ExtensionType,
  TOKEN_2022_PROGRAM_ADDRESS,
  getConfigureConfidentialTransferAccountInstruction,
  getReallocateInstruction,
} from "@solana-program/token-2022";
import { verifyPubkeyValidity } from "@solana-program/zk-elgamal-proof";

import { ConfidentialTransfersError } from "./errors";
import {
  assertCanReceive,
  assertMintAllows,
  assertNotFrozen,
  mintExtension,
  readConfiguredAccount,
  readMint,
} from "./internal/accounts";
import {
  getConfidentialTransferInlineInstructions,
  getConfidentialWithdrawInlineInstructions,
} from "./internal/confidentialTransferProof";
import { assertKeysMatchAccount } from "./internal/ownerKeys";
import { applyPendingLocally, getApplyInstruction, hasPendingCredits, pendingToApply } from "./internal/pendingBalance";
import { resolveTransferHookAccounts } from "./internal/transferHook";
import { PubkeyValidityProofData, ensureZk } from "./internal/zk";
import type { ConfidentialKeypairs } from "./keys";

const MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER = 1n << 16n;

export type PrepareConfigureInput = {
  /** Used only to build the proof instruction. */
  rpc: Rpc<SolanaRpcApi>;
  /** Pays for the account's extra space; signs the reallocation. */
  payer: TransactionSigner;
  /** The token account (it must exist, for example as the PDA's associated token account). */
  token: Address;
  mint: Address;
  /** The PDA that owns the account. */
  authority: Address;
  keys: ConfidentialKeypairs;
  /** Default 65,536 (2^16). */
  maximumPendingBalanceCreditCounter?: bigint;
  programAddress?: Address;
};

/**
 * Configure a program-owned account for confidential transfers: `Reallocate` (room for the
 * extension), `ConfigureAccount` and the pubkey-validity proof right after it (offset 1). The
 * program signs the first two with its PDA.
 */
export async function prepareConfigure(input: PrepareConfigureInput): Promise<Instruction[]> {
  await ensureZk();
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const counter = input.maximumPendingBalanceCreditCounter ?? MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER;
  if (counter < 1n || counter > MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER) {
    throw new ConfidentialTransfersError(
      "INVALID_INPUT",
      `prepareConfigure: maximumPendingBalanceCreditCounter must be from 1 to 65536, got ${counter}.`,
      { operation: "prepareConfigure" },
    );
  }
  const proofData = new PubkeyValidityProofData(input.keys.elgamalKeypair);
  const [verify] = await verifyPubkeyValidity({ rpc: input.rpc, payer: input.payer, proofData: new Uint8Array(proofData.toBytes()) });
  return [
    getReallocateInstruction(
      { token: input.token, payer: input.payer, owner: input.authority, newExtensionTypes: [ExtensionType.ConfidentialTransferAccount] },
      { programAddress },
    ),
    getConfigureConfidentialTransferAccountInstruction(
      {
        token: input.token,
        mint: input.mint,
        authority: input.authority,
        decryptableZeroBalance: input.keys.aesKey.encrypt(0n).toBytes(),
        maximumPendingBalanceCreditCounter: counter,
        proofInstructionOffset: 1,
      },
      { programAddress },
    ),
    verify!,
  ];
}

export type PrepareTransferInput = {
  rpc: Rpc<SolanaRpcApi>;
  /** Pays the transaction; it is not given to the transfer hook. */
  payer: TransactionSigner;
  mint: Address;
  /** The program-owned account the tokens leave. */
  sourceToken: Address;
  /** The PDA that owns it. */
  authority: Address;
  destinationToken: Address;
  amount: number | bigint;
  /** The source account's keys (deriveConfidentialKeysWithSeed). */
  keys: ConfidentialKeypairs;
  /** Refuse the transfer, before anything is encrypted, if the destination has another key. */
  destinationElgamalPubkey?: Address;
  /**
   * Apply what is pending in the source account first, in the same transaction, and spend it
   * too (default `true`). The apply is signed by the PDA as well.
   */
  applyPending?: boolean;
  programAddress?: Address;
};

/**
 * A confidential transfer out of a program-owned account: the apply (when something is pending),
 * the three proofs and the `Transfer` with the transfer hook's accounts, in this order, for one v1
 * transaction. The program signs the apply and the transfer with its PDA. Checks the same as
 * transfer() before building anything.
 */
export async function prepareTransfer(input: PrepareTransferInput): Promise<Instruction[]> {
  const operation = "prepareTransfer";
  await ensureZk();
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const amount = BigInt(input.amount);
  if (amount <= 0n) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `${operation}: the amount must be greater than zero, got ${amount}.`, { operation });
  }
  const [source, dest, mint] = await Promise.all([
    readConfiguredAccount(input.rpc, input.sourceToken, operation, "the source"),
    readConfiguredAccount(input.rpc, input.destinationToken, operation, "the recipient's"),
    readMint(input.rpc, input.mint, operation),
  ]);
  assertMintAllows(mint.data, input.mint, operation, "transfer");
  assertNotFrozen(source.data, input.sourceToken, operation, "the source");
  assertNotFrozen(dest.data, input.destinationToken, operation, "the recipient's");
  assertCanReceive(dest.ct, input.destinationToken, operation, "the recipient's");
  if (source.data.owner !== input.authority) {
    throw new ConfidentialTransfersError(
      "INVALID_INPUT",
      `${operation}: ${input.sourceToken} belongs to ${source.data.owner}, not to ${input.authority}.`,
      { operation },
    );
  }
  if (input.destinationElgamalPubkey != null && dest.ct.elgamalPubkey !== input.destinationElgamalPubkey) {
    throw new ConfidentialTransfersError(
      "RECIPIENT_KEY_MISMATCH",
      `${operation}: the RPC reports ElGamal key ${dest.ct.elgamalPubkey} for ${input.destinationToken}, not the pinned ` +
        `${input.destinationElgamalPubkey}. Nothing was encrypted.`,
      { operation },
    );
  }
  assertKeysMatchAccount(input.keys, source.data, input.sourceToken, operation);
  const transferHookAccounts = await resolveTransferHookAccounts({
    rpc: input.rpc,
    mint: input.mint,
    sourceToken: input.sourceToken,
    destinationToken: input.destinationToken,
    owner: input.authority,
    programAddress,
  });
  const ct = mintExtension(mint.data, "ConfidentialTransferMint");
  const auditorElgamalPubkey = ct && isSome(ct.auditorElgamalPubkey) ? ct.auditorElgamalPubkey.value : undefined;
  const applied = input.applyPending === false ? undefined : pendingToApply(source.ct, input.keys, input.sourceToken, operation);
  return getConfidentialTransferInlineInstructions({
    payer: input.payer,
    rpc: input.rpc,
    sourceToken: input.sourceToken,
    mint: input.mint,
    destinationToken: input.destinationToken,
    sourceTokenAccount: source.data,
    destinationTokenAccount: dest.data,
    authority: input.authority,
    amount,
    sourceElgamalKeypair: input.keys.elgamalKeypair,
    aesKey: input.keys.aesKey,
    auditorElgamalPubkey,
    transferHookAccounts,
    programAddress,
    applied,
  });
}

export type PrepareWithdrawInput = {
  rpc: Rpc<SolanaRpcApi>;
  payer: TransactionSigner;
  mint: Address;
  /** The program-owned account. */
  token: Address;
  /** The PDA that owns it. */
  authority: Address;
  /** Base units to move to the public balance. 0 makes a checked apply (see below). */
  amount: number | bigint;
  keys: ConfidentialKeypairs;
  /** Apply what is pending first, in the same transaction (default `true`). */
  applyPending?: boolean;
  programAddress?: Address;
};

/**
 * A withdrawal from a program-owned account's confidential balance to its public balance: the
 * apply (when something is pending), the two proofs and the `Withdraw`, for one v1 transaction.
 * With `amount` 0 it is a checked apply, as applyPendingBalance() makes: the withdrawal of zero
 * proves the balance the apply leaves, so a credit landing in between makes Token-2022 refuse the
 * whole transaction rather than leave the account's two copies of its balance apart.
 */
export async function prepareWithdraw(input: PrepareWithdrawInput): Promise<Instruction[]> {
  const operation = "prepareWithdraw";
  await ensureZk();
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const amount = BigInt(input.amount);
  if (amount < 0n) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `${operation}: the amount cannot be negative, got ${amount}.`, { operation });
  }
  const [{ data, ct }, mint] = await Promise.all([
    readConfiguredAccount(input.rpc, input.token, operation, "the"),
    readMint(input.rpc, input.mint, operation),
  ]);
  assertMintAllows(mint.data, input.mint, operation, "withdraw");
  assertNotFrozen(data, input.token, operation, "the");
  if (data.owner !== input.authority) {
    throw new ConfidentialTransfersError(
      "INVALID_INPUT",
      `${operation}: ${input.token} belongs to ${data.owner}, not to ${input.authority}.`,
      { operation },
    );
  }
  assertKeysMatchAccount(input.keys, data, input.token, operation);
  const applied = input.applyPending === false ? undefined : pendingToApply(ct, input.keys, input.token, operation);
  return getConfidentialWithdrawInlineInstructions({
    payer: input.payer,
    rpc: input.rpc,
    token: input.token,
    mint: input.mint,
    tokenAccount: data,
    authority: input.authority,
    amount,
    allowZero: true,
    decimals: mint.data.decimals,
    elgamalKeypair: input.keys.elgamalKeypair,
    aesKey: input.keys.aesKey,
    programAddress,
    applied,
  });
}

export type PrepareApplyInput = {
  rpc: Rpc<SolanaRpcApi>;
  /** The program-owned account. */
  token: Address;
  /** The PDA that owns it. */
  authority: Address;
  keys: ConfidentialKeypairs;
  programAddress?: Address;
};

export type PreparedApply = {
  /** The `ApplyPendingBalance` instruction, or none when nothing is pending. */
  instructions: Instruction[];
  /** The available balance once applied, in base units. */
  value: bigint;
  /**
   * The ElGamal ciphertext of the available balance once applied (64 bytes), for a proof that has
   * to be about it, such as a zero-ciphertext proof of the balance in a supply report.
   */
  availableBalance: Uint8Array;
};

/**
 * Apply a program-owned account's pending balance, and say what its available balance will be.
 * On its own an apply is not checked: a credit that lands between the read and the transaction is
 * applied without being in the AES copy written. Put it in the same transaction as an instruction
 * whose proof is about `availableBalance` (prepareWithdraw with amount 0 does that), so that such
 * a credit makes Token-2022 refuse the whole transaction.
 */
export async function prepareApply(input: PrepareApplyInput): Promise<PreparedApply> {
  const operation = "prepareApply";
  await ensureZk();
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const { data, ct } = await readConfiguredAccount(input.rpc, input.token, operation, "the");
  if (data.owner !== input.authority) {
    throw new ConfidentialTransfersError(
      "INVALID_INPUT",
      `${operation}: ${input.token} belongs to ${data.owner}, not to ${input.authority}.`,
      { operation },
    );
  }
  assertKeysMatchAccount(input.keys, data, input.token, operation);
  const applied = applyPendingLocally(ct, input.keys, input.token, operation);
  return {
    instructions: hasPendingCredits(ct) ? [getApplyInstruction(input.token, input.authority, applied, programAddress)] : [],
    value: applied.value,
    availableBalance: hasPendingCredits(ct) ? applied.availableBalance : new Uint8Array(ct.availableBalance),
  };
}
