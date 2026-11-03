// SPDX-License-Identifier: BUSL-1.1
//
// Auditor-key selective disclosure.
//
// A Token-2022 mint can designate an auditor ElGamal public key. When set, every
// confidential transfer on that mint additionally encrypts the transferred amount
// to the auditor. The auditor — and only the auditor — can then recover those
// amounts with its ElGamal secret key, without being able to spend or affecting
// the confidentiality of balances for anyone else. This is the "selective
// disclosure" pattern: privacy by default, auditability by designation.
import {
  getAddressDecoder,
  getBase58Encoder,
  type Address,
  type MessageSigner,
  type Rpc,
  type Signature,
  type SolanaRpcApi,
} from "@solana/kit";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  getConfidentialTransferInstructionDataDecoder,
} from "@solana-program/token-2022";
import { ConfidentialTransfersError } from "./errors";
import { ElGamalCiphertext, ElGamalKeypair, assertZkReady, ensureZk } from "./internal/zk";

import { deriveConfidentialKeys } from "./keys";

const TRANSFER_AMOUNT_LO_BIT_LENGTH = 16n;

// A Token-2022 confidential-transfer instruction's data begins with the extension
// discriminator (27) followed by the inner ConfidentialTransfer discriminator (7).
const CONFIDENTIAL_TRANSFER_DISCRIMINATOR = 27;
const CONFIDENTIAL_TRANSFER_INNER_DISCRIMINATOR = 7;

/**
 * Derive the auditor's ElGamal keypair from its wallet signer. The key is
 * mint-independent (one auditor identity can audit any mint that designates it),
 * so it is recoverable from the wallet alone and never needs to be stored.
 */
export async function deriveAuditorElgamalKeypair(signer: MessageSigner): Promise<ElGamalKeypair> {
  const { elgamalKeypair } = await deriveConfidentialKeys({ signer });
  return elgamalKeypair;
}

/** The auditor's ElGamal public key as an Address, for a mint's confidential-transfer config. */
export function getAuditorElgamalPubkey(auditorKeypair: ElGamalKeypair): Address {
  assertZkReady("getAuditorElgamalPubkey");
  return getAddressDecoder().decode(new Uint8Array(auditorKeypair.pubkey().toBytes()));
}

export type DecryptTransferAmountAsAuditorInput = {
  rpc: Rpc<SolanaRpcApi>;
  /** Signature of a confirmed transaction containing the confidential transfer. */
  signature: Signature;
  auditorKeypair: ElGamalKeypair;
  /**
   * Read only a confidential transfer of this mint. Without it, the first confidential transfer
   * in the transaction is read, whatever its mint.
   */
  mint?: Address;
  programAddress?: Address;
};

type FetchedInstruction = { programIdIndex: number; accounts?: readonly number[]; data: string };
type FetchedTransactionMessage = {
  transaction: {
    message: {
      accountKeys?: readonly string[];
      staticAccountKeys?: readonly string[];
      instructions: readonly FetchedInstruction[];
    };
  };
  meta?: {
    err: unknown;
    innerInstructions?: ReadonlyArray<{ index: number; instructions: readonly FetchedInstruction[] }> | null;
    loadedAddresses?: { writable: readonly string[]; readonly: readonly string[] } | null;
  } | null;
};

/**
 * Recover the amount of a confidential transfer as the mint's auditor: decode the
 * confidential-transfer instruction from the confirmed transaction (made directly, or by a program
 * through a cross-program call) and decrypt the auditor ciphertext (lo/hi halves) with the
 * auditor's ElGamal secret key. A transaction that failed transferred nothing, so it is refused
 * with TRANSACTION_FAILED rather than read.
 *
 * A transaction can hold more than one confidential transfer. With `mint`, the first one of that
 * mint is read; without it, the first one of any mint, in instruction order (each instruction
 * followed by the calls it made). An amount the key cannot decrypt (it was encrypted to another
 * auditor key) is DECRYPTION_FAILED. For every transfer of a mint, see
 * {@link listConfidentialActivity}.
 */
export async function decryptTransferAmountAsAuditor(
  input: DecryptTransferAmountAsAuditorInput,
): Promise<bigint> {
  const operation = "decryptTransferAmountAsAuditor";
  await ensureZk();
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const result = await input.rpc
    .getTransaction(input.signature, {
      commitment: "confirmed",
      encoding: "json",
      maxSupportedTransactionVersion: 1,
    })
    .send();
  if (result == null) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `decryptTransferAmountAsAuditor: transaction ${input.signature} not found`, {
      operation: "decryptTransferAmountAsAuditor",
    });
  }

  const fetched = result as unknown as FetchedTransactionMessage;
  if (fetched.meta?.err) {
    throw new ConfidentialTransfersError(
      "TRANSACTION_FAILED",
      `decryptTransferAmountAsAuditor: transaction ${input.signature} failed on chain, so it transferred nothing`,
      { operation: "decryptTransferAmountAsAuditor" },
    );
  }
  const message = fetched.transaction.message;
  // Instructions of a version-0 transaction can name accounts from address lookup tables, which
  // follow the transaction's own accounts.
  const accountKeys = [
    ...(message.accountKeys ?? message.staticAccountKeys ?? []),
    ...(fetched.meta?.loadedAddresses?.writable ?? []),
    ...(fetched.meta?.loadedAddresses?.readonly ?? []),
  ];
  const inner = new Map((fetched.meta?.innerInstructions ?? []).map((group) => [group.index, group.instructions]));
  const instructions = message.instructions.flatMap((instruction, i) => [instruction, ...(inner.get(i) ?? [])]);
  const base58 = getBase58Encoder();
  const secret = input.auditorKeypair.secret();

  for (const instruction of instructions) {
    if (accountKeys[instruction.programIdIndex] !== programAddress) continue;
    const data = new Uint8Array(base58.encode(instruction.data));
    if (
      data[0] !== CONFIDENTIAL_TRANSFER_DISCRIMINATOR ||
      data[1] !== CONFIDENTIAL_TRANSFER_INNER_DISCRIMINATOR
    ) {
      continue;
    }
    // The mint is the transfer instruction's second account, in every client.
    const mintIndex = instruction.accounts?.[1];
    if (input.mint !== undefined && (mintIndex === undefined || accountKeys[mintIndex] !== input.mint)) continue;

    const decoded = getConfidentialTransferInstructionDataDecoder().decode(data);
    const lo = ElGamalCiphertext.fromBytes(new Uint8Array(decoded.transferAmountAuditorCiphertextLo));
    const hi = ElGamalCiphertext.fromBytes(new Uint8Array(decoded.transferAmountAuditorCiphertextHi));
    if (!lo || !hi) {
      throw new ConfidentialTransfersError("DECRYPTION_FAILED", `${operation}: failed to parse the auditor ciphertext`, { operation });
    }
    try {
      return secret.decrypt(lo) + (secret.decrypt(hi) << TRANSFER_AMOUNT_LO_BIT_LENGTH);
    } catch (e) {
      // The zk-sdk throws a plain string here.
      throw new ConfidentialTransfersError(
        "DECRYPTION_FAILED",
        `${operation}: this auditor key cannot decrypt the amount of the transfer in ${input.signature}; it was ` +
          "encrypted to another auditor key (the mint's auditor key may have changed since).",
        { operation, cause: e },
      );
    }
  }

  throw new ConfidentialTransfersError(
    "INVALID_INPUT",
    `${operation}: no confidential-transfer instruction ${input.mint === undefined ? "" : `of mint ${input.mint} `}found in this transaction`,
    { operation },
  );
}
