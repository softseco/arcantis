// SPDX-License-Identifier: BUSL-1.1
//
// The available balance an SDK call works from.
//
// Token-2022 keeps a confidential account's available balance twice: ElGamal-encrypted
// (`availableBalance`, what the proofs are about) and AES-encrypted
// (`decryptableAvailableBalance`, the copy the owner can decrypt quickly). The owner writes the AES
// copy with every apply, transfer and withdraw. The two can drift apart: ApplyPendingBalance adds
// everything pending when it runs, including a deposit or transfer that arrived after the owner
// read the account, while the AES copy it writes was computed without that credit. Token-2022 does
// not refuse such an apply; it records the expected and actual credit counters and carries on. An
// account that receives many payments hits this in normal use.
//
// Proofs built from a stale AES copy are refused on chain, so every call that reads the available
// balance first checks the AES copy against the ElGamal balance. When they differ, the difference
// is what the AES copy missed. It is recovered by decrypting the ElGamal balance minus the AES
// value, which works while the missed credits add up to less than 2^32 base units. The call then
// works from the corrected value, and a transfer, withdraw or apply writes a corrected AES copy,
// which repairs the account.
import { type Address, type ReadonlyUint8Array } from "@solana/kit";
import { ristretto255 } from "@noble/curves/ed25519";

import { ConfidentialTransfersError } from "../errors";
import type { ConfidentialKeypairs } from "../keys";
import { subtractAmountFromCiphertext } from "./confidentialTransferArithmetic";
import { AeCiphertext, ElGamalCiphertext } from "./zk";

const { Point } = /* @__PURE__ */ ristretto255;

/** The two encrypted copies of an account's available balance, as Token-2022 stores them. */
export type AvailableBalanceCiphertexts = {
  availableBalance: ReadonlyUint8Array;
  decryptableAvailableBalance: ReadonlyUint8Array;
};

function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) + BigInt(bytes[i]!);
  return value;
}

/**
 * True if the ElGamal ciphertext holds `amount` for this secret key. An ElGamal ciphertext is a
 * commitment C = amount·G + r·H and a handle D = r·P, with P = s⁻¹·H, so C − s·D = amount·G.
 * Point arithmetic only: no discrete log, so it costs about a millisecond.
 */
export function ciphertextHolds(ciphertext: ReadonlyUint8Array, secretKey: Uint8Array, amount: bigint): boolean {
  if (ciphertext.length !== 64) return false;
  try {
    const commitment = Point.fromHex(new Uint8Array(ciphertext.slice(0, 32)));
    const handle = Point.fromHex(new Uint8Array(ciphertext.slice(32, 64)));
    const decrypted = commitment.subtract(handle.multiply(littleEndian(secretKey)));
    return decrypted.equals(amount === 0n ? Point.ZERO : Point.BASE.multiply(amount));
  } catch {
    return false; // not a valid encoding
  }
}

function decryptAes(bytes: ReadonlyUint8Array, keys: ConfidentialKeypairs): bigint | undefined {
  const ciphertext = AeCiphertext.fromBytes(new Uint8Array(bytes));
  if (!ciphertext) return undefined;
  try {
    return keys.aesKey.decrypt(ciphertext);
  } catch {
    return undefined;
  }
}

/**
 * The account's available balance. Normally the AES copy; if that copy has fallen behind the
 * ElGamal balance (see the top of this file), the AES value plus what it missed. Throws
 * BALANCE_OUT_OF_SYNC when the difference cannot be recovered.
 */
export function readAvailableBalance(
  account: AvailableBalanceCiphertexts,
  keys: ConfidentialKeypairs,
  token: Address,
  operation: string,
): bigint {
  const secretKey = keys.elgamalKeypair.secret().toBytes();
  const copy = decryptAes(account.decryptableAvailableBalance, keys);
  if (copy !== undefined && ciphertextHolds(account.availableBalance, secretKey, copy)) return copy;

  // The AES copy is missing something (or unreadable). Decrypt what the ElGamal balance holds
  // beyond it; a discrete log, so only differences below 2^32 can be found.
  const base = copy ?? 0n;
  let missed: bigint | undefined;
  try {
    const rest = base === 0n ? new Uint8Array(account.availableBalance) : subtractAmountFromCiphertext(account.availableBalance, base);
    const restCiphertext = ElGamalCiphertext.fromBytes(rest);
    if (restCiphertext) missed = keys.elgamalKeypair.secret().decrypt(restCiphertext);
  } catch {
    missed = undefined; // more than a 32-bit discrete log finds, or the copy is ahead
  }
  if (missed === undefined) {
    throw new ConfidentialTransfersError(
      "BALANCE_OUT_OF_SYNC",
      `${operation}: the AES copy of the available balance of ${token} ` +
        (copy === undefined ? "cannot be decrypted" : "does not match the encrypted balance") +
        ", and the difference is too large to recover here (2^32 base units or more). This happens when " +
        "deposits or transfers arrive while applyPendingBalance runs. The funds are in the encrypted " +
        "balance; only the copy the SDK reads them from is out of date.",
      { operation },
    );
  }
  return base + missed;
}
