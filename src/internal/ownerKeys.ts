// SPDX-License-Identifier: BUSL-1.1
//
// Where an SDK call gets the owner's confidential keys: the `keys` the caller passed, or else one
// message signature from the owner. A browser app derives the keys once with
// deriveConfidentialKeys() and passes them to every call, so the wallet asks to sign the key
// message once per session instead of once per call.
import { isMessageSigner, isSome, type Address, type MessageSigner } from "@solana/kit";
import type { Token } from "@solana-program/token-2022";

import { ConfidentialTransfersError } from "../errors";
import { deriveConfidentialKeys, getElGamalPubkeyAddress, type ConfidentialKeypairs } from "../keys";
import { ensureZk } from "./zk";

export async function ownerKeys(
  owner: { readonly address: Address },
  keys: ConfidentialKeypairs | undefined,
  operation: string,
): Promise<ConfidentialKeypairs> {
  await ensureZk();
  if (keys) return keys;
  if (!isMessageSigner(owner as { address: Address; [key: string]: unknown })) {
    throw new ConfidentialTransfersError(
      "CANNOT_SIGN_MESSAGES",
      `${operation}: the owner ${owner.address} cannot sign messages, and no \`keys\` were passed. ` +
        "The confidential keys come from the owner's signature over a fixed message, so either use " +
        "a signer that can sign messages (a wallet with signMessage, or a keypair signer), or " +
        "derive the keys once with deriveConfidentialKeys({ signer }) and pass them as `keys`.",
      { operation },
    );
  }
  return deriveConfidentialKeys({ signer: owner as MessageSigner });
}

/**
 * Throws unless `keys` are the keys the token account is configured with, so that keys for the
 * wrong wallet are caught before any proof is built or anything is decrypted. Does nothing when
 * the account has no confidential-transfer extension; the caller reports that.
 */
export function assertKeysMatchAccount(
  keys: ConfidentialKeypairs,
  account: Pick<Token, "extensions">,
  token: Address,
  operation: string,
): void {
  if (!isSome(account.extensions)) return;
  const ct = account.extensions.value.find((e) => e.__kind === "ConfidentialTransferAccount");
  if (!ct) return;
  const ours = getElGamalPubkeyAddress(keys.elgamalKeypair);
  if (ours !== ct.elgamalPubkey) {
    throw new ConfidentialTransfersError(
      "KEYS_MISMATCH",
      `${operation}: these confidential keys (ElGamal public key ${ours}) are not the keys token ` +
        `account ${token} is configured with (${ct.elgamalPubkey}). Derive them from the account ` +
        "owner's wallet.",
      { operation },
    );
  }
}
