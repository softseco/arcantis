// SPDX-License-Identifier: BUSL-1.1
//
// Confidential-balances key derivation.
//
// The ElGamal key (balance and amount encryption) and the AES key (the
// `decryptable_available_balance` fast path) are derived from a single ed25519
// signature over the constant message `solana-conf-bal/v1`, expanded through a
// shared HKDF-SHA512 chain. The derivation is bound to the signing wallet
// alone: one ElGamal keypair and one AES key across every mint and token
// account the wallet owns, byte-identical to what the Rust `solana-zk-sdk`,
// the Token-2022 clients and every other standard client derive for the same
// wallet. Keys are therefore recoverable from the wallet and never stored.
//
// Before 2.0.0 this SDK scoped keys by (owner, mint) while its Rust twin
// scoped them by token account. Both schemes are superseded, and because they
// disagreed, an account configured with one could not be read with the other.
// Accounts configured by 1.x must be re-configured; see CHANGELOG.md.
import {
  createSignableMessage,
  getAddressDecoder,
  getAddressEncoder,
  isMessageModifyingSigner,
  isMessagePartialSigner,
  type Address,
  type MessageSigner,
  type ReadonlyUint8Array,
} from "@solana/kit";
import { ed25519 } from "@noble/curves/ed25519";

import { ConfidentialTransfersError } from "./errors";
import { KEY_DERIVATION_SCHEME } from "./formats";
import { AeKey, ConfidentialKeys, ElGamalKeypair, assertZkReady, ensureZk } from "./internal/zk";

/** Public ElGamal key (as an Address) plus the 32-byte ElGamal secret key. */
export type DerivedElGamalKeypair = Readonly<{
  elgamalPubkey: Address;
  secretKey: Uint8Array;
}>;

/** The WASM zk-sdk key objects consumed by the confidential-transfer builders. */
export type ConfidentialKeypairs = Readonly<{
  elgamalKeypair: ElGamalKeypair;
  aesKey: AeKey;
}>;

async function signDerivationMessage(signer: MessageSigner, message: Uint8Array): Promise<Uint8Array> {
  const signable = createSignableMessage(message);
  let signed;
  if (isMessagePartialSigner(signer)) {
    [signed] = await signer.signMessages([signable]);
  } else if (isMessageModifyingSigner(signer)) {
    // A browser wallet (Wallet Standard `solana:signMessage`) signs through this interface. The
    // keys come from the signature over this exact message, so a changed message is an error.
    const [modified] = await signer.modifyAndSignMessages([signable]);
    if (!sameBytes(modified?.content, message)) {
      throw new ConfidentialTransfersError(
        "BAD_MESSAGE_SIGNATURE",
        `Wallet ${signer.address} changed the message it was asked to sign, so the confidential ` +
          "keys would not match the standard derivation. Use a wallet that signs messages as given.",
      );
    }
    signed = modified.signatures;
  } else {
    throw new ConfidentialTransfersError(
      "CANNOT_SIGN_MESSAGES",
      `Signer ${(signer as { address?: string }).address} cannot sign messages, and the ` +
        "confidential keys come from a message signature. With a browser wallet, use one that " +
        "supports signMessage (Wallet Standard `solana:signMessage`).",
    );
  }
  const signature = (signed as Record<string, Uint8Array | undefined> | undefined)?.[signer.address];
  if (signature == null) {
    throw new ConfidentialTransfersError("BAD_MESSAGE_SIGNATURE", `Signer ${signer.address} did not return a signature`);
  }
  // Keys from a signature that does not verify would be keys nobody can derive again.
  const publicKey = new Uint8Array(getAddressEncoder().encode(signer.address));
  if (!ed25519.verify(new Uint8Array(signature), message, publicKey)) {
    throw new ConfidentialTransfersError(
      "BAD_MESSAGE_SIGNATURE",
      `Signer ${signer.address} returned a signature that does not verify against its address`,
    );
  }
  return new Uint8Array(signature);
}

function sameBytes(a: ReadonlyUint8Array | undefined, b: Uint8Array): boolean {
  if (!a || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * `message`, the derivation message the zk-sdk builds for `publicSeed`, once it is checked to be
 * {@link KEY_DERIVATION_SCHEME} followed by the seed. Keys come from the signature over this
 * message, so a library that signed anything else would give the same wallet different keys:
 * not the keys its accounts are configured with, and not the keys other clients derive.
 * Throws UNSUPPORTED_FORMAT instead.
 *
 * @internal Exported for the tests; not part of the package's API.
 */
export function checkDerivationMessage(message: Uint8Array, publicSeed: Uint8Array): Uint8Array {
  const scheme = new TextEncoder().encode(KEY_DERIVATION_SCHEME);
  const expected = new Uint8Array(scheme.length + publicSeed.length);
  expected.set(scheme, 0);
  expected.set(publicSeed, scheme.length);
  if (!sameBytes(message, expected)) {
    throw new ConfidentialTransfersError(
      "UNSUPPORTED_FORMAT",
      `The installed @solana/zk-sdk derives keys from a message other than ${KEY_DERIVATION_SCHEME}` +
        (publicSeed.length ? " followed by the seed" : "") +
        ". Keys derived that way would not match the accounts configured so far, so this release " +
        "refuses to derive them. Use the @solana/zk-sdk version this release depends on.",
    );
  }
  return message;
}

async function confidentialKeysFrom(
  signer: MessageSigner,
  message: Uint8Array,
): Promise<ConfidentialKeypairs> {
  await ensureZk();
  const keys = ConfidentialKeys.fromSignature(await signDerivationMessage(signer, message));
  return { elgamalKeypair: keys.elgamal(), aesKey: keys.ae() };
}

/**
 * Derive the wallet's confidential-balances keys: the standard derivation.
 *
 * One signature over `solana-conf-bal/v1` yields both keys. Use this unless you
 * have a specific reason not to — it is what every other standard client
 * derives for the same wallet, so an account configured here can also be read
 * by the spl-token CLI and by wallets that implement the standard.
 */
export async function deriveConfidentialKeys(input: {
  signer: MessageSigner;
}): Promise<ConfidentialKeypairs> {
  await ensureZk();
  return confidentialKeysFrom(input.signer, checkDerivationMessage(ConfidentialKeys.signerMessage(), new Uint8Array()));
}

/**
 * Derive seed-scoped confidential-balances keys: a non-standard derivation.
 *
 * The signed message becomes `solana-conf-bal/v1 || publicSeed`. Keys derived
 * from a non-empty seed will NOT match the standard keys other clients derive
 * for the same wallet, so use this only for schemes that genuinely need keys
 * scoped more finely than the wallet — single-signer PDA wallets (pass
 * {@link pdaWalletPublicSeed}) or custom application keying.
 */
export async function deriveConfidentialKeysWithSeed(input: {
  signer: MessageSigner;
  publicSeed: ReadonlyUint8Array;
}): Promise<ConfidentialKeypairs> {
  await ensureZk();
  const seed = new Uint8Array(input.publicSeed);
  return confidentialKeysFrom(input.signer, checkDerivationMessage(ConfidentialKeys.signerMessageWithSeed(seed), seed));
}

/**
 * The canonical `publicSeed` for a single-signer PDA wallet, as
 * `programId || walletPda || mint || tokenAccount`. Pass the result to
 * {@link deriveConfidentialKeysWithSeed} so PDA wallets use one seed
 * convention across implementations.
 */
export function pdaWalletPublicSeed(input: {
  programId: Address;
  walletPda: Address;
  mint: Address;
  tokenAccount: Address;
}): Uint8Array {
  assertZkReady("pdaWalletPublicSeed");
  const encode = (address: Address) => new Uint8Array(getAddressEncoder().encode(address));
  return ConfidentialKeys.pdaWalletPublicSeed(
    encode(input.programId),
    encode(input.walletPda),
    encode(input.mint),
    encode(input.tokenAccount),
  );
}

/** An ElGamal public key as an Address, ready for a mint or account config. */
export function getElGamalPubkeyAddress(keypair: ElGamalKeypair): Address {
  assertZkReady("getElGamalPubkeyAddress");
  return getAddressDecoder().decode(new Uint8Array(keypair.pubkey().toBytes()));
}

/**
 * The ElGamal half of the standard derivation, with the secret key as raw
 * bytes. Prefer {@link deriveConfidentialKeys} when you need both keys: it
 * asks the wallet for one signature instead of two.
 */
export async function deriveElGamalKeypair(input: {
  signer: MessageSigner;
}): Promise<DerivedElGamalKeypair> {
  const { elgamalKeypair } = await deriveConfidentialKeys(input);
  return {
    elgamalPubkey: getElGamalPubkeyAddress(elgamalKeypair),
    secretKey: new Uint8Array(elgamalKeypair.secret().toBytes()),
  };
}

/**
 * The AES half of the standard derivation, as raw bytes. Prefer
 * {@link deriveConfidentialKeys} when you need both keys.
 */
export async function deriveAeKey(input: { signer: MessageSigner }): Promise<Uint8Array> {
  const { aesKey } = await deriveConfidentialKeys(input);
  return new Uint8Array(aesKey.toBytes());
}
