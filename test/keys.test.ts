// SPDX-License-Identifier: BUSL-1.1
//
// Unit tests for confidential-balances key derivation. No validator needed —
// this exercises the WASM ZK SDK directly.
//
// The contract under test is that every derivation path in this SDK produces
// the same wallet-level keys, and that those keys come from the standard
// `solana-conf-bal/v1` message every other client signs. Before 2.0.0 the
// TypeScript and Rust halves of this SDK seeded the derivation differently —
// (owner, mint) here, token account there — so keys written by one could not
// be read by the other. The tests below pin both the message and the output so
// that cannot recur silently.
import {
  createKeyPairSignerFromPrivateKeyBytes,
  generateKeyPairSigner,
  getAddressEncoder,
} from "@solana/kit";
import { ConfidentialKeys } from "@solana/zk-sdk/node";
import { expect } from "chai";

import {
  deriveAeKey,
  deriveConfidentialKeys,
  deriveConfidentialKeysWithSeed,
  deriveElGamalKeypair,
  pdaWalletPublicSeed,
} from "../src/keys";

/** The exact bytes of `solana-conf-bal/v1`. */
const STANDARD_DERIVATION_MESSAGE = new Uint8Array([
  115, 111, 108, 97, 110, 97, 45, 99, 111, 110, 102, 45, 98, 97, 108, 47, 118, 49,
]);

// Pinned vector: private key bytes 1..32, standard (no-seed) derivation.
const VECTOR_PRIVATE_KEY = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1));
const VECTOR_ELGAMAL_SECRET_KEY = new Uint8Array([
  18, 9, 170, 121, 195, 51, 117, 115, 170, 156, 1, 205, 213, 187, 10, 37, 32, 121, 194, 13, 155,
  15, 88, 37, 156, 188, 30, 250, 119, 108, 238, 6,
]);
const VECTOR_AE_KEY = new Uint8Array([
  95, 104, 35, 1, 89, 137, 42, 78, 42, 160, 111, 199, 94, 5, 99, 223,
]);

const bytes = (u: Uint8Array | ArrayLike<number>) => Array.from(u);

describe("confidential-balances key derivation", () => {
  it("signs the standard message `solana-conf-bal/v1`", () => {
    expect(bytes(ConfidentialKeys.signerMessage())).to.deep.equal(
      bytes(STANDARD_DERIVATION_MESSAGE),
    );
    expect(Buffer.from(ConfidentialKeys.signerMessage()).toString("utf8")).to.equal(
      "solana-conf-bal/v1",
    );
  });

  it("derives a 32-byte ElGamal secret key and a 16-byte AES key", async () => {
    const signer = await generateKeyPairSigner();
    const { secretKey } = await deriveElGamalKeypair({ signer });
    const aeKey = await deriveAeKey({ signer });
    expect(secretKey.length).to.equal(32);
    expect(aeKey.length).to.equal(16);
    expect(secretKey.every((b) => b === 0)).to.equal(false);
    expect(aeKey.every((b) => b === 0)).to.equal(false);
  });

  it("is deterministic for the same signer", async () => {
    const signer = await generateKeyPairSigner();
    const a = await deriveConfidentialKeys({ signer });
    const b = await deriveConfidentialKeys({ signer });
    expect(bytes(a.elgamalKeypair.secret().toBytes())).to.deep.equal(
      bytes(b.elgamalKeypair.secret().toBytes()),
    );
    expect(bytes(a.aesKey.toBytes())).to.deep.equal(bytes(b.aesKey.toBytes()));
  });

  it("differs between wallets", async () => {
    const [one, two] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
    const a = await deriveConfidentialKeys({ signer: one });
    const b = await deriveConfidentialKeys({ signer: two });
    expect(bytes(a.elgamalKeypair.secret().toBytes())).to.not.deep.equal(
      bytes(b.elgamalKeypair.secret().toBytes()),
    );
  });

  // The regression test for the 1.x drift: every derivation path must agree.
  it("agrees across every derivation helper", async () => {
    const signer = await generateKeyPairSigner();
    const both = await deriveConfidentialKeys({ signer });
    const elgamalOnly = await deriveElGamalKeypair({ signer });
    const aeOnly = await deriveAeKey({ signer });
    expect(bytes(elgamalOnly.secretKey)).to.deep.equal(
      bytes(both.elgamalKeypair.secret().toBytes()),
    );
    expect(bytes(aeOnly)).to.deep.equal(bytes(both.aesKey.toBytes()));
  });

  it("scopes seeded keys away from the standard keys", async () => {
    const signer = await generateKeyPairSigner();
    const standard = await deriveConfidentialKeys({ signer });
    const seedA = await deriveConfidentialKeysWithSeed({
      signer,
      publicSeed: new Uint8Array([1, 2, 3, 4]),
    });
    const seedB = await deriveConfidentialKeysWithSeed({
      signer,
      publicSeed: new Uint8Array([4, 3, 2, 1]),
    });
    const secret = (k: typeof standard) => bytes(k.elgamalKeypair.secret().toBytes());
    expect(secret(seedA)).to.not.deep.equal(secret(standard));
    expect(secret(seedA)).to.not.deep.equal(secret(seedB));
  });

  it("matches the pinned standard derivation vector", async () => {
    const signer = await createKeyPairSignerFromPrivateKeyBytes(VECTOR_PRIVATE_KEY);
    const { elgamalKeypair, aesKey } = await deriveConfidentialKeys({ signer });
    expect(bytes(elgamalKeypair.secret().toBytes())).to.deep.equal(bytes(VECTOR_ELGAMAL_SECRET_KEY));
    expect(bytes(aesKey.toBytes())).to.deep.equal(bytes(VECTOR_AE_KEY));
  });

  it("builds the canonical PDA-wallet seed as programId || walletPda || mint || tokenAccount", async () => {
    const [programId, walletPda, mint, tokenAccount] = await Promise.all([
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
      generateKeyPairSigner(),
    ]);
    const seed = pdaWalletPublicSeed({
      programId: programId.address,
      walletPda: walletPda.address,
      mint: mint.address,
      tokenAccount: tokenAccount.address,
    });
    const encoder = getAddressEncoder();
    const expected = [programId, walletPda, mint, tokenAccount].flatMap((s) =>
      Array.from(encoder.encode(s.address)),
    );
    expect(seed.length).to.equal(128);
    expect(bytes(seed)).to.deep.equal(expected);
  });
});
