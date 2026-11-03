// SPDX-License-Identifier: BUSL-1.1
//
// The shared test vectors in test-vectors/confidential-transfers.json, which the Rust crate's
// tests/vectors.rs checks too. If the two SDKs drift apart in key derivation, the PDA-wallet seed
// or how an auditor reads an amount, one of the two suites fails.
import { readFileSync } from "node:fs";
import path from "node:path";

import { address, createKeyPairSignerFromPrivateKeyBytes } from "@solana/kit";
import { AeCiphertext, ElGamalCiphertext } from "@solana/zk-sdk/node";
import { expect } from "chai";

import { deriveAuditorElgamalKeypair } from "../src/auditor";
import { deriveConfidentialKeys, deriveConfidentialKeysWithSeed, pdaWalletPublicSeed } from "../src/keys";

type Hex = string;
const vectors = JSON.parse(
  readFileSync(path.resolve(__dirname, "../test-vectors/confidential-transfers.json"), "utf8"),
) as {
  standardDerivation: { walletPrivateKey: Hex; elgamalSecretKey: Hex; elgamalPubkey: Hex; aeKey: Hex }[];
  pdaWalletDerivation: {
    operatorPrivateKey: Hex;
    programId: string;
    walletPda: string;
    mint: string;
    tokenAccount: string;
    publicSeed: Hex;
    elgamalSecretKey: Hex;
    aeKey: Hex;
  };
  auditorTransferAmount: { auditorWalletPrivateKey: Hex; ciphertextLo: Hex; ciphertextHi: Hex; amount: string };
  decryptableBalance: { ownerWalletPrivateKey: Hex; ciphertext: Hex; amount: string };
};

const fromHex = (hex: Hex) => new Uint8Array(Buffer.from(hex, "hex"));
const toHex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const wallet = (hex: Hex) => createKeyPairSignerFromPrivateKeyBytes(fromHex(hex));

describe("shared test vectors (same file as the Rust crate)", () => {
  it("standard key derivation", async () => {
    for (const v of vectors.standardDerivation) {
      const { elgamalKeypair, aesKey } = await deriveConfidentialKeys({ signer: await wallet(v.walletPrivateKey) });
      expect(toHex(elgamalKeypair.secret().toBytes())).to.equal(v.elgamalSecretKey);
      expect(toHex(elgamalKeypair.pubkey().toBytes())).to.equal(v.elgamalPubkey);
      expect(toHex(aesKey.toBytes())).to.equal(v.aeKey);
    }
  });

  it("PDA-wallet seed and keys", async () => {
    const v = vectors.pdaWalletDerivation;
    const publicSeed = pdaWalletPublicSeed({
      programId: address(v.programId),
      walletPda: address(v.walletPda),
      mint: address(v.mint),
      tokenAccount: address(v.tokenAccount),
    });
    expect(toHex(publicSeed)).to.equal(v.publicSeed);
    const { elgamalKeypair, aesKey } = await deriveConfidentialKeysWithSeed({
      signer: await wallet(v.operatorPrivateKey),
      publicSeed,
    });
    expect(toHex(elgamalKeypair.secret().toBytes())).to.equal(v.elgamalSecretKey);
    expect(toHex(aesKey.toBytes())).to.equal(v.aeKey);
  });

  it("an auditor reads a transfer amount from its two halves", async () => {
    const v = vectors.auditorTransferAmount;
    const auditor = await deriveAuditorElgamalKeypair(await wallet(v.auditorWalletPrivateKey));
    const secret = auditor.secret();
    const lo = secret.decrypt(ElGamalCiphertext.fromBytes(fromHex(v.ciphertextLo))!);
    const hi = secret.decrypt(ElGamalCiphertext.fromBytes(fromHex(v.ciphertextHi))!);
    expect((lo + (hi << 16n)).toString()).to.equal(v.amount);
  });

  it("the owner reads the AES copy of the available balance", async () => {
    const v = vectors.decryptableBalance;
    const { aesKey } = await deriveConfidentialKeys({ signer: await wallet(v.ownerWalletPrivateKey) });
    expect(aesKey.decrypt(AeCiphertext.fromBytes(fromHex(v.ciphertext))!).toString()).to.equal(v.amount);
  });
});
