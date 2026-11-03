// SPDX-License-Identifier: BUSL-1.1
//
// Validator-free unit tests. These run everywhere (including CI, which has no
// validator) and exercise the public API surface, ciphertext arithmetic,
// key-derivation variants, and the input-validation / guard branches that the
// on-chain integration tests don't reach.
import { generateKeyPairSigner, none, some } from "@solana/kit";
import { expect } from "chai";

import * as sdk from "../src/index";
import { ElGamalCiphertext, ElGamalKeypair } from "@solana/zk-sdk/node";

import {
  extractCiphertextFromGroupedBytes,
  subtractAmountFromCiphertext,
  subtractWithLoHiCiphertexts,
} from "../src/internal/confidentialTransferArithmetic";
import {
  getConfidentialTransferInstructionPlan,
  getConfidentialWithdrawInstructionPlan,
} from "../src/internal/confidentialTransferProof";
import {
  deriveAeKey,
  deriveConfidentialKeysWithSeed,
  deriveElGamalKeypair,
} from "../src/keys";
import { transfer } from "../src/transfer";
import { withdraw } from "../src/withdraw";

describe("public API", () => {
  it("exports every SDK function", () => {
    const names = [
      "configureAccount",
      "deposit",
      "applyPendingBalance",
      "decryptBalance",
      "transfer",
      "withdraw",
      "resolveTransferHookAccounts",
      "getTransferHookProgram",
      "findExtraAccountMetaListPda",
      "deriveAuditorElgamalKeypair",
      "getAuditorElgamalPubkey",
      "decryptTransferAmountAsAuditor",
      "deriveConfidentialKeys",
      "deriveConfidentialKeysWithSeed",
      "deriveElGamalKeypair",
      "deriveAeKey",
      "getElGamalPubkeyAddress",
      "pdaWalletPublicSeed",
      "initConfidentialTransfers",
      "recoverProofAccounts",
      "isConfidentialTransfersError",
      "ConfidentialTransfersError",
      "listConfidentialActivity",
      "confidentialActivityToCsv",
      "confidentialActivityToJson",
      "parseConfidentialActivityJson",
    ];
    for (const name of names) {
      expect(sdk, `missing export: ${name}`)
        .to.have.property(name)
        .that.is.a("function");
    }
  });
});

describe("ciphertext arithmetic", () => {
  it("extracts a handle's ciphertext from a grouped ciphertext", () => {
    // 32-byte commitment + three 32-byte handles = 128 bytes.
    const grouped = new Uint8Array(128);
    for (let i = 0; i < grouped.length; i++) grouped[i] = i % 251;

    const ct0 = extractCiphertextFromGroupedBytes(grouped, 0);
    expect(ct0).to.have.length(64);
    expect(Array.from(ct0.slice(0, 32))).to.deep.equal(Array.from(grouped.slice(0, 32)));
    expect(Array.from(ct0.slice(32, 64))).to.deep.equal(Array.from(grouped.slice(32, 64)));

    const ct2 = extractCiphertextFromGroupedBytes(grouped, 2);
    expect(Array.from(ct2.slice(32, 64))).to.deep.equal(Array.from(grouped.slice(96, 128)));
  });

  it("rejects a negative handle index", () => {
    expect(() => extractCiphertextFromGroupedBytes(new Uint8Array(128), -1)).to.throw(
      "non-negative integer",
    );
  });

  it("rejects a handle index beyond the grouped ciphertext", () => {
    expect(() => extractCiphertextFromGroupedBytes(new Uint8Array(64), 5)).to.throw(
      "does not contain handle",
    );
  });

  it("rejects ciphertexts that are not 64 bytes", () => {
    expect(() =>
      subtractWithLoHiCiphertexts(new Uint8Array(64), new Uint8Array(10), new Uint8Array(64), 16n),
    ).to.throw("64 ciphertext bytes");
  });
});

describe("key derivation (variants)", () => {
  it("derives a 32-byte ElGamal secret and a 16-byte AES key", async () => {
    const signer = await generateKeyPairSigner();
    const { secretKey, elgamalPubkey } = await deriveElGamalKeypair({ signer });
    expect(secretKey).to.have.length(32);
    expect(elgamalPubkey).to.be.a("string");
    expect(await deriveAeKey({ signer })).to.have.length(16);
  });

  it("scopes the seeded variant away from the standard keys", async () => {
    const signer = await generateKeyPairSigner();
    const standard = await deriveElGamalKeypair({ signer });
    const seeded = await deriveConfidentialKeysWithSeed({
      signer,
      publicSeed: new Uint8Array([9, 9, 9, 9]),
    });
    expect(Array.from(new Uint8Array(seeded.elgamalKeypair.secret().toBytes()))).to.not.deep.equal(
      Array.from(standard.secretKey),
    );
    expect(new Uint8Array(seeded.aesKey.toBytes())).to.have.length(16);
  });

  it("throws when the signer returns no signature", async () => {
    const signer = await generateKeyPairSigner();
    const brokenSigner = {
      address: signer.address,
      signMessages: async () => [{}], // returns no signature for this address
    };
    let err: unknown;
    try {
      await deriveAeKey({ signer: brokenSigner as never });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect((err as Error).message).to.contain("did not return a signature");
  });
});

describe("input guards", () => {
  it("transfer() requires a destination", async () => {
    const [payer, owner] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
    const mint = (await generateKeyPairSigner()).address;
    let err: unknown;
    try {
      await transfer({
        rpc: {} as never,
        rpcSubscriptions: {} as never,
        payer,
        owner,
        mint,
        amount: 1n,
      });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect((err as Error).message).to.contain("destinationToken or destinationOwner");
  });

  it("transfer plan rejects a source account without the CT extension", async () => {
    const owner = await generateKeyPairSigner();
    const mint = (await generateKeyPairSigner()).address;
    const { elgamalKeypair, aesKey } = await sdk.deriveConfidentialKeys({ signer: owner });
    let err: unknown;
    try {
      await getConfidentialTransferInstructionPlan({
        payer: owner,
        rpc: {} as never,
        sourceToken: (await generateKeyPairSigner()).address,
        mint,
        destinationToken: (await generateKeyPairSigner()).address,
        sourceTokenAccount: { extensions: none() } as never,
        destinationTokenAccount: { extensions: none() } as never,
        authority: owner,
        amount: 1n,
        sourceElgamalKeypair: elgamalKeypair,
        aesKey,
      });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect((err as Error).message).to.contain("missing");
  });

  it("transfer plan requires a destination", async () => {
    const owner = await generateKeyPairSigner();
    const mint = (await generateKeyPairSigner()).address;
    const { elgamalKeypair, aesKey } = await sdk.deriveConfidentialKeys({ signer: owner });
    let err: unknown;
    try {
      await getConfidentialTransferInstructionPlan({
        payer: owner,
        rpc: {} as never,
        sourceToken: (await generateKeyPairSigner()).address,
        mint,
        destinationToken: (await generateKeyPairSigner()).address,
        // A source account that *has* the CT extension, but no destination given.
        sourceTokenAccount: { extensions: some([{ __kind: "ConfidentialTransferAccount" }]) } as never,
        authority: owner,
        amount: 1n,
        sourceElgamalKeypair: elgamalKeypair,
        aesKey,
      });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect((err as Error).message).to.contain("Destination");
  });

  it("transfer plan rejects an amount over the confidential-transfer maximum", async () => {
    const owner = await generateKeyPairSigner();
    const mint = (await generateKeyPairSigner()).address;
    const { elgamalKeypair, aesKey } = await sdk.deriveConfidentialKeys({ signer: owner });
    let err: unknown;
    try {
      await getConfidentialTransferInstructionPlan({
        payer: owner,
        rpc: {} as never,
        sourceToken: (await generateKeyPairSigner()).address,
        mint,
        destinationToken: (await generateKeyPairSigner()).address,
        sourceTokenAccount: { extensions: some([{ __kind: "ConfidentialTransferAccount" }]) } as never,
        authority: owner,
        amount: 1n << 48n, // 2^48 — one over the maximum (2^48 - 1)
        sourceElgamalKeypair: elgamalKeypair,
        aesKey,
      });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect((err as Error).message).to.contain("exceeds the confidential-transfer maximum");
  });
});

describe("withdraw", () => {
  /** A token account whose confidential available balance holds `balance`. */
  async function accountWithBalance(balance: bigint) {
    const owner = await generateKeyPairSigner();
    const { elgamalKeypair, aesKey } = await sdk.deriveConfidentialKeys({ signer: owner });
    const tokenAccount = {
      extensions: some([
        {
          __kind: "ConfidentialTransferAccount",
          elgamalPubkey: sdk.getElGamalPubkeyAddress(elgamalKeypair),
          availableBalance: elgamalKeypair.pubkey().encryptU64(balance).toBytes(),
          decryptableAvailableBalance: aesKey.encrypt(balance).toBytes(),
        },
      ]),
    } as never;
    return { owner, elgamalKeypair, aesKey, tokenAccount };
  }

  const rentRpc = {
    getMinimumBalanceForRentExemption: () => ({ send: async () => 1_000_000n }),
  } as never;

  it("subtracts a plaintext amount from an encrypted balance", () => {
    const keypair = new ElGamalKeypair();
    const ciphertext = keypair.pubkey().encryptU64(500n).toBytes();
    const remaining = subtractAmountFromCiphertext(ciphertext, 200n);
    const parsed = ElGamalCiphertext.fromBytes(remaining);
    expect(parsed).to.not.equal(undefined);
    expect(keypair.secret().decrypt(parsed!)).to.equal(300n);
  });

  it("builds a plan for an amount within the available balance", async () => {
    const { owner, elgamalKeypair, aesKey, tokenAccount } = await accountWithBalance(500n);
    const plan = await getConfidentialWithdrawInstructionPlan({
      payer: owner,
      rpc: rentRpc,
      token: (await generateKeyPairSigner()).address,
      mint: (await generateKeyPairSigner()).address,
      tokenAccount,
      authority: owner,
      amount: 200n,
      decimals: 2,
      elgamalKeypair,
      aesKey,
    });
    expect(plan.kind).to.equal("sequential");
  });

  it("rejects an amount above the available balance", async () => {
    const { owner, elgamalKeypair, aesKey, tokenAccount } = await accountWithBalance(500n);
    let err: unknown;
    try {
      await getConfidentialWithdrawInstructionPlan({
        payer: owner,
        rpc: rentRpc,
        token: (await generateKeyPairSigner()).address,
        mint: (await generateKeyPairSigner()).address,
        tokenAccount,
        authority: owner,
        amount: 600n,
        decimals: 2,
        elgamalKeypair,
        aesKey,
      });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect((err as Error).message).to.contain("Insufficient funds");
  });

  it("rejects a zero amount before touching the network", async () => {
    const owner = await generateKeyPairSigner();
    let err: unknown;
    try {
      await withdraw({
        rpc: {} as never,
        rpcSubscriptions: {} as never,
        payer: owner,
        owner,
        mint: (await generateKeyPairSigner()).address,
        amount: 0n,
        decimals: 2,
      });
    } catch (e) {
      err = e;
    }
    expect(err).to.be.an("error");
    expect((err as Error).message).to.contain("greater than zero");
  });
});
