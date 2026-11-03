// SPDX-License-Identifier: BUSL-1.1
//
// The available balance the SDK works from: the AES copy when it matches the encrypted balance,
// the corrected value when an apply left it behind (src/internal/availableBalance.ts).
//
// The unit tests need no validator. The integration test reproduces the race on a local
// validator: an apply whose AES copy leaves out a transfer that arrived in the meantime, exactly
// what Token-2022 accepts when a credit lands between the owner's read and the apply.
import { address, type Address } from "@solana/kit";
import { fetchToken, getApplyConfidentialPendingBalanceInstruction } from "@solana-program/token-2022";
import { AeCiphertext, AeKey, ElGamalKeypair } from "@solana/zk-sdk/node";
import { expect } from "chai";

import { applyPendingBalance } from "../src/applyPendingBalance";
import { configureAccount } from "../src/configureAccount";
import { decryptBalance } from "../src/decryptBalance";
import { deposit } from "../src/deposit";
import { isConfidentialTransfersError } from "../src/errors";
import { readConfiguredAccount } from "../src/internal/accounts";
import { ciphertextHolds, readAvailableBalance } from "../src/internal/availableBalance";
import { deriveConfidentialKeys } from "../src/keys";
import { transfer } from "../src/transfer";
import { withdraw } from "../src/withdraw";
import {
  createConfidentialMint,
  fundedSigner,
  mintPublicTokens,
  rpc,
  rpcSubscriptions,
  sendInstructions,
} from "./_helpers";

const TOKEN = address("11111111111111111111111111111111") as Address;

function keysAndAccount(encrypted: bigint, copy: bigint | "garbage") {
  const keys = { elgamalKeypair: new ElGamalKeypair(), aesKey: new AeKey() };
  return {
    keys,
    account: {
      availableBalance: keys.elgamalKeypair.pubkey().encryptU64(encrypted).toBytes(),
      decryptableAvailableBalance: (copy === "garbage" ? new AeKey().encrypt(1n) : keys.aesKey.encrypt(copy)).toBytes(),
    },
  };
}

function outOfSync(run: () => unknown): boolean {
  try {
    run();
    return false;
  } catch (e) {
    return isConfidentialTransfersError(e, "BALANCE_OUT_OF_SYNC");
  }
}

describe("available balance", () => {
  it("is the AES copy when it matches the encrypted balance", () => {
    const { keys, account } = keysAndAccount(1000n, 1000n);
    expect(readAvailableBalance(account, keys, TOKEN, "test")).to.equal(1000n);
  });

  it("reads a fresh account, whose encrypted balance is all zero bytes", () => {
    const keys = { elgamalKeypair: new ElGamalKeypair(), aesKey: new AeKey() };
    const account = { availableBalance: new Uint8Array(64), decryptableAvailableBalance: keys.aesKey.encrypt(0n).toBytes() };
    expect(readAvailableBalance(account, keys, TOKEN, "test")).to.equal(0n);
  });

  it("adds what an AES copy that fell behind missed", () => {
    const { keys, account } = keysAndAccount(1300n, 1000n);
    expect(readAvailableBalance(account, keys, TOKEN, "test")).to.equal(1300n);
  });

  it("decrypts a small balance whose AES copy cannot be read", () => {
    const { keys, account } = keysAndAccount(500n, "garbage");
    expect(readAvailableBalance(account, keys, TOKEN, "test")).to.equal(500n);
  });

  it("refuses when the missing part is 2^32 base units or more", () => {
    const { keys, account } = keysAndAccount(1000n + (1n << 33n), 1000n);
    expect(outOfSync(() => readAvailableBalance(account, keys, TOKEN, "test"))).to.equal(true);
  });

  it("refuses an AES copy that is ahead of the encrypted balance", () => {
    const { keys, account } = keysAndAccount(900n, 1000n);
    expect(outOfSync(() => readAvailableBalance(account, keys, TOKEN, "test"))).to.equal(true);
  });

  it("checks a ciphertext's amount without a discrete log", () => {
    const keypair = new ElGamalKeypair();
    const secret = keypair.secret().toBytes();
    const ciphertext = keypair.pubkey().encryptU64(1n << 50n).toBytes();
    expect(ciphertextHolds(ciphertext, secret, 1n << 50n)).to.equal(true);
    expect(ciphertextHolds(ciphertext, secret, (1n << 50n) - 1n)).to.equal(false);
    expect(ciphertextHolds(ciphertext, new ElGamalKeypair().secret().toBytes(), 1n << 50n)).to.equal(false);
    expect(ciphertextHolds(new Uint8Array(32), secret, 0n)).to.equal(false);
  });
});

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

describeOnChain("available balance (integration)", function () {
  this.timeout(240000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("repairs an AES copy left behind by a transfer that arrived during an apply", async () => {
    const payer = await fundedSigner();
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    const { token: bobToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    for (const [owner, token] of [[alice, aliceToken], [bob, bobToken]] as const) {
      await mintPublicTokens({ payer, mint, token, mintAuthority, amount: 1000n });
      await deposit({ rpc, rpcSubscriptions, payer, owner, mint, amount: 1000n, decimals });
      await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner, mint });
    }
    const aliceKeys = await deriveConfidentialKeys({ signer: alice });

    // Bob pays Alice 300. Alice's apply then runs with the AES copy she computed before the
    // payment arrived (1000), and Token-2022 accepts it: the encrypted balance becomes 1300, the
    // copy stays at 1000.
    await transfer({ rpc, rpcSubscriptions, payer, owner: bob, mint, destinationOwner: alice.address, amount: 300n });
    await sendInstructions(payer, [
      getApplyConfidentialPendingBalanceInstruction({
        token: aliceToken,
        authority: alice,
        expectedPendingBalanceCreditCounter: 0n,
        newDecryptableAvailableBalance: aliceKeys.aesKey.encrypt(1000n).toBytes(),
      }),
    ]);
    const stale = await readConfiguredAccount(rpc, aliceToken, "test");
    expect(stale.ct.expectedPendingBalanceCreditCounter).to.not.equal(stale.ct.actualPendingBalanceCreditCounter);
    expect(aliceKeys.aesKey.decrypt(aeCiphertext(stale.ct.decryptableAvailableBalance))).to.equal(1000n);

    // The SDK reads the real balance, and a transfer of more than the stale copy goes through.
    expect(await decryptBalance({ rpc, owner: alice, mint, keys: aliceKeys })).to.equal(1300n);
    await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 1200n, keys: aliceKeys });

    // That transfer wrote a correct copy: the account is repaired.
    const repaired = await readConfiguredAccount(rpc, aliceToken, "test");
    expect(aliceKeys.aesKey.decrypt(aeCiphertext(repaired.ct.decryptableAvailableBalance))).to.equal(100n);
    expect(await decryptBalance({ rpc, owner: alice, mint, keys: aliceKeys })).to.equal(100n);
    await withdraw({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 100n, decimals, keys: aliceKeys });
    expect((await fetchToken(rpc, aliceToken)).data.amount).to.equal(100n);
  });

  it("applies on top of a copy that fell behind", async () => {
    const payer = await fundedSigner();
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    const { token: bobToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    await mintPublicTokens({ payer, mint, token: bobToken, mintAuthority, amount: 1000n });
    await deposit({ rpc, rpcSubscriptions, payer, owner: bob, mint, amount: 1000n, decimals });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    const aliceKeys = await deriveConfidentialKeys({ signer: alice });

    // A stale apply (copy 0 instead of 250), then another payment, then a normal apply.
    await transfer({ rpc, rpcSubscriptions, payer, owner: bob, mint, destinationOwner: alice.address, amount: 250n });
    await sendInstructions(payer, [
      getApplyConfidentialPendingBalanceInstruction({
        token: aliceToken,
        authority: alice,
        expectedPendingBalanceCreditCounter: 0n,
        newDecryptableAvailableBalance: aliceKeys.aesKey.encrypt(0n).toBytes(),
      }),
    ]);
    await transfer({ rpc, rpcSubscriptions, payer, owner: bob, mint, destinationOwner: alice.address, amount: 50n });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint, keys: aliceKeys });

    const account = await readConfiguredAccount(rpc, aliceToken, "test");
    expect(aliceKeys.aesKey.decrypt(aeCiphertext(account.ct.decryptableAvailableBalance))).to.equal(300n);
  });
});

function aeCiphertext(bytes: ArrayLike<number>) {
  const ciphertext = AeCiphertext.fromBytes(new Uint8Array(bytes));
  if (!ciphertext) throw new Error("not an AES ciphertext");
  return ciphertext;
}
