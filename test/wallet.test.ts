// SPDX-License-Identifier: BUSL-1.1
//
// Browser wallets and key reuse, without a validator.
//
// A Wallet Standard wallet signs messages through kit's MessageModifyingSigner interface (that is
// what @solana/wallet-account-signer returns), not MessagePartialSigner. These tests stand in for
// such a wallet with a keypair behind that interface and check that it derives exactly the keys a
// keypair signer derives, that a wallet which alters the message or returns a bad signature is
// refused, and that passed-in `keys` are used without asking the owner to sign anything.
import {
  AccountState,
  TOKEN_2022_PROGRAM_ADDRESS,
  getTokenEncoder,
} from "@solana-program/token-2022";
import {
  createKeyPairSignerFromPrivateKeyBytes,
  generateKeyPairSigner,
  getBase64Decoder,
  none,
  some,
  type Address,
  type KeyPairSigner,
  type MessageModifyingSigner,
  type SignableMessage,
} from "@solana/kit";
import { expect } from "chai";

import * as sdk from "../src/index";
import { assertKeysMatchAccount, ownerKeys } from "../src/internal/ownerKeys";

/** A wallet that signs through `modifyAndSignMessages`, like a Wallet Standard wallet. */
function walletLike(
  keypair: KeyPairSigner,
  options: { alter?: boolean; badSignature?: boolean } = {},
): MessageModifyingSigner & { calls: number } {
  const wallet = {
    address: keypair.address,
    calls: 0,
    async modifyAndSignMessages(messages: readonly SignableMessage[]) {
      wallet.calls += 1;
      return Promise.all(
        messages.map(async (m) => {
          const content = options.alter
            ? new Uint8Array([...m.content, 0x0a]) // e.g. a wallet that appends a newline
            : m.content;
          const [signatures] = await keypair.signMessages([{ content, signatures: {} }]);
          let signature = new Uint8Array(signatures[keypair.address]);
          if (options.badSignature) signature = signature.map((b, i) => (i === 0 ? b ^ 1 : b));
          return { content, signatures: { ...m.signatures, [keypair.address]: signature } };
        }),
      );
    },
  };
  return wallet as unknown as MessageModifyingSigner & { calls: number };
}

async function errorOf(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (e) {
    return e as Error;
  }
  throw new Error("expected an error");
}

const PRIVATE_KEY = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1));

describe("browser wallets", () => {
  it("derives the same keys through a wallet's signMessage as through a keypair signer", async () => {
    const keypair = await createKeyPairSignerFromPrivateKeyBytes(PRIVATE_KEY);
    const fromKeypair = await sdk.deriveConfidentialKeys({ signer: keypair });
    const wallet = walletLike(keypair);
    const fromWallet = await sdk.deriveConfidentialKeys({ signer: wallet });
    expect(wallet.calls).to.equal(1);
    expect(sdk.getElGamalPubkeyAddress(fromWallet.elgamalKeypair)).to.equal(
      sdk.getElGamalPubkeyAddress(fromKeypair.elgamalKeypair),
    );
    expect(Array.from(fromWallet.aesKey.toBytes())).to.deep.equal(Array.from(fromKeypair.aesKey.toBytes()));
  });

  it("refuses a wallet that changes the message it signs", async () => {
    const wallet = walletLike(await generateKeyPairSigner(), { alter: true });
    const err = await errorOf(sdk.deriveConfidentialKeys({ signer: wallet }));
    expect(err.message).to.contain("changed the message");
  });

  it("refuses a signature that does not verify", async () => {
    const wallet = walletLike(await generateKeyPairSigner(), { badSignature: true });
    const err = await errorOf(sdk.deriveConfidentialKeys({ signer: wallet }));
    expect(err.message).to.contain("does not verify");
  });

  it("explains that a signer without signMessage cannot derive keys", async () => {
    const { address } = await generateKeyPairSigner();
    const err = await errorOf(sdk.deriveConfidentialKeys({ signer: { address } as never }));
    expect(err.message).to.contain("cannot sign messages");
    expect(err.message).to.contain("signMessage");
  });

  it("asks for `keys` when an SDK call's owner cannot sign messages", async () => {
    const { address } = await generateKeyPairSigner();
    const transactionOnlySigner = { address, modifyAndSignTransactions: async () => [] };
    const err = await errorOf(ownerKeys(transactionOnlySigner, undefined, "transfer"));
    expect(err.message).to.contain("transfer:");
    expect(err.message).to.contain("pass them as `keys`");
  });

  it("uses passed-in keys without asking the owner to sign", async () => {
    const keypair = await generateKeyPairSigner();
    const keys = await sdk.deriveConfidentialKeys({ signer: keypair });
    const wallet = walletLike(keypair);
    expect(await ownerKeys(wallet, keys, "transfer")).to.equal(keys);
    expect(wallet.calls).to.equal(0);
  });

  it("resolves initConfidentialTransfers() in Node, where there is nothing to load", async () => {
    await sdk.initConfidentialTransfers();
    await sdk.initConfidentialTransfers({ wasmUrl: "https://example.invalid/unused.wasm" });
  });
});

describe("keys checked against the account", () => {
  async function configuredAccount(owner: KeyPairSigner, balance: bigint) {
    const keys = await sdk.deriveConfidentialKeys({ signer: owner });
    const zero = keys.elgamalKeypair.pubkey().encryptU64(0n).toBytes();
    return {
      keys,
      account: {
        mint: (await generateKeyPairSigner()).address,
        owner: owner.address,
        amount: 0n,
        delegate: none<Address>(),
        state: AccountState.Initialized,
        isNative: none<bigint>(),
        delegatedAmount: 0n,
        closeAuthority: none<Address>(),
        extensions: some([
          {
            __kind: "ConfidentialTransferAccount" as const,
            approved: true,
            elgamalPubkey: sdk.getElGamalPubkeyAddress(keys.elgamalKeypair),
            pendingBalanceLow: zero,
            pendingBalanceHigh: zero,
            availableBalance: keys.elgamalKeypair.pubkey().encryptU64(balance).toBytes(),
            decryptableAvailableBalance: keys.aesKey.encrypt(balance).toBytes(),
            allowConfidentialCredits: true,
            allowNonConfidentialCredits: true,
            pendingBalanceCreditCounter: 0n,
            maximumPendingBalanceCreditCounter: 65536n,
            expectedPendingBalanceCreditCounter: 0n,
            actualPendingBalanceCreditCounter: 0n,
          },
        ]),
      },
    };
  }

  /** An RPC that serves one token account and nothing else. */
  function rpcWith(token: Address, account: Parameters<ReturnType<typeof getTokenEncoder>["encode"]>[0]) {
    const bytes = getTokenEncoder().encode(account);
    return {
      getAccountInfo: (address: Address) => ({
        send: async () => ({
          value:
            address === token
              ? {
                  data: [getBase64Decoder().decode(bytes), "base64"],
                  executable: false,
                  lamports: 2_039_280n,
                  owner: TOKEN_2022_PROGRAM_ADDRESS,
                  space: BigInt(bytes.length),
                  rentEpoch: 0n,
                }
              : null,
        }),
      }),
    } as never;
  }

  it("decryptBalance reads the balance with passed-in keys and no signature", async () => {
    const owner = await generateKeyPairSigner();
    const token = (await generateKeyPairSigner()).address;
    const { keys, account } = await configuredAccount(owner, 1234n);
    const wallet = walletLike(owner);
    const balance = await sdk.decryptBalance({
      rpc: rpcWith(token, account),
      owner: wallet,
      mint: account.mint,
      token,
      keys,
    });
    expect(balance).to.equal(1234n);
    expect(wallet.calls).to.equal(0);
  });

  it("decryptBalance refuses keys that belong to another wallet", async () => {
    const owner = await generateKeyPairSigner();
    const token = (await generateKeyPairSigner()).address;
    const { account } = await configuredAccount(owner, 1n);
    const otherKeys = await sdk.deriveConfidentialKeys({ signer: await generateKeyPairSigner() });
    const err = await errorOf(
      sdk.decryptBalance({ rpc: rpcWith(token, account), owner, mint: account.mint, token, keys: otherKeys }),
    );
    expect(err.message).to.contain("decryptBalance: these confidential keys");
    expect(err.message).to.contain(token);
  });

  it("accepts the right keys and ignores an account without the extension", async () => {
    const owner = await generateKeyPairSigner();
    const token = (await generateKeyPairSigner()).address;
    const { keys, account } = await configuredAccount(owner, 1n);
    assertKeysMatchAccount(keys, account, token, "transfer");
    assertKeysMatchAccount(keys, { extensions: none() }, token, "transfer");
  });
});
