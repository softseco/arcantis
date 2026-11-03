// SPDX-License-Identifier: BUSL-1.1
//
// A Wallet Standard wallet for the browser test. It registers itself the way Phantom, Solflare and
// other wallets do, signs with a key the test hands it, and counts what it was asked to sign, so
// the test can check that the app asked for the key message once and reused the keys after that.
//
// e2e.ts bundles this file and injects it into the page before the app loads.
import { ed25519 } from "@noble/curves/ed25519";
import {
  getBase58Decoder,
  getTransactionDecoder,
  getTransactionEncoder,
  type SignatureBytes,
} from "@solana/kit";
import type { IdentifierArray, Wallet, WalletAccount } from "@wallet-standard/base";
import type { StandardConnectFeature, StandardEventsFeature, StandardEventsListeners } from "@wallet-standard/features";
import { registerWallet } from "@wallet-standard/wallet";

/** signTransaction counts requests (what a user approves); transactions counts what was in them. */
type Stats = { signMessage: number; signTransaction: number; transactions: number };
declare global {
  interface Window {
    __testWalletSecret?: number[];
    __testWallet?: Stats;
  }
}

const secret = new Uint8Array(window.__testWalletSecret ?? []);
if (secret.length !== 32) throw new Error("test wallet: window.__testWalletSecret must hold 32 bytes");
const publicKey = ed25519.getPublicKey(secret);
const address = getBase58Decoder().decode(publicKey);
const chains: IdentifierArray = ["solana:devnet", "solana:localnet"];
const stats: Stats = { signMessage: 0, signTransaction: 0, transactions: 0 };
window.__testWallet = stats;

const account: WalletAccount = {
  address,
  publicKey,
  chains,
  features: ["solana:signMessage", "solana:signTransaction"],
  label: "Test account",
};

let accounts: readonly WalletAccount[] = [];
const listeners: StandardEventsListeners["change"][] = [];

const connect: StandardConnectFeature["standard:connect"]["connect"] = async () => {
  accounts = [account];
  listeners.forEach((listener) => listener({ accounts }));
  return { accounts };
};

const on: StandardEventsFeature["standard:events"]["on"] = (event, listener) => {
  if (event !== "change") return () => {};
  listeners.push(listener);
  return () => listeners.splice(listeners.indexOf(listener), 1);
};

const wallet: Wallet = {
  version: "1.0.0",
  name: "Test wallet",
  icon: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxIDEiLz4=",
  chains,
  get accounts() {
    return accounts;
  },
  features: {
    "standard:connect": { version: "1.0.0", connect },
    "standard:events": { version: "1.0.0", on },
    "solana:signMessage": {
      version: "1.1.0",
      signMessage: async (...inputs: { message: Uint8Array }[]) => {
        stats.signMessage += 1;
        return inputs.map(({ message }) => ({
          signedMessage: message,
          signature: ed25519.sign(message, secret),
        }));
      },
    },
    "solana:signTransaction": {
      version: "1.0.0",
      supportedTransactionVersions: ["legacy", 0, 1],
      signTransaction: async (...inputs: { transaction: Uint8Array }[]) => {
        stats.signTransaction += 1;
        return inputs.map(({ transaction }) => {
          stats.transactions += 1;
          const decoded = getTransactionDecoder().decode(transaction);
          const signature = ed25519.sign(new Uint8Array(decoded.messageBytes), secret) as SignatureBytes;
          const signed = { ...decoded, signatures: { ...decoded.signatures, [address]: signature } };
          return { signedTransaction: new Uint8Array(getTransactionEncoder().encode(signed)) };
        });
      },
    },
  },
};

registerWallet(wallet);
