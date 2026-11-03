// Find Wallet Standard wallets (Phantom, Solflare, Backpack and others register themselves this
// way) and turn a connected account into a kit signer the SDK can use.
//
// With React, @solana/react does the same with hooks; this file shows the plain version.
import { createSignerFromWalletAccount } from "@solana/wallet-account-signer";
import type { MessageSigner, TransactionSigner } from "@solana/kit";
import { getWallets } from "@wallet-standard/app";
import type { IdentifierString, Wallet } from "@wallet-standard/base";
import { StandardConnect, type StandardConnectFeature } from "@wallet-standard/features";
import { getOrCreateUiWalletAccountForStandardWalletAccount } from "@wallet-standard/ui-registry";

export type WalletSigner = TransactionSigner | (TransactionSigner & MessageSigner);

export type WalletChoice = {
  wallet: Wallet;
  /** Confidential keys are derived from a message signature, so this is required to unlock. */
  canSignMessages: boolean;
};

/** Calls `onChange` now and whenever a wallet registers or unregisters. */
export function watchWallets(chain: IdentifierString, onChange: (wallets: WalletChoice[]) => void): void {
  const api = getWallets();
  const update = () =>
    onChange(
      api
        .get()
        .filter(
          (w) =>
            w.chains.includes(chain) && StandardConnect in w.features && "solana:signTransaction" in w.features,
        )
        .map((wallet) => ({ wallet, canSignMessages: "solana:signMessage" in wallet.features })),
    );
  update();
  api.on("register", update);
  api.on("unregister", update);
}

/**
 * Whether the wallet signs v1 transactions, which a confidential transfer or withdrawal needs to
 * fit in one transaction. Pass the opposite as `singleTransaction: false` when it does not.
 */
export function signsV1Transactions(wallet: Wallet): boolean {
  const feature = wallet.features["solana:signTransaction"] as { supportedTransactionVersions?: readonly unknown[] } | undefined;
  return feature?.supportedTransactionVersions?.includes(1) ?? false;
}

/** Asks the wallet to connect and returns a signer for its first account on `chain`. */
export async function connectWallet(wallet: Wallet, chain: IdentifierString): Promise<WalletSigner> {
  const { accounts } = await (wallet.features as StandardConnectFeature)[StandardConnect].connect();
  const account = accounts.find((a) => a.chains.includes(chain)) ?? accounts[0];
  if (!account) throw new Error(`${wallet.name} did not share an account`);
  const uiAccount = getOrCreateUiWalletAccountForStandardWalletAccount(wallet, account);
  return createSignerFromWalletAccount(uiAccount, chain);
}
