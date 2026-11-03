---
title: Web apps
---

# Using the SDK in a web app

Since 3.1.0 the package has a browser build. Bundlers that honour the `browser` export condition
(Vite, webpack 5, esbuild with `platform: "browser"`, and the frameworks built on them) pick it up
by themselves, with no alias. This guide covers what is different in a browser: loading the
cryptography, getting keys from a wallet, and what the user sees.

A complete app to copy from is in
[`examples/vite`](https://github.com/softseco/arcantis/tree/main/examples/vite).

## Install

```bash
npm install @softseco/arcantis @solana/kit @solana/wallet-account-signer
```

## The cryptography is WebAssembly

Proofs and encryption run in `@solana/zk-sdk`, which is WebAssembly (about 2.7 MB, and it does not
compress much). The SDK loads it on the first call that needs it. To start the download as soon
as the page opens, call this once at startup:

```ts
import { initConfidentialTransfers } from "@softseco/arcantis";

void initConfidentialTransfers();
```

The browser fetches `index_bg.wasm` from next to the zk-sdk module. Vite and webpack 5 see that
reference and copy the file into your build:

- **webpack 5**: nothing to configure.
- **Vite**: nothing to configure for `vite build`. For the dev server, add this to `vite.config`:

  ```ts
  export default defineConfig({
    optimizeDeps: { exclude: ["@solana/zk-sdk"] },
  });
  ```

  Without it the dev server pre-bundles zk-sdk into another folder and the `.wasm` request fails.
  In a monorepo, or with the SDK linked from a local folder, the dev server may also refuse the
  file (HTTP 403) because it is outside your project: add that `node_modules` folder to
  `server.fs.allow`.
- **Anything else** (esbuild, for example, does not copy it): serve
  `node_modules/@solana/zk-sdk/dist/web/index_bg.wasm` yourself and say where it is:

  ```ts
  await initConfidentialTransfers({ wasmUrl: "/zk/index_bg.wasm" });
  ```

If the file does not load, the SDK throws an error that says so and names these fixes.

Tested in Chromium: Vite 8 (production build and dev server, in CI on every push) and webpack 5
(production build). The keys a browser derives are byte-for-byte the ones Node derives.

## Keys from a wallet

The confidential keys (ElGamal and AES) come from the wallet's signature over one fixed message,
`solana-conf-bal/v1`. A wallet signs it through Wallet Standard's `solana:signMessage`. Ask for
that signature once, keep the keys in memory, and pass them to every call as `keys`:

```ts
import { createSignerFromWalletAccount } from "@solana/wallet-account-signer";
import { deriveConfidentialKeys, decryptBalance, transfer } from "@softseco/arcantis";
import { isMessageSigner } from "@solana/kit";

const signer = createSignerFromWalletAccount(uiWalletAccount, "solana:devnet");
if (!isMessageSigner(signer)) throw new Error("This wallet cannot sign messages");

// One wallet prompt: "sign this message".
const keys = await deriveConfidentialKeys({ signer });

// No more message prompts: the keys are passed in.
const balance = await decryptBalance({ rpc, owner: signer, mint, keys });
await transfer({ rpc, rpcSubscriptions, payer: signer, owner: signer, mint, destinationOwner, amount, keys });
```

Without `keys`, every call asks the wallet to sign the message again. That works, but the user
gets one extra prompt per call.

With React, `@solana/react` gives you the two signers as hooks:

```tsx
const messageSigner = useWalletAccountMessageSigner(account);
const signer = useWalletAccountTransactionSigner(account, "solana:devnet");

const keys = await deriveConfidentialKeys({ signer: messageSigner });
await configureAccount({ rpc, rpcSubscriptions, payer: signer, owner: signer, mint, keys });
```

What to know about the keys:

- They belong to the wallet, not to a mint: one set reads every confidential account the wallet
  owns. They are the same keys the spl-token CLI and other standard clients derive.
- They cannot move funds (that needs the wallet's transaction signature), but they decrypt every
  balance and amount of the wallet. Keep them in memory for the session. Do not put them in
  `localStorage`; after a reload, ask for the signature again.
- Before it decrypts a balance or builds a proof, the SDK checks that the keys match the
  account's ElGamal key, so keys from the wrong wallet fail with a clear error instead of wrong
  numbers.

## What the wallet must support

- `solana:signMessage`, signing the message as given. The SDK verifies the signature and refuses
  a wallet that changes the message, because the keys would then differ from the standard ones.
- `solana:signTransaction`. A wallet that only offers `signAndSendTransaction` cannot be used yet,
  because the SDK simulates each transaction before sending it.

Phantom, Solflare and Backpack support both. When a wallet cannot sign messages, the SDK's error
says so; you can check up front with `isMessageSigner(signer)` or `"solana:signMessage" in
wallet.features`.

## What the user approves

The wallet is asked once per operation. Since 1.0.0 a transfer and a withdrawal are one
transaction each, with their proofs inside:

| Step | Wallet prompts | Transactions |
|---|---|---|
| Unlock (`deriveConfidentialKeys`) | 1 (sign a message) | none |
| `configureAccount` | 1 | 1 |
| `deposit` | 1 | 1 |
| `applyPendingBalance` | 1 | 1 |
| `transfer` | 1 | 1 (5 with `singleTransaction: false`) |
| `withdraw` | 1 | 1 (4 with `singleTransaction: false`) |

A transfer or withdrawal is a v1 transaction of up to 4,096 bytes, which Solana accepts since
15 September 2026. The wallet has to be able to sign one; a Wallet Standard wallet lists `1` in
`supportedTransactionVersions` of its `solana:signTransaction` feature when it can (the Vite
example checks this when it connects). If yours cannot, pass `singleTransaction: false`: the SDK then verifies the proofs into proof accounts first, the way
it did before 1.0.0, and the wallet still shows one request, for all five transactions. They are
sent one after another, each simulated first. If one fails before the transfer itself lands, the
SDK closes the proof accounts it created (their rent goes back to the payer) and throws a
`ConfidentialTransfersError`. Closing them is one more transaction, so the wallet asks once more in
that case. The SDK also takes this path by itself when the one transaction would be too large,
for example with a transfer hook that asks for many accounts.

The fee payer does not have to be the owner. A relayer that pays the SOL fees (`payer`) lets
people send without holding SOL; the owner still signs the same single transaction.

## Errors

Everything the SDK throws on purpose is a `ConfidentialTransfersError` with a `code`, so the app
can say something useful instead of showing a stack trace:

```ts
import { isConfidentialTransfersError } from "@softseco/arcantis";

try {
  await transfer({ rpc, rpcSubscriptions, payer: signer, owner: signer, mint, destinationOwner, amount, keys });
} catch (e) {
  if (isConfidentialTransfersError(e, "PENDING_BALANCE_LIMIT")) showMessage("The recipient has to accept their incoming payments first.");
  else if (isConfidentialTransfersError(e, "INSUFFICIENT_FUNDS")) showMessage("Not enough confidential balance.");
  else if (isConfidentialTransfersError(e) && e.retryable) showMessage("The network was busy. Try again.");
  else throw e;
}
```

The checks that can be made before anything is signed (the recipient's account exists, is
configured and can take another payment; the amount fits; the balance covers it) are made first,
so a doomed operation fails before the wallet opens.

On a busy network, pass `computeUnitPrice` (a priority fee in micro-lamports per compute unit),
and `retries` to run the operation again when a transaction expires. A retry signs new
transactions, so the wallet asks again.

## Testing

`test/browser/e2e.ts` runs `examples/vite` in Chromium with a Wallet Standard
test wallet against a local validator: connect, unlock, set up, deposit, apply, transfer,
withdraw, then checks the balances, that the wallet signed the key message exactly once, and that
it was asked to approve transactions once per operation. CI runs it on every push. To run it yourself, see
[CONTRIBUTING.md](https://github.com/softseco/arcantis/blob/main/CONTRIBUTING.md).
