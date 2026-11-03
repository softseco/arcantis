# Confidential transfers in a web app (Vite)

A small app on `@softseco/arcantis`: connect a browser wallet, unlock the
confidential balance with one message signature, then set up the token account, deposit, apply,
send confidentially and withdraw. About 250 lines in [`src/main.ts`](./src/main.ts) and
[`src/wallet.ts`](./src/wallet.ts), no framework.

## Run it

```bash
# in the repository root: build the SDK this example uses
npm install && npm run build

cd examples/vite
npm install
npm run dev
```

You need a Token-2022 mint with confidential transfers and some of its tokens in your wallet. In
the repository root, with a Solana CLI wallet that has a little devnet SOL:

```bash
npm run example:devnet-mint -- <your browser wallet address>
```

It creates the mint, puts 1000 public tokens in your wallet and prints the mint address. Open the
page, connect your wallet (set to devnet), paste the mint, and go. The whole flow costs your
wallet about 0.005 devnet SOL in fees.

Settings, in `.env` or the environment:

| Variable | Default |
|---|---|
| `VITE_RPC_URL` | `https://api.devnet.solana.com` |
| `VITE_WS_URL` | the RPC URL with `ws://` or `wss://` |
| `VITE_CHAIN` | `solana:devnet` |
| `VITE_MINT` | empty; fills in the mint field |

## Use it outside this repository

The example uses the SDK from this repository (`"file:../.."` in `package.json`). In your own app,
install it from npm instead:

```bash
npm install @softseco/arcantis
```

and drop the `resolve.dedupe` and `server.fs.allow` lines from `vite.config.ts`; they are only
there because of the local link. Keep `optimizeDeps.exclude`.

## What to look at

- `deriveConfidentialKeys({ signer })` runs once, on "Unlock". The keys stay in memory and are
  passed as `keys` to every call, so the wallet does not ask to sign the message again.
- Each operation needs one approval in the wallet. A transfer and a withdraw are one transaction
  each, with their proofs inside, when the wallet signs v1 transactions. `signsV1Transactions` in
  `src/wallet.ts` checks that on connect; with a wallet that does not, the app passes
  `singleTransaction: false` and the transfer goes through proof accounts, still with one approval.
- The recipient must have set up a token account for the mint before you can send to them.

The repository's browser test (`test/browser/e2e.ts`) runs this app in Chromium with a test wallet
on every push. More in the [web apps guide](../../guides/web-apps.md).
