# Playground

One page that runs a confidential token from start to finish on Solana devnet, with throwaway keys
in the browser: Arcantis for the private amounts, Vigilantis for the issuer's rules.

**Live: [softseco.github.io/arcantis](https://softseco.github.io/arcantis/)**

The page creates one Token-2022 mint that carries everything: confidential transfers with an
auditor key, and [Vigilantis](https://github.com/softseco/vigilantis) as its transfer hook, freeze
authority and pause authority. Then, in ten steps:

| | Step | What it shows |
|---|---|---|
| Arcantis | 1–3 | fund, create the token, open three confidential accounts, deposit |
| | 4–6 | a confidential transfer to Bob; who can decrypt it; Bob withdraws half to public |
| Vigilantis | 7 | Mallory is blocked (reason and case on-chain); a payment to her is refused |
| | 8 | Bob's account is frozen; his payment is refused; the account is thawed |
| | 9 | the token is paused; a payment is refused; transfers resume |
| Oversight | 10 | the auditor's report of every deposit, transfer and withdraw, as CSV or JSON |

The page makes four keypairs (you, Bob, Mallory and the auditor) and keeps them in `localStorage`.
Nothing leaves the browser except signed devnet transactions. A full run costs about 0.05 devnet SOL.

## Build

```bash
cd playground
npm install
npm run build   # writes ../docs: index.html, app.js, zk_sdk_bg.wasm, the site's styles, script and pictures
```

Serve `../docs` with any static server to try it locally, for example `npx serve ../docs`.

## The softseco.com design

The page is a softseco.com page: the same header and menus, footer, styles and script. `site/` holds
copies of them, and `index.html` has a placeholder for each part (`<!-- site:header -->` and so on)
that `npm run build` fills in. The playground's own styles are in `index.html`, on top of the site's.

When the site changes, copy its parts again and rebuild:

```bash
npm run import-site -- "<path to the site>"
npm run build
```

`import-site.mjs` turns the site's links into links to softseco.com, points the Arcantis and
Vigilantis entries of the menus and footer at their repositories, and stops with an error if the
site's markup has changed in a way it does not expect. Do not edit the files in `site/` by hand.

## Run it against a local validator

The page takes its RPC endpoint from `?rpc=`: any `https://` URL, or a validator on the same
machine. Start one with Vigilantis loaded at its program ID and a Token-2022 that matches the client
(the Vigilantis repository's `tests/fixtures/spl_token_2022.so`):

```bash
solana-test-validator --reset \
  --deactivate-feature zkdoVwnSFnSLtGJG7irJPEYUpmb4i7sGMGcnN6T9rnC \
  --bpf-program 4DoDFZJmJWYuBx86UqXi3y24GkQ3Cq4nUBHZwDE5PQM5 vigilantis.so \
  --upgradeable-program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb spl_token_2022.so TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
```

Then open `http://localhost:3000/?rpc=http://127.0.0.1:8899`. The airdrop in step 1 comes from the
local faucet.

## Notes

- **Vigilantis instructions.** `src/vigilantis.js` encodes them with `@solana/kit` from
  `src/vigilantis-idl.json`, the Vigilantis 1.0.0-rc.1 IDL without its doc comments. After a new
  Vigilantis release, compare the copy with the release's IDL and update it:
  `npm run check -- <path>/vigilantis/sdk/src/idl/vigilantis.json [--write]`. From Node you would
  use `@softseco/vigilantis` instead.
- **WebAssembly.** esbuild picks the SDK's browser build by itself but does not copy the zk-sdk
  WebAssembly, so `build.mjs` copies it into `../docs` and the page passes its URL to
  `initConfidentialTransfers({ wasmUrl })`. See the [web apps guide](../guides/web-apps.md).
- **Confirmations.** Transactions are confirmed by polling the HTTP RPC about once a slot
  (`src/polling.js`) instead of a websocket, because the public devnet websocket drops connections
  under load.
- **One transaction per transfer.** A confidential transfer and a withdraw are one transaction
  each, with their proofs inside (a v1 transaction). A transfer the chain would refuse is refused in
  its simulation, before anything is signed or created.
- **Case references.** Steps 7–9 hash each case number with a salt the page keeps in this browser
  (`caseRef` in `src/vigilantis.js`, the same as in `@softseco/vigilantis`). The chain only ever
  sees the hash.
- **A busy public RPC?** Add `?rpc=https://your-devnet-endpoint` to the URL.
