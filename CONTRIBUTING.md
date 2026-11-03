# Contributing

Thanks for your interest in improving Arcantis. This repository holds two packages, versioned
separately:

- **TypeScript** (repository root) — `@softseco/arcantis`
- **Rust** (`rust/`) — `arcantis`

## Prerequisites

- **Node ≥ 20.18** and npm (for the TypeScript package)
- **Rust** (stable) with `rustfmt` and `clippy` (for the crate)
- For on-chain and browser tests: the Solana CLI with `solana-test-validator` from **Agave 4.x**
  (see [On-chain tests](#on-chain-tests))

## TypeScript

```bash
npm install
npm run typecheck        # tsc --noEmit, for src/, examples/ and the browser test
npm run build            # Node build, browser build (dist/browser) and type declarations
npm test                 # unit tests; on-chain tests are skipped without a validator
npm run coverage         # unit tests with coverage
npm run example:devnet   # full round trip on devnet, paid from your Solana CLI wallet
npm run docs:api         # regenerate the API reference in docs/api (TypeDoc)
```

### On-chain tests

The confidential-transfer instructions need a local validator from Agave 4.x (older releases
reject the proofs `@solana/zk-sdk` makes today) and a Token-2022 build that matches the
`@solana-program/token-2022` client. That build is in `test/fixtures/` (see its README):

```bash
# 1. start the validator with that Token-2022 (leave running)
TOKEN_2022_SO=test/fixtures/spl_token_2022.so npm run validator

# 2. run the integration tests against it
CT_LOCAL_PROGRAM=1 npm test
```

Without `CT_LOCAL_PROGRAM=1`, on-chain tests are skipped and only unit tests run.

### Browser test

`test/browser/e2e.ts` runs the Vite example in Chromium with a Wallet Standard test wallet against
the same validator. With the validator running:

```bash
npm run build
(cd examples/vite && npm ci && VITE_RPC_URL=http://127.0.0.1:8899 VITE_CHAIN=solana:localnet npx vite build)
npx playwright-core install chromium      # once; or set CHROMIUM_PATH to a Chrome you have
npm run test:browser
```

On failure it saves a screenshot in `test/browser/artifacts/`.

## Rust

```bash
cd rust
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build
cargo test          # unit tests and the shared vectors; on-chain tests skip
```

On-chain tests, from the repository root (the Anchor example is optional; its test skips without
it):

```bash
(cd rust/examples/anchor-vault && cargo build-sbf --manifest-path programs/confidential-vault/Cargo.toml)
TOKEN_2022_SO=test/fixtures/spl_token_2022.so SENTINEL_SO=test/fixtures/sentinel.so \
CONFIDENTIAL_VAULT_SO=rust/examples/anchor-vault/target/deploy/confidential_vault.so \
  bash scripts/start-test-validator.sh
cd rust && CT_LOCAL_PROGRAM=1 cargo test -- --test-threads 1
```

`test-vectors/confidential-transfers.json` is read by both test suites. Change it only on
purpose, and both suites must pass.

Dependencies are pinned with `=` to the exact set the official `spl-token-cli` uses, because the
Solana crate ecosystem is mid-migration (3.x → 4.x) and newer patches pull conflicting majors.
Keep `Cargo.lock` committed and in sync when changing dependencies.

## Pull requests

- Open an issue first for anything larger than a small fix, so we can align on the approach.
- Keep the two packages in parity where possible: a change to a helper's behavior should land in
  both TS and Rust, or explain why not. Known gaps today: the auditor report
  (`listConfidentialActivity`) is TypeScript only.
- Before pushing: unit tests pass, `tsc` is clean, and (for Rust) `fmt`/`clippy` are clean. CI runs
  all of these.
- Update [CHANGELOG.md](./CHANGELOG.md) under an `Unreleased` heading, and the docs if you change
  the public API. For a release, set `gitRevision` in `typedoc.json` to the new tag and run
  `npm run docs:api`.
- Keep commits focused and messages descriptive.

## Reporting security issues

Please do **not** open a public issue for vulnerabilities. See [SECURITY.md](./SECURITY.md).

## License

Arcantis is under the Business Source License 1.1, and Softseco also licenses it commercially.
Before we can merge a pull request from outside Softseco, its author signs a contributor licence
agreement that lets us do both; we send it when you open the pull request.
