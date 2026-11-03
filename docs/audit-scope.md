# Arcantis: audit scope

Prepared on 29 October 2026 for Arcantis's first independent audit, updated on 30 October for
the format checks ([formats.md](./formats.md)), on 2 November after a second review of our own and
on 3 November for transfers and withdrawals in one transaction. Arcantis is self-audited, not
independently audited. The code under audit is the commit tagged `v1.0.0-rc.1` in the public
`arcantis` repository, which this document describes.

The threat model ([threat-model.md](./threat-model.md)) is the companion to this page: what
Arcantis protects, who is trusted, the thirteen invariants and the tests that check them, the known
limits, the findings of our own review, and the questions we would like answered. This page says
what to read, how to build and test it, and how much of it the tests reach.

## In scope

| Path | What | Lines (code, without blank lines and comments) |
|---|---|---:|
| `src/` | The TypeScript package `@softseco/arcantis`: one file per operation (`configureAccount`, `deposit`, `applyPendingBalance`, `decryptBalance`, `transfer`, `withdraw`, `recoverProofAccounts`), keys (`keys.ts`), the auditor (`auditor.ts`, `auditorReport.ts`, with the JSON report and its reader), the `arcantis` command (`cli.ts`), the format names (`formats.ts`) and errors. | 1,425 |
| `src/internal/` | Proof construction (`confidentialTransferProof.ts`, adapted from `@solana-program/token-2022`), ciphertext arithmetic, the available-balance check, sending and signing (`send.ts`), transfer-hook resolution, account checks, and the two builds of the zk-sdk loader (`zk.ts` for Node, `zk.web.ts` for browsers). | 1,479 |
| `rust/src/` | The Rust crate `arcantis`: `ConfidentialClient` (`client.rs`), account checks, proof accounts, sending, keys, the auditor and errors, with their unit tests. | 2,915 |
| `package.json`, `package-lock.json`, `rust/Cargo.toml`, `rust/Cargo.lock` | Dependencies and their exact versions. | |

About 5,800 lines in all, 2,900 of them TypeScript. The two SDKs do the same things; reading one
closely and the other for differences is the efficient order, and the shared test vectors
(`test-vectors/`) pin where they must agree.

TypeScript dependencies (versions in `package-lock.json`): `@solana/kit` 8.3.0 (a peer
dependency), `@solana/zk-sdk` 0.5.3 (the WebAssembly build of the Rust zk-sdk),
`@solana-program/token-2022` 0.19.0, `@solana-program/zk-elgamal-proof` 0.4.0,
`@solana-program/system` 0.15.0, `@solana/sysvars` 8.3.0 and `@noble/curves` 1.9.7. Node 20.18 or
later.

Rust dependencies, pinned with `=` (see the comment in `rust/Cargo.toml` on why they move
together): `solana-zk-sdk` 7.0.1, `spl-token-client` 0.19.1,
`spl-token-confidential-transfer-proof-generation` 0.6.1,
`spl-token-confidential-transfer-proof-extraction` 0.6.1, `spl-token-2022` 11.0.0,
`spl-token-2022-interface` 3.1.1, `solana-sdk` 3.0.0 and `solana-client` 4.0.0-rc.0.
`rust/.cargo/audit.toml` lists the four RustSec advisories `cargo audit` ignores, with the reason
for each.

## Out of scope

- Token-2022, the ZK ElGamal Proof Program, and the libraries that generate and verify the
  proofs (`@solana/zk-sdk`, `solana-zk-sdk`). Arcantis relies on Token-2022 behaving as
  documented: it checks the source's and destination's ElGamal keys, the source's balance
  ciphertext and the auditor's key and ciphertexts against the proofs, and it accepts an
  `ApplyPendingBalance` whatever the expected credit counter (threat model, finding 1).
- `playground/`, `examples/` (including the Anchor program in `rust/examples/anchor-vault`),
  `docs/`, `guides/`, `test/`, `rust/tests/` and `scripts/`.
- The transfer-hook programs of particular mints, Sentinel and Vigilantis included (separate
  repositories).

## The SDK on one page

### Operations

| TypeScript | Rust (`ConfidentialClient`) | Signed by | Transactions | Token-2022 instructions |
|---|---|---|---|---|
| `configureAccount` | `configure_account` | payer, owner | 1 | `CreateAssociatedTokenAccountIdempotent`, `Reallocate`, `ConfigureAccount` with the pubkey-validity proof in the next instruction |
| `deposit` | `deposit` | payer, owner | 1 | `Deposit` (amount public) |
| `applyPendingBalance` | `apply_pending_balance` | payer, owner | 1 | `ApplyPendingBalance` |
| `decryptBalance` | `decrypt_balance`, `decrypt_balance_of` | owner (key message only) | 0 | none |
| `transfer` | `transfer` | payer, owner | 1 (TypeScript, a v1 transaction); 5 with proof accounts (Rust, or TypeScript's fallback) | the three proofs verified from instruction data, then `Transfer` with the hook's accounts, reading them at offsets −3, −2, −1; or the proofs verified into three context accounts, `Transfer`, and the accounts closed |
| `withdraw` | `withdraw` | payer, owner | 1 (TypeScript); 4 with proof accounts | the two proofs, then `Withdraw` (amount public) reading them at offsets −2, −1; or two context accounts, `Withdraw`, and the accounts closed |
| `recoverProofAccounts` | `recover_proof_accounts` | payer | 1 per 8 accounts | `CloseContextState` |
| `listConfidentialActivity`, `decryptTransferAmountAsAuditor`, `arcantis audit-report` | `decrypt_auditor_amount` | auditor (key message only) | 0 | none |
| | `prepare_configure`, `prepare_transfer`, `prepare_withdraw`, `pending_balance_update`, `transfer_hook_accounts`, `close_proof_accounts` | payer | proofs only | for a program that makes the Token-2022 calls through CPI |

Every operation that sends transactions first reads the accounts it needs and checks them (threat
model, invariant 4), then signs all its transactions together (one request per signer), simulates
each before sending it, and confirms it. In TypeScript a transfer or withdrawal is one v1
transaction, simulated with the largest limits before it is signed so that its compute units and
loaded account data can be set (`sendSingleTransaction` in `send.ts`); it falls back to proof
accounts when it would not fit or the caller sets `singleTransaction: false`. A transfer or
withdrawal with proof accounts that fails partway closes the proof accounts it created and says
which step failed.

### Keys

`deriveConfidentialKeys` (Rust `ConfidentialKeys::derive`) asks the wallet to sign
`solana-conf-bal/v1`, verifies the signature against the wallet's address, and expands it with the
zk-sdk's standard derivation into an ElGamal keypair and a 16-byte AES key. The seeded variant
signs `solana-conf-bal/v1 || seed`; `pdaWalletPublicSeed` (`pda_wallet_public_seed`) is the seed
convention for token accounts owned by a program. No key is ever stored by Arcantis. Before
asking for the signature, both SDKs check that the zk-sdk's message is exactly that
(`KEY_DERIVATION_SCHEME`, otherwise `UNSUPPORTED_FORMAT`); [formats.md](./formats.md) lists this
and every other format Arcantis reads or writes.

### Calls to other programs

- Token-2022: the instructions in the table above, built with `@solana-program/token-2022` and
  `spl-token-2022-interface`.
- ZK ElGamal Proof Program: `VerifyPubkeyValidity` (in the configure transaction),
  `VerifyCiphertextCommitmentEquality`, `VerifyBatchedGroupedCiphertext3HandlesValidity`,
  `VerifyBatchedRangeProofU128` (transfer), `VerifyBatchedRangeProofU64` (withdraw): from
  instruction data, in the transfer's or withdrawal's own transaction, or each into a
  context-state account created in the same transaction, and `CloseContextState`.
- Instructions sysvar: passed to `Transfer` and `Withdraw` when they read their proofs from the
  same transaction.
- System program: creating the context-state accounts. Associated Token Account program:
  `CreateIdempotent`. Compute Budget: `SetComputeUnitPrice` when a priority fee is asked for and
  the transaction has room; in a v1 transaction the compute-unit limit, loaded-account-data limit
  and priority fee are fields of the transaction itself.
- A mint's transfer-hook program is not called by Arcantis; Token-2022 calls it, with the accounts
  Arcantis appends.

### Errors

One error type in each SDK with a code: `INVALID_INPUT`, `ACCOUNT_NOT_FOUND`,
`ACCOUNT_NOT_CONFIGURED`, `ACCOUNT_ALREADY_CONFIGURED`, `ACCOUNT_NOT_APPROVED`,
`RECIPIENT_REJECTS_CONFIDENTIAL`, `PENDING_BALANCE_LIMIT`, `INSUFFICIENT_FUNDS`,
`AMOUNT_TOO_LARGE`, `KEYS_MISMATCH`, `DECRYPTION_FAILED`, `BALANCE_OUT_OF_SYNC`,
`UNSUPPORTED_FORMAT`, `CANNOT_SIGN_MESSAGES`, `BAD_MESSAGE_SIGNATURE`, `CRYPTO_UNAVAILABLE` (browser), `TRANSACTION_FAILED`,
`TRANSACTION_EXPIRED`, `TRANSACTION_OUTCOME_UNKNOWN` (TypeScript; in Rust a `TRANSACTION_FAILED`
whose `unknown_outcome()` names the transaction) and `RPC_ERROR`. Only `TRANSACTION_EXPIRED` is
retryable.

## Build and test

Toolchain: Node 22 (20.18 or later), Rust stable, Solana CLI and `solana-test-validator` from
Agave 4.2.2. The on-chain tests need Agave 4.x because older validators reject today's proofs, and
Token-2022 v11.1.0 from `test/fixtures` because the validator's bundled Token-2022 does not match
the client (see `test/fixtures/README.md`).

| What | Command |
|---|---|
| Install, build, typecheck | `npm ci`, `npm run build`, `npm run typecheck` |
| Local validator with Token-2022 v11.1.0, Sentinel and the Anchor example | `TOKEN_2022_SO=test/fixtures/spl_token_2022.so SENTINEL_SO=test/fixtures/sentinel.so CONFIDENTIAL_VAULT_SO=rust/examples/anchor-vault/target/deploy/confidential_vault.so npm run validator` |
| TypeScript tests (132: 106 without a validator, 26 on it) | `CT_LOCAL_PROGRAM=1 npm test` |
| TypeScript line coverage | `CT_LOCAL_PROGRAM=1 npm run coverage` |
| Browser test (the Vite example in Chromium, with a test wallet) | `npm run test:browser` |
| Rust checks | `cd rust && cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo audit` |
| Rust tests (40: 27 unit, 7 on-chain, the Anchor example, 4 shared vectors, a doctest) | `cd rust && CT_LOCAL_PROGRAM=1 cargo test -- --test-threads 1` |
| Rust line coverage | `cd rust && CT_LOCAL_PROGRAM=1 cargo llvm-cov -- --test-threads 1` |
| The Anchor example program | `cargo build-sbf --manifest-path rust/examples/anchor-vault/programs/confidential-vault/Cargo.toml` |
| Proofs against mainnet's ZK ElGamal Proof Program (simulation only) | `MAINNET_RPC=… npm run example:mainnet` |

CI runs all of these on every push except the coverage and the mainnet check. Without
`CT_LOCAL_PROGRAM=1` the on-chain tests are skipped and the rest still run.

## Coverage

TypeScript measured on 3 November 2026 with all 132 tests, on-chain ones included, against a local
validator; its line numbers are from that commit. Rust measured on 30 October, before the fixes of
2 November, which added 14 Rust tests; its line numbers are from that commit (Rust has not changed
since 2 November).

| | TypeScript (`c8`) | Rust (`cargo llvm-cov`) |
|---|---|---|
| Tests run | 132 | 26 |
| Lines reached | 4,197 of 4,281 (98.0%) | 1,387 of 1,700 (81.6%) |
| Counted | every line of `src/`, comments included, `src/internal/zk.web.ts` too (a test loads it the way a browser does; the browser test runs it in Chromium) | lines of code in `rust/src/`, the unit-test modules in those files included |
| Functions reached | 334 of 337 (99.1%; the three left are re-exported constants) | 150 of 207 (72.5%) |

What no test reaches, by theme:

- **A transaction whose blockhash expired** (TypeScript `send.ts` 286 and 304, Rust `send.rs`
  108–145). The decision is unit-tested in both (`outcomeAfterExpiry`, `outcome_after_expiry`); the
  code around it is not, because a local validator cannot be made to drop a confirmation on
  demand. Nor is Rust's `with_max_retries`.
- **Proof accounts that cannot be closed** (TypeScript `send.ts` 521–523, 548–549, 585–586; Rust
  `proofs.rs` 82–110, 139–155): the cleanup of the cleanup. Since 3 November a transfer or
  withdrawal only creates proof accounts when it falls back from one transaction.
- **Errors for malformed on-chain data and failed RPC requests** (most of the rest of
  `accounts.rs`, `client.rs` and `error.rs` in Rust; in TypeScript `auditor.ts` 108–111, 141–142
  and 151–152, `accounts.ts` 57–61, `send.ts` 172–173 and 526, `availableBalance.ts` 55–56 and
  `transferHook.ts` 213–214 and 243), and defensive checks that the public functions make before
  these are called (`confidentialTransferProof.ts` 115–119, 126–127, 141–142, 158–159, 506–507;
  `confidentialTransferArithmetic.ts` 108–109).
- **A simulation that does not report the accounts it loaded** (`send.ts` 454): the single
  transaction then keeps the 64 MiB limit it was simulated with.
- **TypeScript only:** the `arcantis` command's usage and error output (`cli.ts` 44–46, 64–76,
  118–119), a pending balance too large to decrypt (`applyPendingBalance.ts` 81–91), a transfer
  with fee in the auditor's report (`auditorReport.ts` 266–272), and the browser build's error
  when the WebAssembly is not loaded yet (`zk.web.ts` 76–81).

## Earlier reviews

No independent audit. Our own reviews, on 29 October and 2 November, found the issues listed with
their effect and status in the threat model: fixed, or documented as known limits. Security contact: [SECURITY.md](../SECURITY.md).
