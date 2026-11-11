# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This repository holds Arcantis: the TypeScript package `@softseco/arcantis` and the Rust crate
`arcantis`. Until 28 Oct 2026 they were published as `@softseco/confidential-transfers` (up to
3.3.0) and `softseco-confidential-transfers` (up to 3.0.0); that history is kept below. Up to 2.0.0
the two were released together under one version, and from 2.1.0 each had its own versions: the
TypeScript package tagged `vX.Y.Z`, the Rust crate `rust-vX.Y.Z` (entries headed `rust-X.Y.Z`).

## [1.0.0-rc.3] - 2026-11-11

The pending balance applied where it is spent, an apply that cannot leave the balance copies apart,
a pinned recipient key and closing an account, in both the TypeScript package and the Rust crate.
Both move to 1.0.0-rc.3. Self-audited, not independently audited.

### Added

- **What is pending can be spent at once.** A one-transaction `transfer` or `withdraw` applies the
  pending balance first, in the same transaction, and builds its proofs from the balance after it,
  computed with Token-2022's own arithmetic (`add_with_lo_hi`). A recipient of earlier payments no
  longer has to call `applyPendingBalance` before spending them. Option `applyPending` (TypeScript,
  default `true`) and `with_apply_pending` (Rust). With proof accounts (the fallback) only the
  available balance is spent, as before.
- **A checked apply.** `applyPendingBalance` / `apply_pending_balance` sends the apply with a
  withdraw of zero in the same v1 transaction, whose proof is about the exact balance the apply
  should leave. A deposit or transfer that lands between reading the account and the transaction
  makes Token-2022 refuse both (`ConfidentialTransferBalanceMismatch`, 0x1b) instead of leaving
  the AES copy behind; the call reads the account again, up to three times in all. About 130,000
  compute units more. Option `verify` (TypeScript) and `with_checked_apply` (Rust), default on; a
  frozen account or a paused mint gets the plain apply. Threat model: known limit 3, invariant 7,
  change of 6 November.
- **A pinned recipient key.** `transfer({ destinationElgamalPubkey })` (TypeScript) and
  `transfer_to_known_key` (Rust) refuse the transfer, before anything is encrypted or signed, when
  the RPC reports another ElGamal key for the recipient's account (`RECIPIENT_KEY_MISMATCH`, new
  code in both). Threat model: known limit 12.
- `decryptBalance({ includePending: true })` (TypeScript) and `decrypt_balance_with_pending`
  (Rust): available plus pending, which is what a transfer or withdraw can now spend.
- Accounts a program owns (TypeScript, as the Rust crate's `prepare_*`): `prepareConfigure`,
  `prepareApply`, `prepareWithdraw` and `prepareTransfer` build the Token-2022 instructions with
  the program's PDA as authority and the proofs inside the transaction, for the program to check
  and sign through CPI. The program keeps each Token-2022 instruction at its position, so the proof
  offsets stay right. `prepareWithdraw` with amount 0 is a checked apply. The eUSD issuance
  program (PAPER) moves its treasury accounts this way.
- `closeAccount` (TypeScript) and `close_account` (Rust): close an emptied confidential account
  and return its rent deposit, in one transaction (an apply if anything is pending, a
  zero-ciphertext proof, `EmptyAccount`, `CloseAccount`). Refused while the account holds a public
  or confidential balance, or is frozen.

### Changed

- `listConfidentialActivity` and `arcantis audit-report` leave out withdraws of zero, which move
  nothing (the checked apply sends one).
- Rust: the crate depends directly on `spl-token-confidential-transfer-ciphertext-arithmetic`
  0.5.1, the version `spl-token-2022` 11.0.0 already uses.

### Tests

- TypeScript `test/pending.test.ts`: a checked apply built before a credit lands is refused by
  Token-2022 and changes nothing; a transfer of more than the available balance spends the pending
  part in one transaction; a withdraw from what is pending; `applyPending: false` keeps the old
  rule; a wrong pinned key is refused and the right one goes through; `closeAccount` refuses a
  funded account and closes an emptied one, returning its rent.
- Rust `spends_what_is_pending_checks_its_apply_and_pins_the_recipient_key`: the transfer's
  transaction holds the apply and then the transfer; the checked apply calls the ZK program and the
  plain one does not; the copies agree after each step; the pinned key.
- TypeScript `test/programAccounts.test.ts`: an owner that signs only through its "program"
  configures, applies with a check, transfers and withdraws; a source of another owner is refused.
- Rust `closes_an_emptied_account_and_refuses_one_that_still_holds_tokens`: refused with a
  pending and then a public balance, closed once empty, the rent back to the owner.

### Licence

- 1.0.0-rc.3 becomes Apache-2.0 on its Change Date, 2030-11-11 (`LICENSE`, `rust/LICENSE`).

## [1.0.0-rc.2] - 2026-11-05

The Rust crate's transfers and withdrawals in one transaction, as in the TypeScript package. Both
move to 1.0.0-rc.2; the TypeScript package's code is unchanged. Self-audited, not independently
audited.

### Added

- **Rust: a transfer or withdrawal in one transaction**, as in the TypeScript package since
  1.0.0-rc.1. `transfer` and `withdraw` send the proof verifications and the transfer or withdraw
  together, in one v1 transaction of up to 4,096 bytes (SIMD-0385), instead of five or four sent
  one after another: no proof accounts, no rent held while they are open, nothing to clean up when
  the chain refuses. The transaction is simulated with the largest limits before it is signed; its
  compute-unit limit (+20%) and loaded-account-data limit (+10%) are set from that simulation, and
  `with_compute_unit_price` becomes the v1 message's priority fee (price times the unit limit,
  rounded up). The Solana client crates the crate pins predate v1 messages, so the message is
  compiled with `solana-message` 6.0.0 and the transaction is signed, simulated and sent as bytes
  through the same `RpcClient`. Measured on a local validator through Sentinel as the transfer
  hook: 2,690 bytes and 14 accounts, as in TypeScript. Threat model: invariant 8 and finding 17.
- `ConfidentialClient::with_single_transaction(false)` keeps the proof accounts, for an RPC that
  does not take v1 transactions. The client also falls back to them by itself, before signing,
  when one transaction would be too large (a transfer hook with many accounts).
- Tests: `v1::tests` (the message starts with the v1 version byte, lists its signers payer first,
  reads back with `solana-message` with its budget and instructions, and does not fit above 4,096
  bytes or 64 accounts; the budget's arithmetic). The on-chain tests check that a transfer and a withdrawal are
  one v1 transaction each, with the proofs next to them and the priority fee in the message, that
  a hook's refusal is caught in simulation with nothing sent, and still cover the proof-account
  path.

### Changed

- `TransferResult::signatures` and `WithdrawResult::signatures` hold a single signature when the
  operation went in one transaction, and `proof_accounts_left_open` is then empty. A transfer that
  a transfer hook or Token-2022 refuses fails in its simulation: nothing is sent, and the error
  has no proof accounts (`Error::proof_accounts` is `None`).
- Dependencies: `solana-message` 6.0.0 (with its `wincode` feature) is new; `base64` and
  `serde_json` are now direct dependencies (they were already in the tree through
  `solana-client`). `Cargo.lock` moves `solana-address` to 2.9.0, `solana-hash` to 4.7.0 and
  `solana-pubkey` to 4.4.0, which `solana-message` 6 needs.
- The crate's README (`rust/README.md`) starts with the project's banner, for crates.io.

### Licence

- 1.0.0-rc.2 becomes Apache-2.0 on its Change Date, 2030-11-05 (`LICENSE`, `rust/LICENSE`).

## [1.0.0-rc.1] - 2026-11-03

The release candidate for Arcantis's first independent audit, and the first release under the new
name and the Business Source License 1.1. Self-audited, not independently audited.

### Added

- **A transfer or withdrawal in one transaction** (TypeScript). Since 15 September 2026 Solana takes
  v1 transactions of up to 4,096 bytes, and Token-2022 can read a transfer's proofs from earlier
  instructions of the same transaction. `transfer` and `withdraw` now send the proof
  verifications and the transfer or withdraw together, in one transaction, instead of five or four
  sent one after another: no proof accounts, no rent held while they are open, nothing to clean up
  when the chain refuses. The transaction is simulated with the largest limits before it is
  signed, and its compute units and loaded account data are set from that simulation. On a local
  validator, with Vigilantis as the transfer hook: 2,690 bytes, 14 accounts, about 280,000 compute
  units. The fee payer can be someone else than the owner, such as a relayer, so the sender needs
  no SOL. `singleTransaction: false` keeps the proof accounts, for a wallet or an RPC that cannot
  handle v1 transactions (the Vite example passes it when the wallet does not list version 1); the SDK also falls back to them by itself when the one transaction would
  be too large (a transfer hook with many accounts). The Rust crate keeps proof accounts until it
  moves to `solana-message` 4.4 or later. Threat model: invariant 8 and finding 17.
- **Named and versioned formats** ([docs/formats.md](./docs/formats.md)): every format Arcantis
  reads or writes, who defines it, how it is recognised, and how a change to one is handled. The
  names are constants: `KEY_DERIVATION_SCHEME` (`"solana-conf-bal/v1"`, in both SDKs),
  `CONFIDENTIAL_ACTIVITY_FORMAT` and `CONFIDENTIAL_ACTIVITY_VERSION`.
- **Key derivation checks its message.** Both SDKs refuse to derive keys if the zk-sdk they run on
  would sign anything other than `solana-conf-bal/v1` (followed by the seed): such keys would match
  none of the wallet's accounts. New error code `UNSUPPORTED_FORMAT`
  (`ErrorCode::UnsupportedFormat` in Rust).
- **The auditor report as versioned JSON.** `confidentialActivityToJson` writes the activity with
  `"format": "arcantis.confidential-activity", "version": 1`, the mint, the auditor key, the
  decimals and the time it was made; slots and amounts are decimal strings.
  `parseConfidentialActivityJson` reads it back, refuses another format or a newer version
  (`UNSUPPORTED_FORMAT`) and a damaged file (`INVALID_INPUT`). `arcantis audit-report --format
  json`, or an `--out` name ending in `.json`, writes it from the command line.
- Tests: `test/formats.test.ts` (7, no validator), the JSON report from the command line in
  `auditorReport.test.ts`, and two Rust unit tests of the derivation message. The CSV header is
  pinned by a test: columns are only ever added at the end.

### Changed

- The auditor's reads (`decryptTransferAmountAsAuditor`, `listConfidentialActivity`, `arcantis
  audit-report`) ask the RPC for v1 transactions too, so they read one-transaction transfers.
- Licence: the Business Source License 1.1 ([LICENSE](./LICENSE), in plain words
  [COMMERCIAL-LICENSE.md](./COMMERCIAL-LICENSE.md)) instead of all rights reserved. Testing and
  development are free for everyone. Production use is free with eUSD, and with other tokens for
  companies whose Total Finances are up to USD 5,000,000, after a notice to
  developers@softseco.com; above that it needs a commercial license. Each version becomes
  Apache-2.0 four years after its release (Change Date 2030-11-03 for this one). `rust/LICENSE` and `rust/NOTICE`, which still carried
  the Apache-2.0 text of the public repository, now carry the same licence, and the playground
  says "Source-available · BUSL 1.1" instead of "Open source · Apache-2.0".
- New name. The TypeScript package is `@softseco/arcantis` (was `@softseco/confidential-transfers`)
  and its command is `arcantis` (was `confidential-transfers`); the Rust crate is `arcantis` (was
  `softseco-confidential-transfers`), so Rust code imports `arcantis::`. Functions, types, keys
  and error codes are unchanged.
- Both start again at 1.0.0. The earlier versions stay published under Apache-2.0.
- `package.json` and `rust/Cargo.toml` no longer block publishing (`private`, `publish = false`),
  for this release.
- `package.json` writes the `bin` path as npm normalizes it (`dist/cli.js`), so `npm publish` no
  longer warns.
- The playground (`playground/`, served at softseco.github.io/arcantis) runs a confidential token
  with Vigilantis as its transfer hook, freeze and pause authority: ten steps from a confidential
  payment to a blocked wallet, a frozen account, a paused token and the auditor's report, in the
  design of softseco.com. It encodes Vigilantis's instructions from a copy of its IDL
  (`npm run check` compares the copy). Its transfers and withdraws are one transaction each, and
  it polls for confirmations about once a slot.

### Removed

- Rust: the 2.x free functions (`configure_account`, `deposit`, `apply_pending_balance`,
  `decrypt_balance`, `transfer`), deprecated since 3.0.0. Use `ConfidentialClient`, which they
  only wrapped.

### Fixed

- **An account whose AES balance copy fell behind is no longer stuck.** Token-2022 keeps the
  available balance twice: encrypted under ElGamal, and as an AES copy the owner writes with each
  apply, transfer and withdraw. When a deposit or transfer arrives between the owner reading the
  account and its `ApplyPendingBalance`, Token-2022 applies it but keeps the copy computed without
  it, and every transfer or withdraw built from that copy was then refused on chain. An account
  that receives many payments runs into this in normal use. Both SDKs now check the copy against
  the encrypted balance whenever they read it and recover what it missed (a difference below 2^32
  base units). `decryptBalance` returns the real balance, and the next transfer, withdraw or apply
  writes a correct copy. A larger difference is the new error code `BALANCE_OUT_OF_SYNC`
  (`ErrorCode::BalanceOutOfSync` in Rust).

- **A transaction that landed is no longer reported as expired.** When no confirmation arrived
  before a transaction's blockhash expired, both SDKs called it expired, and the TypeScript SDK's
  `retries` then ran the whole operation again; if the transaction had landed after all (a
  confirmation the RPC failed to deliver), a transfer or deposit went out twice. They now look up
  the transaction's status first: one that landed counts as sent, one that failed is
  `TRANSACTION_FAILED` with its logs, and one whose status cannot be read is `TRANSACTION_FAILED`,
  not retried. Only a transaction the RPC has no record of is `TRANSACTION_EXPIRED`.

- **TypeScript: transfer-hook accounts resolve the way the SPL interface resolves them.** An
  extra-account-meta entry that stores an address in instruction or account data (`PubkeyData`)
  failed with a confusing error; it now resolves, as it always did in the Rust crate. Entries that
  read past the end of the instruction or of an account's data, a list that claims more entries
  than it holds, and a hook mint with no extra-account-meta list are now refused before signing
  with `ACCOUNT_NOT_FOUND`, like the Rust crate, instead of producing a transfer that fails on
  chain. Only the list's entry for the hook's `Execute` instruction is read, and an entry that
  names an account already in the list read-only (the mint, say) stays read-only, as the SPL
  resolver keeps it.

- **TypeScript: `decryptTransferAmountAsAuditor` reads only transfers that happened.** It decrypted
  the amount of a transaction that had failed, which transferred nothing; it now refuses it with
  `TRANSACTION_FAILED`. It also finds a transfer that a program made through a cross-program call,
  and accounts from address lookup tables, as `listConfidentialActivity` already did.

### Security

Fixes from a second review of our own before this release; findings 6–16 in the
[threat model](./docs/threat-model.md).

- **A transfer hook can no longer get a signer.** Both SDKs refuse, before signing, a hook account
  list that names the payer, the owner or another signer of the transaction (TypeScript
  `INVALID_INPUT`, Rust `InvalidInput`): signer status belongs to the whole transaction, so the hook
  would receive that account as a signer, and could spend a relayer's SOL.
- **A transaction that may have landed is no longer reported as failed.** After a lost
  confirmation, an HTTP 5xx or a timeout, both SDKs settle the outcome from the transaction's
  status: landed is success, not found after its blockhash expired is `TRANSACTION_EXPIRED` (the
  only retryable case), and a status that cannot be read is an unknown outcome naming the
  transaction (TypeScript `TRANSACTION_OUTCOME_UNKNOWN` with `error.signature`; Rust
  `Error::unknown_outcome()`). The proof accounts of a step whose outcome is unknown are left alone.
  In TypeScript, "not found" is trusted only from a node that has itself seen the blockhash expire,
  an error on a transaction that is only processed is not final, and a transaction whose wallet
  changed its blockhash is never called expired.
- **Rust: RPC errors no longer carry the RPC URL's path, query or user info**, where providers put
  API keys.
- **Amounts are kept out of error messages** in both SDKs (Rust: `Error::available_balance()`).
- **Auditor's report:** CSV fields that start like a formula get a leading `'`; addresses from the
  RPC are checked; a transaction the RPC cannot return stops the report with the new `RPC_ERROR`
  instead of leaving a gap; `concurrency`, `maxTransactions`, `since` and `until` are validated; the
  JSON reader caps `decimals` at 255 and allows `decrypted: true` only on transfers with an amount.
- **`arcantis` command:** a piped report is written in full before the command exits; a keypair
  file is never quoted in an error; times without an offset are read as UTC; new report files are
  created readable by their owner only.
- Rust: rustls 0.23.46, rustls-webpki 0.103.16, webpki-roots and webpki-root-certs 1.0.11,
  ctutils 0.4.6, zstd-sys 2.1.2 and zstd-safe 7.3.0 in `Cargo.lock`, for the RustSec advisories of
  14 and 23 October 2026. Four advisories have no fix that the Solana crates accept yet
  (crypto-bigint 0.5, zstd 0.13, zstd-safe 7); `rust/.cargo/audit.toml` says why each is not reached
  in a way that matters, so `cargo audit` passes until the fixes land.

### Fixed (second review)

- `recoverProofAccounts` reads accounts 100 at a time and retries a failed batch of closes one
  account at a time.
- `decryptTransferAmountAsAuditor` reports a wrong key as `DECRYPTION_FAILED`, and takes an
  optional `mint`.
- The browser build remembers the `wasmUrl` given to `initConfidentialTransfers`, and a failed load
  no longer blocks a later one.
- `transfer` and `withdraw` refuse a paused mint and a frozen account, and `transfer` a mint with a
  transfer fee, before any proof is built (Rust: also a source that is not approved, and the
  hook's accounts are resolved first).
- `transfer` refuses a `destinationOwner` that does not own `destinationToken`;
  `configureAccount` refuses a `maximumPendingBalanceCreditCounter` outside 1 to 65536.
- Rust: `read_token_account` refuses accounts not owned by Token-2022.

### Rust crate API, before 1.0

- `ConfidentialClient` and its futures are `Send`: the payer is `Arc<dyn Signer + Send + Sync>`
  and owners are `&(dyn Signer + Sync)`.
- Re-exports `solana_client`, `solana_sdk` and `solana_zk_sdk`; use them to avoid version
  mismatches with the exact versions the crate is built on.
- `ProofAccounts` gains `unverified` and `unknown`; transfer and withdraw results gain
  `proof_accounts_left_open`; `ProofAccounts` and the result structs are `#[non_exhaustive]`.
- `spl-token-client` without its default features: 64 fewer crates, no clap 2 or libusb.
- `rust-version = "1.89"`, docs.rs metadata, README and NOTICE links that work on crates.io.

### Tests

- TypeScript: 132 tests (37 new: the CLI, the pre-signing checks, the browser loader, sending,
  one-transaction transfers and their fallback, hooks, the report and formats). The browser test
  checks that a wallet that signs v1 transactions signs five for the five steps. Rust: 40 (14 new, among them the URL redaction, `Send`, the
  unknown outcome against a mock RPC and the hook signer check).
- Shared test vectors with the Rust crate (`test-vectors/confidential-transfers.json`): key
  derivation, the PDA-wallet seed, an auditor's transfer amount and an AES balance, checked by
  both test suites.

## [rust-3.0.0] - 2026-10-12

The Rust crate catches up with the TypeScript SDK. Breaking: a client type replaces the free
functions, which stay for now as deprecated wrappers.

### Added

- `ConfidentialClient` over an `Arc<RpcClient>` and a payer: `configure_account`, `deposit`,
  `apply_pending_balance`, `decrypt_balance`, `transfer` and, new, **`withdraw`**.
- **Transfer hooks.** `transfer` resolves the accounts a mint's hook needs and passes them along.
  Tested with Sentinel as the hook, refusing and then allowing a confidential transfer.
- **Cleanup when a transfer or withdraw fails partway**: the proof accounts created so far are
  closed, and the error names the step and the accounts (`Error::step`, `Error::proof_accounts`).
  `recover_proof_accounts()` closes any left by a process that stopped. On success the proof
  accounts are closed in the transfer's own transaction.
- **Checks before signing**, with the TypeScript SDK's error codes: `Error` and `ErrorCode`
  (`ACCOUNT_NOT_FOUND`, `ACCOUNT_NOT_CONFIGURED`, `PENDING_BALANCE_LIMIT`, `INSUFFICIENT_FUNDS`,
  `AMOUNT_TOO_LARGE`, `KEYS_MISMATCH`, ...). Every transaction is simulated first, so a failure
  comes with the program logs.
- Priority fees (`with_compute_unit_price`) and resending after an expired blockhash
  (`with_max_retries`).
- **Accounts owned by a program**: `ConfidentialKeys::derive_for_pda_wallet` and
  `pda_wallet_public_seed` (the TypeScript SDK's convention), and `prepare_configure`,
  `prepare_transfer`, `prepare_withdraw`, `pending_balance_update`, `transfer_hook_accounts`,
  `close_proof_accounts`, so a program can make the Token-2022 calls through CPI.
- `examples/anchor-vault`: an Anchor program that holds a confidential balance in a PDA-owned
  account and pays out of it, through a transfer hook, with the mint's auditor reading each payout.
  Tested on a local validator.
- `ConfidentialKeys` (`derive`, `derive_with_seed`); key derivation now checks that the signature
  verifies.

### Changed

- `transfer` reads the mint's auditor key itself; the 2.x `transfer` ignores its
  `auditor_elgamal_pubkey` argument.
- Errors are this crate's `Error` instead of `Box<dyn Error>`.
- The 2.x free functions are deprecated wrappers over `ConfidentialClient`; `decimals` is read from
  the mint.

### Tests

- On-chain tests (gated by `CT_LOCAL_PROGRAM=1`): the full flow with an auditor, a priority fee and
  a withdraw; every check before signing; a transfer through Sentinel; recovery of proof accounts;
  the Anchor example. The shared test vectors replace the single pinned vector. CI runs them on a
  local validator with Token-2022 v11.1, Sentinel 2.1.0 and the example program.

## [3.3.0] - 2026-10-12

For auditors. No breaking changes.

### Added

- `listConfidentialActivity({ rpc, mint, auditorKeypair })` reads a mint's transaction history and
  lists every deposit, confidential transfer and withdraw, oldest first, with the transferred
  amounts decrypted with the auditor key. It finds the instructions inside other programs' calls
  too, works with transactions built by any client, skips failed transactions, and takes
  `since`, `until`, `maxTransactions` and `concurrency`. It checks that the key is the mint's
  auditor key (`KEYS_MISMATCH` otherwise; `skipAuditorKeyCheck` lists what the key can read).
- `confidentialActivityToCsv(activity, { decimals })`: the list as CSV (RFC 4180, UTC times).
- A command line: `npx @softseco/confidential-transfers audit-report --mint … --keypair … --rpc …`
  writes the report as CSV, with the auditor key derived from the auditor's wallet file.
- A guide for auditors (`guides/auditors.md`), also in the API reference.

### Changed

- `transfer` reads the mint's auditor key itself when `auditorElgamalPubkey` is not given. Before,
  a transfer on a mint with an auditor failed on chain unless the caller passed the key.

## [3.2.0] - 2026-10-12

Reliability, for mainnet. No breaking changes for code that awaits these functions and handles a
thrown error; see Changed for what is different.

### Added

- **One wallet prompt per operation.** `transfer` (five transactions) and `withdraw` (four) plan
  all their transactions first and have each signer sign them together, so a browser wallet asks
  once instead of five or four times. They are then sent in order, each simulated first.
- **Cleanup when a step fails halfway.** If a transaction fails before the transfer or withdraw
  itself lands (in simulation, on chain, or because it expired), the proof accounts already
  created are closed again and their rent returned to the payer. The error says which step failed
  (`step`: `"proofs"` or the operation), which transactions landed, and which proof accounts were
  closed or left open.
- `recoverProofAccounts({ rpc, rpcSubscriptions, authority })` finds proof accounts a stopped
  process left behind (the authority is the payer of the transfer) and closes them.
- **Typed errors.** Everything the SDK throws on purpose is a `ConfidentialTransfersError` with a
  `code` (`INSUFFICIENT_FUNDS`, `PENDING_BALANCE_LIMIT`, `ACCOUNT_NOT_FOUND`,
  `ACCOUNT_NOT_CONFIGURED`, `KEYS_MISMATCH`, `TRANSACTION_FAILED`, `TRANSACTION_EXPIRED` and
  others), `operation`, program `logs` when there are any, and `retryable`.
  `isConfidentialTransfersError(error, code?)` checks it.
- **Checks before signing.** `deposit` and `transfer` check that the account (for a transfer, the
  recipient's) exists, is configured and approved, accepts confidential credits and has room for
  one more pending credit, and that the amount fits (at most 2^48 - 1 per deposit or transfer) and
  is covered. A doomed operation now fails before a wallet opens.
- `computeUnitPrice` on every sending function: a priority fee in micro-lamports per compute unit,
  added to each transaction that has room for it. (The range-proof transaction of a transfer is too
  full to take one.)
- `retries` on every sending function: run the operation again when a transaction expires before
  it is confirmed. Default 0, since a retry signs new transactions and a wallet asks again.
- `examples/mainnet.ts` (`npm run example:mainnet`): checks in a free simulation that mainnet's ZK
  ElGamal Proof Program accepts the SDK's proofs and, with `--send`, runs the whole flow with a
  test token and tiny amounts (about 0.01 SOL, mostly rent).

### Changed

- Errors are `ConfidentialTransfersError` instead of plain `Error` (still `instanceof Error`, with
  the same kind of message). Calls that used to fail in simulation now fail earlier with a specific
  code: `configureAccount` on a configured account (`ACCOUNT_ALREADY_CONFIGURED`), `deposit` into
  an unconfigured account (`ACCOUNT_NOT_CONFIGURED`), a transfer to a missing account
  (`ACCOUNT_NOT_FOUND`).
- `transfer` and `deposit` refuse an amount of zero.
- `transfer` and `withdraw` results have `proofAccountsLeftOpen`, normally empty.
- `applyPendingBalance` explains when the pending balance cannot be decrypted because incoming
  amounts add up to more than about 2^48 base units (`DECRYPTION_FAILED`), instead of passing on
  the zk-sdk's error.

## [3.1.0] - 2026-10-12

Web apps. No breaking changes: code written for 3.0 works unchanged.

### Added

- **Browser build.** The package has a second build for browsers (`dist/browser`), selected by the
  `browser` export condition, so Vite, webpack 5 and other bundlers use it with no alias. It loads
  `@solana/zk-sdk`'s WebAssembly on first use. The bundler alias the 3.0.1 README described is no
  longer needed.
- `initConfidentialTransfers({ wasmUrl? })` starts loading the WebAssembly early, or loads it from
  a URL you serve. In Node it does nothing.
- **Browser wallets.** Key derivation accepts any kit `MessageSigner`, including the
  `MessageModifyingSigner` that `@solana/wallet-account-signer` makes from a Wallet Standard
  wallet. The signature is verified against the wallet's address, and a wallet that changes the
  message is refused, since the keys would then differ from the standard ones. A signer that
  cannot sign messages gets an error that says so.
- **`keys` option** on `configureAccount`, `applyPendingBalance`, `decryptBalance`, `transfer` and
  `withdraw`: pass the keys from `deriveConfidentialKeys` and the call does not ask the wallet to
  sign again. A web app asks once per session.
- Before decrypting or building a proof, `applyPendingBalance`, `decryptBalance`, `transfer` and
  `withdraw` check that the keys match the account's ElGamal key, and fail with a clear error if
  not.
- `examples/vite`: a web app (connect a wallet, unlock, set up, deposit, apply, send, withdraw).
- A guide for web apps (`guides/web-apps.md`) and an API reference generated with TypeDoc, at
  https://softseco.github.io/confidential-sdk/api/.
- CI runs the on-chain integration tests and a browser test on a local Agave 4.2 validator: the
  Vite example in Chromium with a Wallet Standard test wallet, through the whole flow, on the
  production build and the dev server. The Token-2022 build the tests need is in
  `test/fixtures/` (v11.1.0, with its hash and how to rebuild it).

### Changed

- `owner` is typed `TransactionSigner` (was `TransactionSigner & MessagePartialSigner`), and
  `decryptBalance`'s `owner` can also be a `MessageSigner`; whether the owner can sign messages is
  checked when keys are needed. `deriveAuditorElgamalKeypair` and the `derive*` key functions take
  a `MessageSigner`. Every value accepted before is still accepted.
- `applyPendingBalance`, `decryptBalance`, `transfer` and `withdraw` read the account before
  asking for the key signature, so a missing or unconfigured account fails before the wallet is
  bothered.

## [3.0.1] - 2026-10-12

Documentation only. No code changes: the published `dist/` is built from the same source as 3.0.0.

### Changed

- The README on npm now links the [browser playground](https://softseco.github.io/confidential-sdk/),
  which runs the whole flow on devnet in a browser tab.
- The README explains how to use the SDK in a browser today (one bundler alias from
  `@solana/zk-sdk/node` to its web build) instead of saying it does not run there.
- The auditor example imports `transfer`, which it calls.

## [3.0.0] - 2026-09-28

### Changed

- **BREAKING: built on `@solana/kit` 8** (was 6), with `@solana-program/token-2022` 0.19,
  `@solana-program/zk-elgamal-proof` 0.4, `@solana-program/system` 0.15 and `@solana/sysvars` 8.
- **`@solana/kit` is now a peer dependency** (`^8.3.0`). With kit as a regular dependency, an app
  on kit 8 got a second, nested copy of kit 6, and every call failed type-checking because the
  app's `Rpc` and `RpcSubscriptions` were not assignable to the SDK's. Now the app and the SDK
  share one copy.
- A clean `npm install` no longer prints peer-dependency warnings, and the repository no longer
  needs `legacy-peer-deps` (`.npmrc` removed).
- Requires Node ≥ 20.18 (the minimum for `@solana/kit` 8).

### Added

- `withdraw()` moves tokens from the confidential available balance back to the public balance.
  It generates the ciphertext-commitment equality proof and a U64 range proof on the remaining
  balance, verifies both into context-state accounts, runs the withdraw and closes the proof
  accounts. Run end-to-end on devnet.
- `examples/devnet.ts` now includes a withdraw step and runs with `npm run example:devnet`. The
  README explains how to try the SDK on devnet in a few commands.
- `npm run typecheck` also type-checks the examples, so they cannot drift from the API unnoticed.
- Package keywords, homepage and issue tracker in `package.json`.

### Migration from 2.x

Move your app to `@solana/kit` 8. Function signatures and key derivation are unchanged, so
accounts configured with 2.x keep working.

### Notes

- The Rust crate is unchanged at 2.0.0. It has no `withdraw`, and its `transfer` does not resolve
  transfer-hook accounts.

## [2.1.0] - 2026-09-23

### Added

- `transfer()` now resolves a mint's transfer-hook accounts and appends them to the confidential
  transfer instruction. Token-2022 invokes the hook on a confidential transfer with an amount of
  `u64::MAX`, and without those accounts the transfer fails with `MissingAccount`. Mints without a
  transfer hook are unaffected.
- `resolveTransferHookAccounts`, `getTransferHookProgram` and `findExtraAccountMetaListPda` are
  exported for callers that build their own instructions.

### Notes

- The Rust crate is unchanged at 2.0.0.

## [2.0.0] - 2026-09-19

### Changed
- **BREAKING — key derivation now follows the ecosystem standard.** Both the TypeScript package
  and the Rust crate derive the ElGamal and AES keys from a single signature over the constant
  message `solana-conf-bal/v1`, expanded through HKDF-SHA512 (`ConfidentialKeys` in
  `@solana/zk-sdk`, `derive_confidential_keys` in `solana-zk-sdk`). Keys are bound to the signing
  wallet alone — one ElGamal keypair and one AES key across every mint and token account — and are
  byte-identical to what the Token-2022 clients and every other standard client derive for the
  same wallet.
- **TypeScript** — requires `@solana/zk-sdk` >= 0.5.3, which replaces the per-key
  `ElGamalKeypair.signerMessage` / `AeKey.signerMessage` derivation with the unified
  `ConfidentialKeys` API.
- **Rust** — requires `solana-zk-sdk` 7, where `encryption::derivation` lives, together with
  `spl-token-client` 0.19.1 and `spl-token-confidential-transfer-proof-generation` 0.6.1. All
  three move as a set: the 0.19.0 and 0.6.0 releases are built against `solana-zk-sdk` 6, and a
  graph holding two majors compiles but does not type-check, because `ElGamalKeypair` from one
  major is a different type from `ElGamalKeypair` in the other.

### Fixed
- **The two language bindings derived different keys.** TypeScript seeded the derivation with the
  64-byte tuple `(owner, mint)`; Rust seeded it with the 32-byte token account address. An account
  configured with one binding therefore could not be read with the other, and neither matched the
  spl-token CLI. The existing cross-language test compared the two implementations at the
  primitive level — the same signer and the same explicit seed — so it passed while the two halves
  fed that primitive different seeds. Found in review, before any mainnet use.

### Added
- `deriveConfidentialKeys({ signer })` — the standard derivation, one signature for both keys.
- `deriveConfidentialKeysWithSeed({ signer, publicSeed })` — explicitly non-standard, seed-scoped
  derivation for schemes that need keys scoped more finely than the wallet.
- `pdaWalletPublicSeed({ programId, walletPda, mint, tokenAccount })` — the canonical seed for
  single-signer PDA wallets, so PDA and passkey wallets share one convention.
- `getElGamalPubkeyAddress(keypair)` — an ElGamal public key as an `Address`.
- Tests that pin the derivation message bytes, pin a standard-derivation vector, and assert that
  every derivation helper in the package agrees — the drift above cannot recur silently.

### Removed
- `deriveConfidentialKeypairs`, `deriveElGamalKeypairForOwnerMint` and `deriveAeKeyForOwnerMint`.
  They are not deprecated wrappers, because a wrapper that ignored its own `owner` and `mint`
  arguments would silently return different keys than 1.x did. `deriveElGamalKeypair` and
  `deriveAeKey` remain but no longer take a `publicSeed`.

### Migration
Keys derived by 1.x and 2.0 are different. There is no in-place migration, because the on-chain
account stores the ElGamal public key that the old derivation produced. Apply the pending balance
of a 1.x account and move its available balance out with a 1.x `transfer` to an account
configured with 2.0. (Neither 1.x nor 2.0 had a `withdraw`; it arrived in 3.0.0.)

## [1.0.1] - 2026-07-14

### Fixed
- **TypeScript** — `transfer` now rejects amounts above the confidential-transfer maximum
  (`2^48 - 1`) with a clear error instead of producing an invalid range proof. Found in a
  self-audit; covered by a unit test.
- **Rust** — `transfer` no longer builds an oversized transaction. Its three ZK proofs are now
  verified into temporary **context-state accounts** (closed afterwards to reclaim rent), mirroring
  the TypeScript SDK, so the transfer transaction fits Solana's 1232-byte limit. The previous inline
  proofs produced a ~3308-byte transaction that always failed. Covered by a gated Rust integration
  test (`rust/tests/ct_integration.rs`).

## [1.0.0] - 2026-07-13

First stable release. No functional changes to the API surface over `0.2.0`; this release commits
to that surface under semantic versioning.

### Added
- Documentation overhaul: auditor selective disclosure is now documented in the main README
  (Features, Usage, and API), with status badges (npm, crates.io, CI, license).
- Cross-links between the TypeScript package and the Rust crate.
- `CHANGELOG.md`, `CONTRIBUTING.md`, and `SECURITY.md`.

### Changed
- Marked the public API stable (`1.0.0`). Breaking changes will bump the major version.
- Refreshed the project status/roadmap to reflect completed work.

## [0.2.0]

### Added
- **Auditor-key selective disclosure** in both packages:
  - TypeScript: `deriveAuditorElgamalKeypair`, `getAuditorElgamalPubkey`,
    `decryptTransferAmountAsAuditor`, and an optional `auditorElgamalPubkey` on `transfer`.
  - Rust: `derive_auditor_keypair`, `decrypt_auditor_amount`.
- **New Rust crate** `softseco-confidential-transfers`, mirroring the five core helpers, published
  to crates.io.
- Rust CI (fmt, clippy, build, test).

## [0.1.0]

### Added
- Initial TypeScript SDK (alpha): `configureAccount`, `deposit`, `applyPendingBalance`,
  `decryptBalance`, and `transfer`, built on `@solana/kit`.
- Deterministic ElGamal/AES key derivation bound to `(owner, mint)`.
- `transfer` using context-state proof accounts (equality, ciphertext-validity, range).
- Local-validator integration tests (gated behind `CT_LOCAL_PROGRAM=1`) and validator-free unit
  tests in CI. Published to npm.

[Unreleased]: https://github.com/softseco/confidential-sdk/compare/v3.3.0...HEAD
[rust-3.0.0]: https://github.com/softseco/confidential-sdk/releases/tag/rust-v3.0.0
[3.3.0]: https://github.com/softseco/confidential-sdk/releases/tag/v3.3.0
[3.2.0]: https://github.com/softseco/confidential-sdk/releases/tag/v3.2.0
[3.1.0]: https://github.com/softseco/confidential-sdk/releases/tag/v3.1.0
[3.0.1]: https://github.com/softseco/confidential-sdk/releases/tag/v3.0.1
[3.0.0]: https://github.com/softseco/confidential-sdk/releases/tag/v3.0.0
[2.1.0]: https://github.com/softseco/confidential-sdk/releases/tag/v2.1.0
[2.0.0]: https://github.com/softseco/confidential-sdk/releases/tag/v2.0.0
[1.0.1]: https://github.com/softseco/confidential-sdk/releases/tag/v1.0.1
[1.0.0]: https://github.com/softseco/confidential-sdk/releases/tag/v1.0.0
[0.2.0]: https://github.com/softseco/confidential-sdk/releases/tag/v0.2.0
[0.1.0]: https://www.npmjs.com/package/@softseco/confidential-transfers/v/0.1.0
