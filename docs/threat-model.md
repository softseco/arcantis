# Arcantis threat model

Version 1.0.0-rc.1, 3 November 2026. Written by the author as part of a self-review on 29 October,
updated on 30 October with invariant 13 (formats), on 2 November after a second review, and on
3 November for transfers and withdrawals in one transaction (finding 17). Arcantis is
self-audited, not independently audited; this document is meant to make that audit faster and cheaper. Versions up to 3.3.0
(TypeScript) and 3.0.0 (Rust) were published as
`@softseco/confidential-transfers` and `softseco-confidential-transfers`. What to read, how to
build and test it, and what it depends on are in [audit-scope.md](./audit-scope.md).

## Scope

Two client libraries for Token-2022 confidential transfers that do the same things with the same
keys, checks and error codes:

- the TypeScript package `@softseco/arcantis` in `src/` (Node and browsers, built on
  `@solana/kit` 8 and the `@solana/zk-sdk` WebAssembly), including its `arcantis audit-report`
  command;
- the Rust crate `arcantis` in `rust/src/` (built on `solana-zk-sdk` 7 and the SPL client crates).

Arcantis has no on-chain program. It derives keys from a wallet signature, builds the
zero-knowledge proofs and the Token-2022 instructions, sends and confirms the transactions, reads
balances, resolves transfer-hook accounts, and lets a mint's auditor read transfer amounts.
Token-2022 and the ZK ElGamal Proof Program check every proof and every balance on chain, so no bug
in Arcantis can make Token-2022 accept a transfer that the account's owner did not sign, or a proof
that does not hold. What a bug in Arcantis can do is narrower but real:

- leak the keys that decrypt a wallet's balances, or an amount meant to stay encrypted;
- put something the user did not mean in a transaction the user signs (a wrong amount, a wrong
  recipient, a second transfer);
- report a wrong number: a balance, or an auditor's amount;
- leave an account unusable, or rent locked in proof accounts.

Out of scope: Token-2022, the ZK ElGamal Proof Program and the zk-sdk libraries themselves; the
playground, the examples (including the Anchor program in `rust/examples/anchor-vault`), the docs
and the tests.

## What Arcantis protects

- **The owner's confidential keys.** One ElGamal keypair and one AES key per wallet, derived from
  the wallet's signature over the fixed message `solana-conf-bal/v1` (the standard derivation, the
  same keys the spl-token CLI and other standard clients derive). They decrypt every confidential
  balance and every incoming and outgoing amount of that wallet, on every mint. They cannot spend:
  every instruction that moves tokens also needs the wallet's transaction signature.
- **The wallet's signatures.** Arcantis asks the wallet to sign two kinds of things: the key
  message, and transactions it built for the call the application made.
- **What stays encrypted.** A confidential transfer's amount is on chain only as ciphertexts for
  the sender, the recipient and the mint's auditor, and a confidential balance only as ciphertexts
  for its owner. A deposit's and a withdrawal's amount are public by Token-2022's design (they are
  instruction arguments), and so are the accounts, the owners and the times of every transaction.
- **Correct amounts.** A transfer sends exactly the amount asked to the account asked; a balance
  Arcantis reports is the balance the encrypted state holds; the auditor's report lists the
  transfers that happened, with their amounts.
- **Rent.** A transfer or withdrawal verifies its proofs into temporary accounts paid by the payer;
  they must be closed again.

## Who is trusted

| Actor | Trust | What it can do |
|---|---|---|
| The owner's wallet (signer) | Trusted | Signs the key message and the transactions. It must sign the key message exactly as given (Arcantis checks the message and the signature) and deterministically, as Ed25519 is specified (RFC 8032): a wallet that signs the same message differently each time would give different keys each time (known limit 2). A wallet that changes a transaction before signing it (a priority fee, say) is allowed to; Arcantis signs and sends what it returns. |
| The application | Trusted | Holds the `keys` object once derived, chooses the payer, the amounts and the recipients. Arcantis cannot protect keys that the application stores or logs. |
| The RPC node | Trusted for availability and for an honest view; not for safety | Supplies account state, history and confirmations. A lying RPC can make calls fail, show a wrong balance, hide transfers from an auditor's report, or claim a transaction was not confirmed. It cannot make Token-2022 accept a transfer to a key or at an amount the proofs do not cover: Token-2022 checks the source's and the destination's ElGamal keys and the source's balance ciphertext against the proofs, and the auditor's key and ciphertexts against the mint. It can, however, learn an amount (known limit 12). |
| The payer | Trusted by the owner | Pays fees, and the rent of proof accounts when they are used, as their close authority. It does not need the owner's keys. It may be someone else than the owner, such as a relayer that pays the SOL for other people's transfers. |
| Mint's confidential-transfer authority | Trusted | Chosen by the issuer. Approves accounts (unless the mint approves them automatically) and can change the auditor key. |
| Mint's auditor | Trusted, by design | Reads every confidential transfer's amount on the mint, and nothing else: not balances, not keys, and it cannot move tokens. |
| Transfer-hook program | Trusted by the mint's holders | Runs on every transfer. Arcantis adds the accounts its extra-account-meta list asks for, never as signers, and refuses a list that names the payer, the owner or another signer of the transaction (invariant 10). |
| Token-2022, ZK ElGamal Proof Program | Trusted | Verify every proof and keep balances. The tests run against Token-2022 v11.1.0; `examples/mainnet.ts` checks in simulation that mainnet's programs accept Arcantis's proofs. |
| `@solana/zk-sdk`, `solana-zk-sdk`, `@noble/curves` | Trusted | Proof generation, ElGamal and AES, key derivation, Ristretto arithmetic. |
| Anyone else (other holders, senders) | Untrusted | Can send confidential transfers to any account that accepts them, at any time. |

## Invariants

Each holds in both SDKs unless the line says otherwise. The tests named are in `test/` (TypeScript)
and `rust/tests/` and the `#[cfg(test)]` modules of `rust/src/` (Rust).

1. **Keys come only from a verified signature over the exact key message.** The message is
   `solana-conf-bal/v1`, or `solana-conf-bal/v1 || seed` for the seeded variant. A wallet that
   returns a different message, no signature, or a signature that does not verify against its
   address is refused (`BAD_MESSAGE_SIGNATURE`), before any key exists. (`keys.test.ts`,
   `wallet.test.ts`, `vectors.test.ts`; `keys::tests`, `tests/vectors.rs`)
2. **Keys match the account before they are used.** Every call that proves or decrypts first
   checks that the keys' ElGamal public key is the one the account is configured with
   (`KEYS_MISMATCH`). (`wallet.test.ts`; `refuses_before_signing_anything`)
3. **A configured key is one its owner can prove.** `configureAccount` sends the pubkey-validity
   proof, so an account cannot be configured with an ElGamal key whose secret nobody knows.
   (`configureAccount.test.ts`, Token-2022)
4. **Amounts are checked before anything is signed.** A transfer is 1 to 2^48 − 1 base units, a
   deposit too and no more than the public balance, a withdrawal at least 1, and a transfer or
   withdrawal no more than the available balance (`INVALID_INPUT`, `AMOUNT_TOO_LARGE`,
   `INSUFFICIENT_FUNDS`). The recipient must exist, be configured, be approved, accept
   confidential credits and have room in its pending-credit counter. (`send.test.ts`,
   `unit.test.ts`, `errors.test.ts`, `reliability.test.ts`; `refuses_before_signing_anything`,
   `refuses_recipients_that_cannot_take_a_confidential_transfer`)
5. **A transfer's amount is never on chain in the clear.** It is split into 16 and 32 bits and
   each half is encrypted to the source, the destination and the auditor; the instruction carries
   only those ciphertexts and where its proofs are, and the proofs carry only ciphertexts and
   commitments. (Token-2022's instruction layout; `auditor.test.ts` decrypts it as the auditor)
6. **Every transfer is readable by the mint's auditor.** The auditor key is read from the mint at
   the time of the transfer. (In TypeScript, `auditorElgamalPubkey` can override it, and
   Token-2022 then refuses a key that is not the mint's.) (`auditor.test.ts`, `auditorReport.test.ts`;
   `transfers_and_withdraws_with_an_auditor_and_a_priority_fee`)
7. **Proofs are built from the real available balance.** The AES copy of the available balance is
   checked against the ElGamal balance each time it is read; when it has fallen behind (finding 1
   below), the missing amount is recovered and the next transfer, withdrawal or apply writes a
   correct copy. A copy that cannot be reconciled is `BALANCE_OUT_OF_SYNC`, and nothing is
   signed. (`availableBalance.test.ts`; `accounts::tests`,
   `repairs_an_aes_copy_left_behind_by_a_credit_during_an_apply`)
8. **Proofs travel inside the transfer, or in temporary accounts.** In TypeScript a transfer or
   withdrawal is one v1 transaction (up to 4,096 bytes): the proof-verification instructions come
   right before the transfer or withdraw instruction, which names them by offset (−3, −2, −1 for a
   transfer; −2, −1 for a withdrawal) and reads them through the instructions sysvar. Token-2022
   checks that each offset points to an instruction of the ZK ElGamal Proof Program of the
   expected proof type, and takes the proof's context from it. No proof account exists, so none
   can be left behind. The transaction is simulated with the largest limits before anything is
   signed; its compute units (+20%) and loaded account data (+10%) are set from that simulation.
   When it would be larger than 4,096 bytes or 64 accounts (a transfer hook that asks for many
   accounts), when the caller sets `singleTransaction: false` (a wallet or RPC without v1
   transactions), and always in Rust, each proof goes into a proof account instead: a fresh
   keypair whose authority is the payer, closed after the transfer or withdrawal, or as soon as a
   step fails; `recoverProofAccounts` closes any that a stopped process left. (`reliability.test.ts`,
   `transferHook.test.ts`; `recovers_proof_accounts_left_behind`,
   `goes_through_a_transfer_hook_and_cleans_up_when_the_hook_refuses`)
9. **The SDK never sends an operation twice by itself.** Retries (TypeScript `retries`, Rust
   `with_max_retries`) only follow `TRANSACTION_EXPIRED`, which since finding 2 means the RPC has
   no record of the transaction after its blockhash expired. A transaction that landed after its
   confirmation was missed counts as sent. Since finding 7, any failure after a transaction may
   have reached a node (a lost confirmation, an HTTP 5xx, a timeout) is settled from the
   transaction's status the same way; if the status cannot be read, the call ends with an unknown
   outcome that names the transaction (`TRANSACTION_OUTCOME_UNKNOWN` in TypeScript,
   `unknown_outcome()` in Rust), is never retried, and leaves that step's proof accounts open. In
   TypeScript, "not found" counts only from a status answer at or after the slot at which the RPC
   saw the expiry (behind a load balancer another node may lag), an error on a transaction that is
   only processed is not taken as final, and a transaction whose wallet put in another blockhash is
   never called expired.
   (`send.test.ts`; `send::tests`)
10. **The SDK signs only what it built for the call.** In TypeScript all transactions of an
    operation (one, unless proof accounts are used) are signed together, one request per signer. No account from a transfer hook's list
    is added as a signer, and none is made writable where the Execute instruction has it read-only,
    as in the SPL resolver the Rust crate uses. A list that names a signer of the transaction (the
    payer, the owner, a proof account) is refused before anything is signed (`INVALID_INPUT`, finding
    6): signer status belongs to the whole transaction, so the hook would receive that account as a
    signer, and a hook could then spend a relayer's SOL. (`send.test.ts`, `reliability.test.ts`,
    `transferHook.test.ts`)
11. **Transfer-hook accounts resolve as the SPL interface resolves them**, and a list that does
    not resolve is refused before signing (`ACCOUNT_NOT_FOUND`). The Rust crate uses the SPL
    library itself; the TypeScript resolver follows it (finding 3). (`transferHook.test.ts`;
    `goes_through_a_transfer_hook_and_cleans_up_when_the_hook_refuses`)
12. **The auditor reads only what happened.** Failed transactions are skipped; transfers made
    through cross-program calls, with address lookup tables and in v1 transactions are found; an
    amount the auditor key cannot decrypt is listed as not decrypted, never as zero.
    (`auditor.test.ts`, `auditorReport.test.ts`)
13. **A format is recognised by what it carries, and an unknown one is refused.** Keys are derived
    only while the zk-sdk signs exactly `solana-conf-bal/v1` (then the seed); a library that
    would sign anything else is refused (`UNSUPPORTED_FORMAT`) before it is asked for a
    signature. A JSON auditor report is read only in its own format and in versions up to the one
    this release writes (`UNSUPPORTED_FORMAT`); a damaged one is `INVALID_INPUT`. The CSV header
    is pinned. [formats.md](./formats.md) lists every format and the rules for changing one.
    (`formats.test.ts`, `auditorReport.test.ts`; `keys::tests`)

## Known limits

1. **One key per wallet, on every mint.** The standard derivation binds the keys to the wallet
   alone, so whoever obtains the wallet's signature over `solana-conf-bal/v1` can read all of that
   wallet's confidential balances and amounts, on every mint, forever. A site that asks a user to
   sign that message is asking for this. Wallets can warn about it; Arcantis cannot. The keys never
   allow spending.
2. **A wallet that signs non-deterministically.** Some threshold or hardware signers may produce a
   different valid signature for the same message. Keys derived from it would differ each time:
   an account configured with one set could later only be used with that same set. Arcantis
   catches a mismatch on every later call (`KEYS_MISMATCH`), but cannot tell at configuration
   time. Passing the same `keys` object to every call avoids it within a session.
3. **A balance copy that fell behind by 2^32 base units or more.** The recovery in invariant 7
   decrypts the missing amount with a 32-bit discrete log. If the credits that raced an apply add
   up to 2^32 base units or more (4,294.97 units of a 6-decimal token), the call fails with
   `BALANCE_OUT_OF_SYNC`. The funds are in the encrypted balance; repairing the copy then needs
   the missed credits' own ciphertexts, which Arcantis does not read yet.
4. **Large pending balances.** The pending balance is decrypted half by half with the same 32-bit
   discrete log, so incoming amounts that add up to about 2^48 base units before an apply cannot be
   applied (`DECRYPTION_FAILED`). Applying more often avoids it.
5. **Mints and accounts it does not handle.** Transfers on a mint with a transfer fee (Token-2022's
   `TransferWithFee`) are not built, and are refused before any proof is paid for; the auditor's
   report lists such transfers without an amount. A paused mint and a frozen or unapproved account
   are refused up front as well.
   Recipients that require a memo on incoming transfers (`MemoTransfer`) refuse Arcantis's
   transfers. A transfer hook that needs an extra signer cannot be used, since Arcantis adds no
   signers for hooks.
6. **What is public stays public.** Deposit and withdrawal amounts, every account and owner
   involved, and the time of every transaction are visible to everyone. So is a transfer's
   existence. Only transfer amounts and balances are hidden.
7. **The RPC's view.** Balances, confirmations and the auditor's report are as good as the RPC
   that serves them. An auditor should run the report against an RPC it trusts and that keeps the
   mint's full history; a report stops (`RPC_ERROR`) when the RPC cannot return a transaction it
   listed, rather than leave a gap. When a transaction's status cannot be read, the call ends with
   an unknown outcome (invariant 9) and is not retried; the application has to look the signature
   up.
8. **Concurrent use.** Two operations on the same account at once: the second fails, because its
   proofs refer to a balance that has changed (in one transaction usually already in simulation;
   with proof accounts, fees and, until closed, rent are lost).
   `recoverProofAccounts` closes every proof account of its payer, including those of a transfer
   still running in another process, which then fails.
9. **Keys in memory.** JavaScript cannot erase memory, and the WebAssembly key objects live until
   the application drops them. In a browser, the WebAssembly is loaded from wherever the
   application serves it; its integrity is the application's.
10. **A changed auditor key.** The confidential-transfer authority can change the mint's auditor
    key. Transfers made before the change are encrypted to the old key, and the report built with
    the new key lists them as not decrypted.
11. **The auditor key is the auditor wallet's ordinary key.** `deriveAuditorElgamalKeypair` uses
    the standard derivation (known limit 1), so any site that has the auditor's wallet sign
    `solana-conf-bal/v1` gets the key that reads every amount on every mint naming that auditor.
    Use a wallet that does nothing but audit, and never connect it to other sites. A derivation
    with a seed of its own would separate the two, but it changes the auditor key of every existing
    mint, so it waits for a decision (question for the auditor below).
12. **A lying RPC can learn a transfer's amount.** The destination's and the auditor's ElGamal
    keys are read from the RPC. An RPC that substitutes its own key receives the transaction that
    carries the amount encrypted to that key (with proof accounts, the proof transactions that go
    out before the transfer). Token-2022 then refuses the transfer, but the amount has leaked. Use an RPC you trust for transfers; the
    auditor key can be pinned (`auditorElgamalPubkey`), the destination key cannot yet.
13. **Unverified range-proof accounts.** In Rust the range-proof context account is created in one
    transaction and verified in the next, because the two do not fit in one. Anyone can verify a
    proof of their own into it in between, take it over and close it to themselves: the transfer
    fails and the rent is lost. An account that stays unverified has no authority, so
    `recover_proof_accounts` cannot find it; the error lists it in `ProofAccounts::unverified`.
14. **A balance copy that is ahead.** Only one repair is tried, for a copy that fell behind
    (invariant 7). A copy that is ahead, which only forged pending amounts from an RPC can cause, is
    refused with `BALANCE_OUT_OF_SYNC` on every later call, and such an RPC can make
    `decryptBalance` show any value below 2^32 without the AES key.

## Findings of our own review (29 October 2026)

| # | Finding | Effect | Status |
|---|---|---|---|
| 1 | Token-2022 accepts an `ApplyPendingBalance` whose AES copy leaves out a credit that arrived after the owner read the account. Both SDKs then built every transfer and withdrawal from the stale copy, and Token-2022 refused them all. | An account receiving many payments could become unusable through Arcantis in normal use, and anyone could cause it by timing a small transfer. No funds at risk. | Fixed in both SDKs: the copy is checked and repaired (invariant 7), with the limit in known limit 3. |
| 2 | When no confirmation arrived before a transaction's blockhash expired, both SDKs reported it expired without asking whether it had landed. The TypeScript SDK's `retries` then ran the whole operation again. | A transfer or deposit could be sent twice if a confirmation was lost (the Rust crate re-sent the same instructions, which only a deposit survives). | Fixed in both SDKs (invariant 9). |
| 3 | The TypeScript transfer-hook resolver read an address stored in data (`PubkeyData`) as a PDA of program −126, cut seeds that read past the end of the data short, accepted a list claiming more entries than it held, and returned nothing for a hook mint without a list. | Transfers on such mints failed with a confusing error or on chain. No funds at risk. | Fixed (invariant 11). |
| 4 | `decryptTransferAmountAsAuditor` (TypeScript) decrypted the amount of a transaction that had failed, and missed transfers made through cross-program calls. | An auditor could record a transfer that never happened, or miss one out of a program-owned account. | Fixed (invariant 12). |
| 5 | The Rust crate still shipped the 2.x free functions, deprecated since 3.0.0. | More code to audit for no user. | Removed. |

## Findings of our own review (2 November 2026)

A second review before 1.0.0-rc.1: separate passes over the TypeScript SDK and the Rust crate, each
finding reproduced before it was fixed.

| # | Finding | Effect | Status |
|---|---|---|---|
| 6 | A transfer-hook list could name the payer, which then reached the hook as a signer (signer status belongs to the whole transaction). | A malicious mint could make a relayer that pays fees for other people's transfers sign for its hook, which could move the relayer's SOL. | Fixed in both SDKs (invariant 10). |
| 7 | Any confirmation error other than an expired blockhash, an HTTP 5xx from the node or a timeout was reported as a failure without checking whether the transaction had landed. In Rust any RPC error after sending was reported as an RPC failure, and the proof accounts were closed. | An application that retried on "failed" could pay twice. | Fixed in both SDKs: the outcome is settled from the transaction's status, and an unknown one is reported as such (invariant 9). |
| 8 | Rust errors carried the RPC URL, query string included, through reqwest's error text. | API keys of RPC providers in logs and telemetry. | Fixed: URLs are cut to scheme and host, and a source that still shows one is dropped. |
| 9 | `arcantis audit-report` exited before a piped report was fully written; a report missed transactions the RPC could not return, and `--concurrency abc` gave an empty report, both reported as success. | An incomplete audit with exit code 0. | Fixed. |
| 10 | CSV fields starting with `=`, `+`, `-` or `@` were only quoted, and owners from the RPC were not checked to be addresses. | Formulas in a spreadsheet opened by the auditor. | Fixed: such fields get a leading `'`; RPC addresses are checked. |
| 11 | `recoverProofAccounts` read every account in one request, which RPCs cap at 100, and one account that could not be closed kept seven others open. | Recovery failed for a payer with many leftovers. | Fixed. |
| 12 | Decrypted balances appeared in error messages (both SDKs), and a bad keypair file was quoted in the CLI's error. | Amounts and part of a secret in logs. | Fixed: amounts are kept out of messages (Rust `Error::available_balance()`); the file is not quoted. |
| 13 | Transfers on a paused mint, from a frozen or unapproved account or on a mint with a transfer fee built and paid for proofs that Token-2022 then refused. | Lost fees and rent, an extra wallet prompt. | Fixed: refused before any proof (known limit 5). |
| 14 | The Rust client and its futures were neither `Send` nor `Sync`. | Unusable from `tokio::spawn` and most web servers; a breaking change after 1.0. | Fixed before 1.0. |
| 15 | The browser build forgot the `wasmUrl` given to `initConfidentialTransfers`. | A web app whose first SDK call raced the init could not load the zk module. | Fixed. |
| 16 | The auditor key is the wallet's ordinary key; an RPC can learn amounts by substituting keys; Rust range-proof accounts can be taken over between creation and verification; a balance copy that is ahead is not repaired. | See known limits 11–14. | Documented. |

## Change of 3 November 2026

| # | Finding | Effect | Status |
|---|---|---|---|
| 17 | A transfer took five transactions and a withdrawal four, sent one after another, each waiting for its confirmation. Solana has taken v1 transactions of up to 4,096 bytes since 15 September 2026, and Token-2022 can read proofs from earlier instructions of the same transaction. | Several seconds per payment on mainnet; rent held in proof accounts while they were open; more steps that can fail (findings 7 and 11, known limit 13). | Changed in TypeScript: one v1 transaction by default, proof accounts as the fallback (invariant 8). The auditor's reads ask the RPC for v1 transactions, without which a v1 transfer could not be read (invariant 12). Measured on a local validator with Vigilantis as the hook: 2,690 bytes, 14 accounts, about 280,000 compute units. Rust keeps proof accounts until it moves to `solana-message` 4.4 or later, the first with v1 messages. |

## How the invariants are tested

- **TypeScript:** 132 tests (`CT_LOCAL_PROGRAM=1 npm test`), of which 106 need no validator and 26
  run against a local validator with Token-2022 v11.x and Sentinel, the transfer hook, loaded. The
  browser test (`npm run test:browser`) runs the Vite example in Chromium with a test wallet that
  signs v1 transactions, and checks it signs one transaction per step.
- **Rust:** 40 tests (`CT_LOCAL_PROGRAM=1 cargo test -- --test-threads 1`): 27 unit tests, 7
  on-chain tests of the client, one of the Anchor example that holds a confidential balance in a
  program-owned account, 4 shared-vector tests and a doctest.
- **Shared vectors:** `test-vectors/confidential-transfers.json` pins key derivation, the
  PDA-wallet seed, an auditor's amount and an AES balance; both SDKs check them, so a change in
  either that would make them disagree fails.
- **Line coverage** is in [audit-scope.md](./audit-scope.md#coverage), with the lines no test
  reaches.

Every finding above came with a test that fails without the fix: the race in finding 1 is
reproduced on a validator by sending the apply with the stale copy, exactly as Token-2022 accepts
it when a credit lands in between.

## What we ask an auditor to look at

1. **The vendored proof construction** (`src/internal/confidentialTransferProof.ts`) against the
   upstream helper in `@solana-program/token-2022` it was adapted from: the same proofs, the same
   openings, the same instruction data.
2. **The ciphertext arithmetic in `@noble/curves`** (`src/internal/confidentialTransferArithmetic.ts`,
   `src/internal/availableBalance.ts`): the lo/hi combination, the subtraction of a plaintext
   amount, and the check `C − s·D = v·G` that decides whether the AES copy is current.
3. **The repair of a stale copy.** Is recovering the difference with a discrete log sound in every
   case, including a copy that is ahead, and should the SDK also look at the expected and actual
   credit counters Token-2022 records?
4. **Signing.** `src/internal/send.ts` signs all transactions of an operation together and sends
   what a modifying signer (a browser wallet) returns. Should it check that the wallet changed
   nothing but what wallets may change?
5. **Retries and expiry.** Can any path still send a transfer, withdrawal or deposit twice?
6. **Transfer-hook resolution** in TypeScript against `spl-tlv-account-resolution`.
7. **The auditor's report** (`src/auditorReport.ts`): it relies on the token account, mint and
   destination being the first three accounts of each confidential instruction, in every client.
8. **What a malicious RPC can make the SDK do** beyond failing: in particular, whether a forged
   account state can make it build or sign something harmful.
9. **Non-deterministic signers** (known limit 2): is checking two signatures at configuration time
   worth a second wallet prompt?
10. **Formats** ([formats.md](./formats.md)): is anything Arcantis reads recognised by its length
    or shape rather than by what it carries, and is the auditor report reader strict enough?
