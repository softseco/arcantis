<!-- SPDX-License-Identifier: BUSL-1.1 -->
# Example: a confidential vault in Anchor

A program that holds a Token-2022 **confidential** balance and pays out of it. The vault's token
account is owned by a PDA, so only the program can move its tokens, and only when the vault's
operator asks. Amounts stay encrypted throughout: what comes in, the balance, what goes out. The
mint's auditor, if it has one, can read every amount, the payouts included.

Think of a treasury, payroll or escrow program whose payments should not be public.

## How it fits together

A token account owned by a PDA cannot sign the message its confidential keys come from, and a
program cannot generate zero-knowledge proofs. So the work is split:

| Who | Does |
|---|---|
| Operator's wallet | Derives the vault's keys: `ConfidentialKeys::derive_for_pda_wallet(operator, program_id, vault, mint, vault_token)`. Only the operator can read the vault's balance. |
| Operator's client (the `arcantis` crate) | Generates the proofs and verifies them into proof accounts: `prepare_configure`, `prepare_transfer`, `pending_balance_update`. Resolves transfer-hook accounts. Closes the proof accounts afterwards. |
| This program | Checks the operator, then makes the Token-2022 call, signing as the PDA. It never sees a key. |

Instructions:

- `initialize`: the vault PDA (`["vault", mint]`) with its operator.
- `configure(decryptable_zero_balance)`: adds the confidential-transfer extension to the vault's
  token account and configures it with the vault's key, proved in a proof account.
- `apply_pending(expected_pending_balance_credit_counter, new_decryptable_available_balance)`:
  moves incoming transfers into the vault's available balance.
- `pay(new_decryptable_available_balance, auditor_ciphertext_lo, auditor_ciphertext_hi)`:
  transfers from the vault to any account of the mint. The amount is not an argument: it is in
  the proofs. Transfer-hook accounts come as remaining accounts.

Anyone pays into the vault with an ordinary confidential transfer to the vault's token account.

The Token-2022 instructions are built from their byte layout in `src/lib.rs`
(`mod token_2022`), so the program depends on `anchor-lang` only.

## The client side

`rust/tests/anchor_vault.rs` is the client, written as a test. The payout, in short:

```rust
let keys = ConfidentialKeys::derive_for_pda_wallet(&operator, &VAULT_PROGRAM, &vault, &mint, &vault_token)?;
let prepared = client.prepare_transfer(&mint, &vault_token, &keys, &bob_token, 250).await?;
let hook = client.transfer_hook_accounts(&mint, &vault_token, &bob_token, &vault).await?;
// pay(prepared.new_decryptable_available_balance, prepared.auditor_ciphertext_lo/hi)
// with the three proof accounts, and `hook` as remaining accounts; signed by the operator.
client.close_proof_accounts(&prepared.proof_accounts()).await;
```

## Build and run

With Anchor 0.31 (`anchor build`) or with the Solana CLI alone:

```bash
cd rust/examples/anchor-vault
cargo build-sbf --manifest-path programs/confidential-vault/Cargo.toml
```

The test loads the program into a local validator next to the Token-2022 build in
`test/fixtures` (and Sentinel, so the payout also goes through a transfer hook):

```bash
# from the repository root
TOKEN_2022_SO=test/fixtures/spl_token_2022.so \
SENTINEL_SO=test/fixtures/sentinel.so \
CONFIDENTIAL_VAULT_SO=rust/examples/anchor-vault/target/deploy/confidential_vault.so \
  bash scripts/start-test-validator.sh

cd rust && CT_LOCAL_PROGRAM=1 cargo test --test anchor_vault
```

The program id in `declare_id!` and `Anchor.toml` is the one the test uses. To deploy your own
copy, generate a keypair and run `anchor keys sync`.

This is an example, not an audited program. A real treasury would put the operator behind a
multisig and record each payout's purpose.
