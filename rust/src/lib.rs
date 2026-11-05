// SPDX-License-Identifier: BUSL-1.1
//! Token-2022 confidential transfers in Rust: a mirror of the
//! [`@softseco/arcantis`](https://www.npmjs.com/package/@softseco/arcantis)
//! TypeScript SDK, with the same keys, the same checks and the same error codes.
//!
//! [`ConfidentialClient`] configures accounts, deposits, applies pending balances, reads
//! balances, transfers and withdraws. A transfer or withdraw goes in one v1 transaction with its
//! proofs inside, or, when that does not fit, verifies them into temporary proof accounts and
//! cleans up after itself when a step fails. A transfer reads the mint's auditor key and transfer
//! hook.
//!
//! For token accounts owned by a program, [`ConfidentialClient::prepare_transfer`] and its
//! siblings generate and verify the proofs, and return what the program needs to make the
//! transfer through a cross-program call; `examples/anchor-vault` is a complete Anchor program.
//!
//! Keys come from the owner's wallet with the standard derivation ([`ConfidentialKeys`]), so an
//! account configured here can be used with the TypeScript SDK, the spl-token CLI and any other
//! standard client.
//!
//! The Solana crates whose types appear in this crate's API are re-exported:
//! [`solana_client`] (the `RpcClient`), [`solana_sdk`] (`Pubkey`, `Signer`, `Instruction`, …)
//! and [`solana_zk_sdk`] (`ElGamalKeypair`, `AeKey`, ciphertexts). This crate pins them to exact
//! versions, and a type from another version of the same crate is a different type that does not
//! fit. Use them through these re-exports (`arcantis::solana_sdk::pubkey::Pubkey`) rather than
//! through a dependency of your own, unless you pin the same versions.

/// The Solana RPC client this crate is built with. See the crate documentation.
pub use solana_client;
/// The Solana SDK this crate is built with. See the crate documentation.
pub use solana_sdk;
/// The ZK SDK this crate is built with (ElGamal and AES keys, ciphertexts). See the crate
/// documentation.
pub use solana_zk_sdk;

mod accounts;
pub mod auditor;
mod client;
pub mod error;
pub mod keys;
mod proofs;
mod send;
mod v1;

pub use auditor::{decrypt_auditor_amount, derive_auditor_keypair};
pub use client::{
    ConfidentialClient, ConfigureAccountResult, PendingBalanceUpdate, PreparedConfigure,
    PreparedTransfer, PreparedWithdraw, RecoverProofAccountsResult, TransferResult, WithdrawResult,
    TOKEN_2022_PROGRAM_ID,
};
pub use error::{Error, ErrorCode, ProofAccounts, Result};
pub use keys::{
    derive_account_keys, pda_wallet_public_seed, ConfidentialKeys, KEY_DERIVATION_SCHEME,
};

/// The crate version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
