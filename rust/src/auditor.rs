// SPDX-License-Identifier: BUSL-1.1
//! Auditor-key selective disclosure.
//!
//! A Token-2022 mint can designate an auditor ElGamal public key. When set,
//! every confidential transfer on that mint also encrypts the amount to the
//! auditor, who can recover it here with their ElGamal secret key — without
//! being able to spend, and without affecting anyone else's confidentiality.
//! [`crate::ConfidentialClient::transfer`] reads the auditor key from the mint and encrypts every
//! amount to it. Mirrors the TypeScript SDK's auditor utilities.
use solana_sdk::signer::Signer;
use solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair};
use spl_token_2022_interface::extension::confidential_transfer::PENDING_BALANCE_LO_BIT_LENGTH;

use crate::error::{Error, ErrorCode, Result};
use crate::keys::ConfidentialKeys;

/// Derive the auditor's ElGamal keypair from its wallet signer: the ElGamal half
/// of the wallet's standard confidential-balances keys. The key is
/// mint-independent, so it is recoverable from the wallet alone and never stored.
/// The TypeScript SDK's `deriveAuditorElgamalKeypair` gives the same key.
pub fn derive_auditor_keypair(signer: &dyn Signer) -> Result<ElGamalKeypair> {
    Ok(ConfidentialKeys::derive(signer)?.elgamal)
}

/// Recover a confidential transfer's amount from its auditor ciphertexts (the
/// lo and hi halves of the instruction), using the auditor's ElGamal secret key.
pub fn decrypt_auditor_amount(
    auditor_keypair: &ElGamalKeypair,
    ciphertext_lo: &ElGamalCiphertext,
    ciphertext_hi: &ElGamalCiphertext,
) -> Result<u64> {
    let operation = "decrypt_auditor_amount";
    let secret = auditor_keypair.secret();
    let fail = |half: &str| {
        Error::new(
            ErrorCode::DecryptionFailed,
            operation,
            format!(
                "could not decrypt the {half} ciphertext; it is not encrypted to this auditor key"
            ),
        )
    };
    let lo = secret
        .decrypt_u32(ciphertext_lo)
        .ok_or_else(|| fail("lo"))?;
    let hi = secret
        .decrypt_u32(ciphertext_hi)
        .ok_or_else(|| fail("hi"))?;
    Ok(lo + (hi << PENDING_BALANCE_LO_BIT_LENGTH))
}
