// SPDX-License-Identifier: BUSL-1.1
//! Confidential-balances key derivation.
//!
//! An account's ElGamal keypair and AES key come from the standard derivation:
//! one signature over the constant message `solana-conf-bal/v1`, expanded
//! through a shared HKDF-SHA512 chain. The keys are bound to the signing wallet
//! alone — one ElGamal keypair and one AES key across every mint and token
//! account the wallet owns — so they are recoverable from the wallet, never
//! stored, and byte-identical to what the TypeScript SDK, the Token-2022
//! clients and every other standard client derive for the same wallet.
//!
//! A token account owned by a program (a PDA) cannot sign, so its keys come
//! from an operator's wallet with a seed that scopes them to that account:
//! [`ConfidentialKeys::derive_for_pda_wallet`], the same convention as the
//! TypeScript SDK's `pdaWalletPublicSeed`.
use solana_sdk::{pubkey::Pubkey, signer::Signer};
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    derivation::derive_confidential_keys_from_signature,
    elgamal::{ElGamalKeypair, ElGamalPubkey},
};

use crate::error::{Error, ErrorCode, Result};

/// The key derivation: one wallet signature over this message (followed by a public seed for the
/// seed-scoped keys), expanded with HKDF-SHA512. The version is part of the message, so a
/// different derivation would sign a different message and give different keys. The TypeScript
/// SDK exports the same name; `docs/formats.md` describes it.
pub const KEY_DERIVATION_SCHEME: &str = "solana-conf-bal/v1";

/// Checks that `message`, the derivation message the zk-sdk builds for `public_seed`, is
/// [`KEY_DERIVATION_SCHEME`] followed by the seed. A zk-sdk that signed anything else would give
/// the same wallet keys that match none of its configured accounts; that is refused with
/// [`ErrorCode::UnsupportedFormat`] instead.
pub(crate) fn check_derivation_message(message: &[u8], public_seed: &[u8]) -> Result<()> {
    let scheme = KEY_DERIVATION_SCHEME.as_bytes();
    if message.len() == scheme.len() + public_seed.len()
        && message.starts_with(scheme)
        && message.ends_with(public_seed)
    {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::UnsupportedFormat,
        "derive keys",
        format!(
            "the solana-zk-sdk in use derives keys from a message other than {KEY_DERIVATION_SCHEME}{}; \
             keys derived that way would not match the accounts configured so far, so this \
             release refuses to derive them",
            if public_seed.is_empty() {
                ""
            } else {
                " followed by the seed"
            }
        ),
    ))
}

/// An account's ElGamal keypair (balances and amounts) and AES key (the owner's fast
/// copy of the available balance).
pub struct ConfidentialKeys {
    pub elgamal: ElGamalKeypair,
    pub ae: AeKey,
}

impl ConfidentialKeys {
    /// The wallet's standard keys: what every standard client derives for this wallet.
    pub fn derive(owner: &dyn Signer) -> Result<Self> {
        Self::derive_with_seed(owner, b"")
    }

    /// Keys from the message `solana-conf-bal/v1 || public_seed`. A non-empty seed gives keys no
    /// other client derives for the wallet; use it only for a scheme that needs keys scoped more
    /// finely than the wallet, such as a program-owned account ([`Self::derive_for_pda_wallet`]).
    pub fn derive_with_seed(signer: &dyn Signer, public_seed: &[u8]) -> Result<Self> {
        let operation = "derive keys";
        let message =
            solana_zk_sdk::encryption::derivation::confidential_derivation_message(public_seed);
        check_derivation_message(&message, public_seed)?;
        let signature = signer.try_sign_message(&message).map_err(|e| {
            Error::new(
                ErrorCode::CannotSignMessages,
                operation,
                format!(
                    "signer {} could not sign the key-derivation message: {e}",
                    signer.pubkey()
                ),
            )
            .with_source(e)
        })?;
        // A signature that does not verify gives keys nobody can derive again.
        if !signature.verify(signer.pubkey().as_ref(), &message) {
            return Err(Error::new(
                ErrorCode::BadMessageSignature,
                operation,
                format!(
                    "signer {} returned a signature that does not verify against its address",
                    signer.pubkey()
                ),
            ));
        }
        let (elgamal, ae) = derive_confidential_keys_from_signature(&signature).map_err(|e| {
            Error::new(
                ErrorCode::BadMessageSignature,
                operation,
                format!("cannot derive keys from the signature: {e}"),
            )
        })?;
        Ok(Self { elgamal, ae })
    }

    /// Keys for a token account owned by a program (a PDA wallet), derived by `operator` with
    /// the seed [`pda_wallet_public_seed`]. Whoever holds `operator` can read the account and
    /// prepare its transfers; the program signs them.
    pub fn derive_for_pda_wallet(
        operator: &dyn Signer,
        program_id: &Pubkey,
        wallet_pda: &Pubkey,
        mint: &Pubkey,
        token_account: &Pubkey,
    ) -> Result<Self> {
        Self::derive_with_seed(
            operator,
            &pda_wallet_public_seed(program_id, wallet_pda, mint, token_account),
        )
    }

    /// The ElGamal public key, as it is stored in a configured account.
    pub fn elgamal_pubkey(&self) -> &ElGamalPubkey {
        self.elgamal.pubkey()
    }
}

/// The canonical seed for a program-owned (PDA) wallet's keys:
/// `program_id || wallet_pda || mint || token_account`, 128 bytes. The TypeScript SDK's
/// `pdaWalletPublicSeed` builds the same bytes.
pub fn pda_wallet_public_seed(
    program_id: &Pubkey,
    wallet_pda: &Pubkey,
    mint: &Pubkey,
    token_account: &Pubkey,
) -> Vec<u8> {
    [program_id, wallet_pda, mint, token_account]
        .iter()
        .flat_map(|p| p.to_bytes())
        .collect()
}

/// Derive the wallet's `(ElGamal keypair, AES key)` for confidential balances: the standard
/// derivation, with no seed. Same as [`ConfidentialKeys::derive`].
pub fn derive_account_keys(owner: &dyn Signer) -> Result<(ElGamalKeypair, AeKey)> {
    let keys = ConfidentialKeys::derive(owner)?;
    Ok((keys.elgamal, keys.ae))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Keypair;
    use solana_zk_sdk::encryption::derivation::derive_confidential_keys;

    /// Same as [`derive_account_keys`], through the zk-sdk's own signing helper, to check the two
    /// paths against each other.
    fn derive_account_keys_via_zk_sdk(
        owner: &dyn Signer,
    ) -> std::result::Result<(ElGamalKeypair, AeKey), Box<dyn std::error::Error>> {
        derive_confidential_keys(owner, b"")
    }

    #[test]
    fn matches_the_zk_sdk_derivation() {
        let owner = Keypair::new();
        let (a, ae_a) = derive_account_keys(&owner).unwrap();
        let (b, ae_b) = derive_account_keys_via_zk_sdk(&owner).unwrap();
        assert_eq!(a.secret().as_bytes(), b.secret().as_bytes());
        assert_eq!(<[u8; 16]>::from(&ae_a), <[u8; 16]>::from(&ae_b));
    }

    #[test]
    fn signs_the_versioned_derivation_message() {
        use solana_zk_sdk::encryption::derivation::confidential_derivation_message;
        assert_eq!(
            confidential_derivation_message(b""),
            KEY_DERIVATION_SCHEME.as_bytes()
        );
        let seeded = confidential_derivation_message(&[7, 8, 9]);
        assert!(check_derivation_message(&seeded, &[7, 8, 9]).is_ok());
    }

    #[test]
    fn refuses_any_other_derivation_message() {
        let refused = |message: &[u8], seed: &[u8]| {
            check_derivation_message(message, seed).unwrap_err().code()
        };
        assert_eq!(
            refused(b"solana-conf-bal/v2", b""),
            ErrorCode::UnsupportedFormat
        );
        assert_eq!(
            refused(KEY_DERIVATION_SCHEME.as_bytes(), &[1]),
            ErrorCode::UnsupportedFormat
        );
        assert_eq!(
            refused(b"solana-conf-bal/v1\x01", &[2]),
            ErrorCode::UnsupportedFormat
        );
    }

    #[test]
    fn is_deterministic_and_wallet_bound() {
        let owner = Keypair::new();
        let (a, _) = derive_account_keys(&owner).unwrap();
        let (b, _) = derive_account_keys(&owner).unwrap();
        let (c, _) = derive_account_keys(&Keypair::new()).unwrap();
        assert_eq!(a.secret().as_bytes(), b.secret().as_bytes());
        assert_ne!(a.secret().as_bytes(), c.secret().as_bytes());
    }

    /// A signer that declines to sign, or signs something other than what it was asked to.
    struct Odd {
        key: Keypair,
        lies: bool,
    }

    impl Signer for Odd {
        fn try_pubkey(&self) -> std::result::Result<Pubkey, solana_sdk::signer::SignerError> {
            Ok(self.key.pubkey())
        }
        fn try_sign_message(
            &self,
            _message: &[u8],
        ) -> std::result::Result<solana_sdk::signature::Signature, solana_sdk::signer::SignerError>
        {
            if self.lies {
                Ok(self.key.sign_message(b"another message"))
            } else {
                Err(solana_sdk::signer::SignerError::Custom(
                    "declined".to_string(),
                ))
            }
        }
        fn is_interactive(&self) -> bool {
            false
        }
    }

    #[test]
    fn refuses_a_signer_that_declines_or_signs_something_else() {
        let declines = Odd {
            key: Keypair::new(),
            lies: false,
        };
        let lies = Odd {
            key: Keypair::new(),
            lies: true,
        };
        let code = |result: Result<ConfidentialKeys>| match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e.code(),
        };
        assert_eq!(
            code(ConfidentialKeys::derive(&declines)),
            ErrorCode::CannotSignMessages
        );
        assert_eq!(
            code(ConfidentialKeys::derive(&lies)),
            ErrorCode::BadMessageSignature
        );
    }

    #[test]
    fn scopes_seeded_keys_away_from_the_standard_keys() {
        let owner = Keypair::new();
        let standard = ConfidentialKeys::derive(&owner).unwrap();
        let seeded = ConfidentialKeys::derive_with_seed(&owner, &[1, 2, 3, 4]).unwrap();
        assert_ne!(
            standard.elgamal.secret().as_bytes(),
            seeded.elgamal.secret().as_bytes()
        );
    }
}
