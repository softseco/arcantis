// SPDX-License-Identifier: BUSL-1.1
//! The shared test vectors in `test-vectors/confidential-transfers.json`, which the TypeScript
//! SDK's `test/vectors.test.ts` checks too. If the two SDKs drift apart in key derivation, the
//! PDA-wallet seed or how an auditor reads an amount, one of the two suites fails.
use arcantis::{
    decrypt_auditor_amount, derive_auditor_keypair, pda_wallet_public_seed, ConfidentialKeys,
};
use serde_json::Value;
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use solana_zk_sdk::encryption::{auth_encryption::AeCiphertext, elgamal::ElGamalCiphertext};
use solana_zk_sdk_pod::encryption::{
    auth_encryption::PodAeCiphertext,
    elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
};

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-vectors/confidential-transfers.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn wallet(v: &Value) -> Keypair {
    Keypair::new_from_array(bytes(v).try_into().unwrap())
}

fn pubkey(v: &Value) -> Pubkey {
    v.as_str().unwrap().parse().unwrap()
}

#[test]
fn standard_derivation() {
    for case in vectors()["standardDerivation"].as_array().unwrap() {
        let keys = ConfidentialKeys::derive(&wallet(&case["walletPrivateKey"])).unwrap();
        assert_eq!(
            keys.elgamal.secret().as_bytes().to_vec(),
            bytes(&case["elgamalSecretKey"])
        );
        assert_eq!(
            PodElGamalPubkey::from(*keys.elgamal.pubkey()).0.to_vec(),
            bytes(&case["elgamalPubkey"])
        );
        assert_eq!(<[u8; 16]>::from(&keys.ae).to_vec(), bytes(&case["aeKey"]));
    }
}

#[test]
fn pda_wallet_derivation() {
    let case = &vectors()["pdaWalletDerivation"];
    let seed = pda_wallet_public_seed(
        &pubkey(&case["programId"]),
        &pubkey(&case["walletPda"]),
        &pubkey(&case["mint"]),
        &pubkey(&case["tokenAccount"]),
    );
    assert_eq!(seed, bytes(&case["publicSeed"]));
    let keys = ConfidentialKeys::derive_for_pda_wallet(
        &wallet(&case["operatorPrivateKey"]),
        &pubkey(&case["programId"]),
        &pubkey(&case["walletPda"]),
        &pubkey(&case["mint"]),
        &pubkey(&case["tokenAccount"]),
    )
    .unwrap();
    assert_eq!(
        keys.elgamal.secret().as_bytes().to_vec(),
        bytes(&case["elgamalSecretKey"])
    );
    assert_eq!(<[u8; 16]>::from(&keys.ae).to_vec(), bytes(&case["aeKey"]));
}

#[test]
fn auditor_transfer_amount() {
    let case = &vectors()["auditorTransferAmount"];
    let auditor = derive_auditor_keypair(&wallet(&case["auditorWalletPrivateKey"])).unwrap();
    let ciphertext = |v: &Value| {
        ElGamalCiphertext::try_from(PodElGamalCiphertext(bytes(v).try_into().unwrap())).unwrap()
    };
    let amount = decrypt_auditor_amount(
        &auditor,
        &ciphertext(&case["ciphertextLo"]),
        &ciphertext(&case["ciphertextHi"]),
    )
    .unwrap();
    assert_eq!(amount.to_string(), case["amount"].as_str().unwrap());
}

#[test]
fn decryptable_balance() {
    let case = &vectors()["decryptableBalance"];
    let keys = ConfidentialKeys::derive(&wallet(&case["ownerWalletPrivateKey"])).unwrap();
    let ciphertext = AeCiphertext::try_from(PodAeCiphertext(
        bytes(&case["ciphertext"]).try_into().unwrap(),
    ))
    .unwrap();
    assert_eq!(
        keys.ae.decrypt(&ciphertext).unwrap().to_string(),
        case["amount"].as_str().unwrap()
    );
}
