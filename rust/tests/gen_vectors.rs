// SPDX-License-Identifier: BUSL-1.1
// Prints test-vectors/confidential-transfers.json. Run once, by hand:
//   cargo test --test gen_vectors -- --ignored --nocapture
use arcantis::{pda_wallet_public_seed, ConfidentialKeys};
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use solana_zk_sdk_pod::encryption::{
    auth_encryption::PodAeCiphertext,
    elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
#[ignore]
fn print_vectors() {
    let wallet_a: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    let wallet_b: [u8; 32] = core::array::from_fn(|i| 0xa0 ^ (i as u8 * 7));
    let mut out = String::from("{\n");
    out += "  \"standardDerivation\": [\n";
    for (n, w) in [wallet_a, wallet_b].iter().enumerate() {
        let k = ConfidentialKeys::derive(&Keypair::new_from_array(*w)).unwrap();
        out += &format!("    {{ \"walletPrivateKey\": \"{}\", \"elgamalSecretKey\": \"{}\", \"elgamalPubkey\": \"{}\", \"aeKey\": \"{}\" }}{}\n",
            hex(w), hex(k.elgamal.secret().as_bytes()), hex(&PodElGamalPubkey::from(*k.elgamal.pubkey()).0), hex(&<[u8;16]>::from(&k.ae)), if n == 0 { "," } else { "" });
    }
    out += "  ],\n";
    let program_id = Pubkey::new_from_array([7; 32]);
    let wallet_pda = Pubkey::new_from_array([8; 32]);
    let mint = Pubkey::new_from_array([9; 32]);
    let token = Pubkey::new_from_array([10; 32]);
    let seed = pda_wallet_public_seed(&program_id, &wallet_pda, &mint, &token);
    let k = ConfidentialKeys::derive_with_seed(&Keypair::new_from_array(wallet_a), &seed).unwrap();
    out += &format!("  \"pdaWalletDerivation\": {{ \"operatorPrivateKey\": \"{}\", \"programId\": \"{program_id}\", \"walletPda\": \"{wallet_pda}\", \"mint\": \"{mint}\", \"tokenAccount\": \"{token}\", \"publicSeed\": \"{}\", \"elgamalSecretKey\": \"{}\", \"aeKey\": \"{}\" }},\n",
        hex(&wallet_a), hex(&seed), hex(k.elgamal.secret().as_bytes()), hex(&<[u8;16]>::from(&k.ae)));
    // The auditor is wallet B; the amount splits into 16 low bits and 32 high bits.
    let auditor = ConfidentialKeys::derive(&Keypair::new_from_array(wallet_b)).unwrap();
    let amount: u64 = 123_456_789_012;
    let lo = PodElGamalCiphertext::from(auditor.elgamal.pubkey().encrypt(amount & 0xffff));
    let hi = PodElGamalCiphertext::from(auditor.elgamal.pubkey().encrypt(amount >> 16));
    out += &format!("  \"auditorTransferAmount\": {{ \"auditorWalletPrivateKey\": \"{}\", \"ciphertextLo\": \"{}\", \"ciphertextHi\": \"{}\", \"amount\": \"{amount}\" }},\n",
        hex(&wallet_b), hex(&lo.0), hex(&hi.0));
    let owner = ConfidentialKeys::derive(&Keypair::new_from_array(wallet_a)).unwrap();
    let balance: u64 = 987_654_321;
    let ae = PodAeCiphertext::from(owner.ae.encrypt(balance));
    out += &format!("  \"decryptableBalance\": {{ \"ownerWalletPrivateKey\": \"{}\", \"ciphertext\": \"{}\", \"amount\": \"{balance}\" }}\n", hex(&wallet_a), hex(&ae.0));
    out += "}\n";
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/confidential-transfers.json"
        ),
        out,
    )
    .unwrap();
}
