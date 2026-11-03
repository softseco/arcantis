// SPDX-License-Identifier: BUSL-1.1
//! Helpers for the on-chain tests: a local validator with the ZK ElGamal Proof Program and a
//! Token-2022 build that matches the clients (see ../test/fixtures/README.md). Run:
//!
//!   solana-test-validator --reset \
//!     --upgradeable-program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb ../test/fixtures/spl_token_2022.so none \
//!     --bpf-program 5fH1jj6XeZC96jPCxKiSb2onAXcs7f4rMeqMmSsP6puD ../test/fixtures/sentinel.so
//!   CT_LOCAL_PROGRAM=1 cargo test -- --test-threads 1
#![allow(dead_code)]
use std::{sync::Arc, time::Duration};

use solana_client::{nonblocking::rpc_client::RpcClient, rpc_config::CommitmentConfig};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::Transaction,
};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey;
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::{ExtensionInitializationParams, Token},
};

pub const RPC_URL: &str = "http://127.0.0.1:8899";
pub const DECIMALS: u8 = 2;
pub const SENTINEL: Pubkey = solana_sdk::pubkey!("5fH1jj6XeZC96jPCxKiSb2onAXcs7f4rMeqMmSsP6puD");

/// None (and a note) unless CT_LOCAL_PROGRAM=1.
pub fn on_chain() -> Option<Arc<RpcClient>> {
    if std::env::var("CT_LOCAL_PROGRAM").is_err() {
        eprintln!("skipping: set CT_LOCAL_PROGRAM=1 and run a local validator with the ZK program");
        return None;
    }
    Some(Arc::new(RpcClient::new_with_commitment(
        RPC_URL.to_string(),
        CommitmentConfig::confirmed(),
    )))
}

pub async fn funded(rpc: &RpcClient) -> Keypair {
    let keypair = Keypair::new();
    airdrop(rpc, &keypair.pubkey(), 5_000_000_000).await;
    keypair
}

pub async fn airdrop(rpc: &RpcClient, to: &Pubkey, lamports: u64) {
    for _ in 0..8 {
        if let Ok(signature) = rpc.request_airdrop(to, lamports).await {
            for _ in 0..60 {
                if rpc.confirm_transaction(&signature).await.unwrap_or(false) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("airdrop to {to} failed");
}

pub struct TestMint {
    pub mint: Pubkey,
    pub authority: Keypair,
    pub token: Token<ProgramRpcClientSendTransaction>,
}

/// A mint with confidential transfers (accounts approved automatically), an optional auditor and
/// an optional transfer hook. The mint authority is funded: Sentinel makes it pay for its policy.
pub async fn create_mint(
    rpc: &Arc<RpcClient>,
    payer: Arc<dyn Signer>,
    auditor: Option<PodElGamalPubkey>,
    hook: Option<Pubkey>,
) -> TestMint {
    create_mint_approving(rpc, payer, auditor, hook, true).await
}

/// As [`create_mint`], choosing whether new accounts are approved automatically. When they are
/// not, the mint authority (also the confidential-transfer authority) approves each one.
pub async fn create_mint_approving(
    rpc: &Arc<RpcClient>,
    payer: Arc<dyn Signer>,
    auditor: Option<PodElGamalPubkey>,
    hook: Option<Pubkey>,
    auto_approve_new_accounts: bool,
) -> TestMint {
    let mint = Keypair::new();
    let authority = funded(rpc).await;
    let token = Token::new(
        Arc::new(ProgramRpcClient::new(
            rpc.clone(),
            ProgramRpcClientSendTransaction,
        )),
        &spl_token_2022::id(),
        &mint.pubkey(),
        Some(DECIMALS),
        payer,
    );
    let mut extensions = vec![ExtensionInitializationParams::ConfidentialTransferMint {
        authority: Some(authority.pubkey()),
        auto_approve_new_accounts,
        auditor_elgamal_pubkey: auditor,
    }];
    if let Some(program_id) = hook {
        extensions.push(ExtensionInitializationParams::TransferHook {
            authority: Some(authority.pubkey()),
            program_id: Some(program_id),
        });
    }
    token
        .create_mint(&authority.pubkey(), None, extensions, &[&mint])
        .await
        .expect("create mint");
    TestMint {
        mint: mint.pubkey(),
        authority,
        token,
    }
}

impl TestMint {
    pub async fn mint_to(&self, account: &Pubkey, amount: u64) {
        self.token
            .mint_to(
                account,
                &self.authority.pubkey(),
                amount,
                &[&self.authority],
            )
            .await
            .expect("mint_to");
    }
}

pub async fn public_balance(rpc: &RpcClient, account: &Pubkey) -> u64 {
    rpc.get_token_account_balance(account)
        .await
        .unwrap()
        .amount
        .parse()
        .unwrap()
}

/// Sentinel as the mint's transfer hook: a policy (set by the mint authority) and the
/// extra-account-meta list Token-2022 resolves the hook's accounts from.
pub async fn setup_sentinel(rpc: &RpcClient, mint: &TestMint, allow_confidential: bool) {
    let policy = Pubkey::find_program_address(&[b"policy", mint.mint.as_ref()], &SENTINEL).0;
    let metas =
        Pubkey::find_program_address(&[b"extra-account-metas", mint.mint.as_ref()], &SENTINEL).0;
    let system = solana_sdk::pubkey!("11111111111111111111111111111111");
    let initialize_policy = Instruction::new_with_bytes(
        SENTINEL,
        &policy_data([9, 186, 86, 225, 129, 162, 231, 56], allow_confidential),
        vec![
            AccountMeta::new(mint.authority.pubkey(), true),
            AccountMeta::new_readonly(mint.mint, false),
            AccountMeta::new(policy, false),
            AccountMeta::new_readonly(system, false),
        ],
    );
    let initialize_metas = Instruction::new_with_bytes(
        SENTINEL,
        &[92, 197, 174, 197, 41, 124, 19, 3],
        vec![
            AccountMeta::new(mint.authority.pubkey(), true),
            AccountMeta::new(metas, false),
            AccountMeta::new_readonly(mint.mint, false),
            AccountMeta::new_readonly(system, false),
        ],
    );
    send(rpc, &[initialize_policy, initialize_metas], &mint.authority).await;
}

/// Sentinel's `update_policy`: allowlist and blocklist off, a limit, and the confidential opt-in.
pub async fn set_sentinel_confidential(rpc: &RpcClient, mint: &TestMint, allow_confidential: bool) {
    let policy = Pubkey::find_program_address(&[b"policy", mint.mint.as_ref()], &SENTINEL).0;
    let update = Instruction::new_with_bytes(
        SENTINEL,
        &policy_data([212, 245, 246, 7, 163, 151, 18, 57], allow_confidential),
        vec![
            AccountMeta::new_readonly(mint.authority.pubkey(), true),
            AccountMeta::new_readonly(mint.mint, false),
            AccountMeta::new(policy, false),
        ],
    );
    send(rpc, &[update], &mint.authority).await;
}

fn policy_data(discriminator: [u8; 8], allow_confidential: bool) -> Vec<u8> {
    let mut data = discriminator.to_vec();
    data.extend([0u8, 0u8]); // allowlist off, blocklist off
    data.extend(1_000_000u64.to_le_bytes()); // limit for public transfers
    data.push(u8::from(allow_confidential));
    data
}

pub async fn send(rpc: &RpcClient, instructions: &[Instruction], signer: &Keypair) {
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        instructions,
        Some(&signer.pubkey()),
        &[signer],
        blockhash,
    );
    rpc.send_and_confirm_transaction(&tx).await.expect("send");
}

/// The proof accounts whose authority is `authority`.
pub async fn proof_accounts_of(rpc: &RpcClient, authority: &Pubkey) -> usize {
    use solana_client::{
        rpc_config::{
            RpcAccountInfoConfig, RpcProgramAccountsConfig, UiAccountEncoding, UiDataSliceConfig,
        },
        rpc_filter::{Memcmp, RpcFilterType},
    };
    rpc.get_program_ui_accounts_with_config(
        &solana_zk_elgamal_proof_interface::id(),
        RpcProgramAccountsConfig {
            filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
                0,
                authority.as_ref(),
            ))]),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                data_slice: Some(UiDataSliceConfig {
                    offset: 0,
                    length: 0,
                }),
                commitment: Some(rpc.commitment()),
                ..RpcAccountInfoConfig::default()
            },
            ..RpcProgramAccountsConfig::default()
        },
    )
    .await
    .unwrap()
    .len()
}
