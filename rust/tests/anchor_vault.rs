// SPDX-License-Identifier: BUSL-1.1
//! The example program in examples/anchor-vault: a PDA holds a confidential balance, the
//! operator's client prepares the proofs with this crate, and the program makes the Token-2022
//! calls through CPI. Needs the program on the validator (see examples/anchor-vault/README.md):
//!
//!   --bpf-program DzaS2RboEYWKC1EvuPPnWpDbjJesPheCw3KV14qVvoPn examples/anchor-vault/target/deploy/confidential_vault.so
mod common;

use std::sync::Arc;

use arcantis::{
    decrypt_auditor_amount, derive_auditor_keypair, ConfidentialClient, ConfidentialKeys,
    TOKEN_2022_PROGRAM_ID,
};
use common::*;
use solana_client::{
    nonblocking::rpc_client::RpcClient,
    rpc_config::{RpcTransactionConfig, UiTransactionEncoding},
};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    transaction::Transaction,
};
use solana_zk_sdk::encryption::elgamal::ElGamalCiphertext;
use solana_zk_sdk_pod::encryption::elgamal::{PodElGamalCiphertext, PodElGamalPubkey};
use spl_associated_token_account_interface::instruction::create_associated_token_account_idempotent;

const VAULT_PROGRAM: Pubkey = solana_sdk::pubkey!("DzaS2RboEYWKC1EvuPPnWpDbjJesPheCw3KV14qVvoPn");
const SYSTEM: Pubkey = solana_sdk::pubkey!("11111111111111111111111111111111");

// Anchor instruction discriminators: sha256("global:<name>")[..8].
const INITIALIZE: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];
const CONFIGURE: [u8; 8] = [245, 7, 108, 117, 95, 196, 54, 217];
const APPLY_PENDING: [u8; 8] = [88, 86, 232, 48, 42, 150, 180, 196];
const PAY: [u8; 8] = [119, 18, 216, 65, 192, 117, 122, 220];

#[tokio::test]
async fn a_program_holds_and_pays_out_a_confidential_balance() {
    let Some(rpc) = on_chain() else { return };
    if rpc.get_account(&VAULT_PROGRAM).await.is_err() {
        eprintln!(
            "skipping: the example program is not loaded (see examples/anchor-vault/README.md)"
        );
        return;
    }
    // With Sentinel on the validator, the mint also gets it as transfer hook, so the program's
    // transfer has to pass the hook's accounts along.
    let with_hook = rpc.get_account(&SENTINEL).await.is_ok();
    let payer: Arc<dyn Signer + Send + Sync> = Arc::new(funded(&rpc).await);
    let client = ConfidentialClient::new(rpc.clone(), payer.clone());
    let operator = funded(&rpc).await;
    let auditor = derive_auditor_keypair(&Keypair::new()).unwrap();
    let mint = create_mint(
        &rpc,
        payer.clone(),
        Some(PodElGamalPubkey::from(*auditor.pubkey())),
        with_hook.then_some(SENTINEL),
    )
    .await;
    if with_hook {
        setup_sentinel(&rpc, &mint, true).await;
    }
    let vault = Pubkey::find_program_address(&[b"vault", mint.mint.as_ref()], &VAULT_PROGRAM).0;
    let vault_token = client.token_account(&vault, &mint.mint);

    // The vault and its token account (owned by the vault PDA).
    send(
        &rpc,
        &[
            Instruction::new_with_bytes(
                VAULT_PROGRAM,
                &INITIALIZE,
                vec![
                    AccountMeta::new(operator.pubkey(), true),
                    AccountMeta::new_readonly(mint.mint, false),
                    AccountMeta::new(vault, false),
                    AccountMeta::new_readonly(SYSTEM, false),
                ],
            ),
            create_associated_token_account_idempotent(
                &operator.pubkey(),
                &vault,
                &mint.mint,
                &TOKEN_2022_PROGRAM_ID,
            ),
        ],
        &operator,
    )
    .await;

    // The vault's keys come from the operator's wallet, scoped to the vault's token account.
    let keys = ConfidentialKeys::derive_for_pda_wallet(
        &operator,
        &VAULT_PROGRAM,
        &vault,
        &mint.mint,
        &vault_token,
    )
    .unwrap();
    let configure = client.prepare_configure(&keys).await.unwrap();
    let mut data = CONFIGURE.to_vec();
    data.extend_from_slice(&configure.decryptable_zero_balance);
    send(
        &rpc,
        &[Instruction::new_with_bytes(
            VAULT_PROGRAM,
            &data,
            vec![
                AccountMeta::new(operator.pubkey(), true),
                AccountMeta::new_readonly(vault, false),
                AccountMeta::new_readonly(mint.mint, false),
                AccountMeta::new(vault_token, false),
                AccountMeta::new_readonly(configure.pubkey_validity_proof, false),
                AccountMeta::new_readonly(TOKEN_2022_PROGRAM_ID, false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
        )],
        &operator,
    )
    .await;
    assert_eq!(
        client
            .close_proof_accounts(&[configure.pubkey_validity_proof])
            .await
            .closed
            .len(),
        1
    );

    // Alice pays 700 into the vault with an ordinary confidential transfer.
    let (alice, bob) = (Keypair::new(), Keypair::new());
    let alice_token = client
        .configure_account(&alice, &mint.mint)
        .await
        .unwrap()
        .token_account;
    let bob_token = client
        .configure_account(&bob, &mint.mint)
        .await
        .unwrap()
        .token_account;
    mint.mint_to(&alice_token, 1_000).await;
    client.deposit(&alice, &mint.mint, 1_000).await.unwrap();
    client
        .apply_pending_balance(&alice, &mint.mint)
        .await
        .unwrap();
    client
        .transfer(&alice, &mint.mint, &vault, 700)
        .await
        .unwrap();

    // The program applies the vault's pending balance with what the client computed.
    let update = client
        .pending_balance_update(&mint.mint, &vault_token, &keys)
        .await
        .unwrap();
    let mut data = APPLY_PENDING.to_vec();
    data.extend_from_slice(&update.expected_pending_balance_credit_counter.to_le_bytes());
    data.extend_from_slice(&update.new_decryptable_available_balance);
    send(
        &rpc,
        &[Instruction::new_with_bytes(
            VAULT_PROGRAM,
            &data,
            vec![
                AccountMeta::new_readonly(operator.pubkey(), true),
                AccountMeta::new_readonly(vault, false),
                AccountMeta::new(vault_token, false),
                AccountMeta::new_readonly(TOKEN_2022_PROGRAM_ID, false),
            ],
        )],
        &operator,
    )
    .await;
    assert_eq!(
        client
            .decrypt_balance_of(&mint.mint, &vault_token, &keys)
            .await
            .unwrap(),
        700
    );

    // The vault pays Bob 250: the client prepares the proofs, the program transfers.
    let pay = |signer: Pubkey, prepared: &arcantis::PreparedTransfer, hook: &[AccountMeta]| {
        let mut data = PAY.to_vec();
        data.extend_from_slice(&prepared.new_decryptable_available_balance);
        data.extend_from_slice(&prepared.auditor_ciphertext_lo);
        data.extend_from_slice(&prepared.auditor_ciphertext_hi);
        let mut accounts = vec![
            AccountMeta::new_readonly(signer, true),
            AccountMeta::new_readonly(vault, false),
            AccountMeta::new_readonly(mint.mint, false),
            AccountMeta::new(vault_token, false),
            AccountMeta::new(prepared.destination_token_account, false),
            AccountMeta::new_readonly(prepared.equality_proof, false),
            AccountMeta::new_readonly(prepared.ciphertext_validity_proof, false),
            AccountMeta::new_readonly(prepared.range_proof, false),
            AccountMeta::new_readonly(TOKEN_2022_PROGRAM_ID, false),
        ];
        accounts.extend_from_slice(hook);
        Instruction::new_with_bytes(VAULT_PROGRAM, &data, accounts)
    };
    let prepared = client
        .prepare_transfer(&mint.mint, &vault_token, &keys, &bob_token, 250)
        .await
        .unwrap();
    let hook = client
        .transfer_hook_accounts(&mint.mint, &vault_token, &bob_token, &vault)
        .await
        .unwrap();
    assert_eq!(hook.is_empty(), !with_hook);
    let signature = send_signed(&rpc, &[pay(operator.pubkey(), &prepared, &hook)], &operator)
        .await
        .unwrap();
    assert_eq!(
        client
            .close_proof_accounts(&prepared.proof_accounts())
            .await
            .closed
            .len(),
        3
    );

    // The auditor reads the amount from the transfer the program made (an inner instruction).
    let data = inner_transfer_data(&rpc, &signature).await;
    let ciphertext = |range: std::ops::Range<usize>| {
        ElGamalCiphertext::try_from(PodElGamalCiphertext(data[range].try_into().unwrap())).unwrap()
    };
    assert_eq!(
        decrypt_auditor_amount(&auditor, &ciphertext(38..102), &ciphertext(102..166)).unwrap(),
        250
    );

    client
        .apply_pending_balance(&bob, &mint.mint)
        .await
        .unwrap();
    assert_eq!(client.decrypt_balance(&bob, &mint.mint).await.unwrap(), 250);
    assert_eq!(
        client
            .decrypt_balance_of(&mint.mint, &vault_token, &keys)
            .await
            .unwrap(),
        450
    );

    // Only the operator can make the vault pay.
    let stranger = funded(&rpc).await;
    let prepared = client
        .prepare_transfer(&mint.mint, &vault_token, &keys, &bob_token, 1)
        .await
        .unwrap();
    let refused = send_signed(&rpc, &[pay(stranger.pubkey(), &prepared, &hook)], &stranger).await;
    let refused = refused.unwrap_err();
    assert!(
        refused.contains("ConstraintHasOne") || refused.contains("0x7d1"),
        "refused by the vault's operator check: {refused}"
    );
    client
        .close_proof_accounts(&prepared.proof_accounts())
        .await;
    assert_eq!(
        client
            .decrypt_balance_of(&mint.mint, &vault_token, &keys)
            .await
            .unwrap(),
        450
    );
    assert_eq!(proof_accounts_of(&rpc, &payer.pubkey()).await, 0);
}

async fn send_signed(
    rpc: &RpcClient,
    instructions: &[Instruction],
    signer: &Keypair,
) -> Result<Signature, String> {
    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        instructions,
        Some(&signer.pubkey()),
        &[signer],
        blockhash,
    );
    rpc.send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| format!("{e:?}"))
}

/// The data of the Token-2022 confidential transfer a program made in this transaction.
async fn inner_transfer_data(rpc: &RpcClient, signature: &Signature) -> Vec<u8> {
    use solana_client::rpc_response::{UiInnerInstructions, UiInstruction};
    let tx = rpc
        .get_transaction_with_config(
            signature,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                commitment: Some(rpc.commitment()),
                max_supported_transaction_version: Some(0),
            },
        )
        .await
        .unwrap();
    let keys = tx
        .transaction
        .transaction
        .decode()
        .unwrap()
        .message
        .static_account_keys()
        .to_vec();
    let inner: Option<Vec<UiInnerInstructions>> =
        tx.transaction.meta.unwrap().inner_instructions.into();
    inner
        .unwrap()
        .into_iter()
        .flat_map(|group| group.instructions)
        .find_map(|ix| match ix {
            UiInstruction::Compiled(c)
                if keys[usize::from(c.program_id_index)] == TOKEN_2022_PROGRAM_ID =>
            {
                let data = bs58::decode(&c.data).into_vec().unwrap();
                data.starts_with(&[27, 7]).then_some(data)
            }
            _ => None,
        })
        .expect("a confidential transfer made by the program")
}
