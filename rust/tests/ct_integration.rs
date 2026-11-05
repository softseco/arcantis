// SPDX-License-Identifier: BUSL-1.1
//! On-chain tests of the crate against a local validator (see tests/common/mod.rs for the setup).
//! Skipped unless CT_LOCAL_PROGRAM=1, so `cargo test` stays green without a validator.
mod common;

use std::sync::Arc;

use arcantis::{
    decrypt_auditor_amount, derive_auditor_keypair, ConfidentialClient, ConfidentialKeys,
    ErrorCode, TOKEN_2022_PROGRAM_ID,
};
use common::*;
use solana_sdk::{pubkey::Pubkey, signature::Signature, signer::Signer};
use solana_zk_sdk::encryption::elgamal::ElGamalCiphertext;
use solana_zk_sdk_pod::encryption::{
    auth_encryption::PodAeCiphertext,
    elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
};
use spl_token_2022_interface::extension::confidential_transfer::instruction as ct_instruction;

const COMPUTE_BUDGET: Pubkey = solana_sdk::pubkey!("ComputeBudget111111111111111111111111111111");
const ZK_PROOF_PROGRAM: Pubkey = solana_sdk::pubkey!("ZkE1Gama1Proof11111111111111111111111111111");

#[tokio::test]
async fn transfers_and_withdraws_with_an_auditor_and_a_priority_fee() {
    let Some(rpc) = on_chain() else { return };
    let payer: Arc<dyn Signer + Send + Sync> = Arc::new(funded(&rpc).await);
    let client = ConfidentialClient::new(rpc.clone(), payer.clone()).with_compute_unit_price(1_000);

    let auditor_wallet = solana_sdk::signature::Keypair::new();
    let auditor = derive_auditor_keypair(&auditor_wallet).unwrap();
    let mint = create_mint(
        &rpc,
        payer.clone(),
        Some(PodElGamalPubkey::from(*auditor.pubkey())),
        None,
    )
    .await;
    let (alice, bob) = (
        solana_sdk::signature::Keypair::new(),
        solana_sdk::signature::Keypair::new(),
    );

    let alice_account = client
        .configure_account(&alice, &mint.mint)
        .await
        .unwrap()
        .token_account;
    client.configure_account(&bob, &mint.mint).await.unwrap();
    mint.mint_to(&alice_account, 1_000).await;
    client.deposit(&alice, &mint.mint, 1_000).await.unwrap();
    client
        .apply_pending_balance(&alice, &mint.mint)
        .await
        .unwrap();
    assert_eq!(
        client.decrypt_balance(&alice, &mint.mint).await.unwrap(),
        1_000
    );
    assert_eq!(public_balance(&rpc, &alice_account).await, 0);

    // No auditor key passed: the crate reads it from the mint.
    let sent = client
        .transfer(&alice, &mint.mint, &bob.pubkey(), 400)
        .await
        .unwrap();
    assert_eq!(
        sent.signatures,
        vec![sent.transfer_signature],
        "one transaction, the proofs inside"
    );
    client
        .apply_pending_balance(&bob, &mint.mint)
        .await
        .unwrap();
    assert_eq!(client.decrypt_balance(&bob, &mint.mint).await.unwrap(), 400);

    // The auditor reads the amount from the transfer instruction.
    let sent_tx = sent_transaction(&rpc, &sent.transfer_signature).await;
    assert_eq!(sent_tx.version, 1, "a v1 transaction");
    assert_eq!(
        sent_tx.programs_called(),
        vec![
            TOKEN_2022_PROGRAM_ID,
            ZK_PROOF_PROGRAM,
            ZK_PROOF_PROGRAM,
            ZK_PROOF_PROGRAM
        ],
        "the transfer, then its three proofs"
    );
    assert!(
        sent_tx.size <= 4096,
        "{} bytes, within a v1 transaction",
        sent_tx.size
    );
    let data = sent_tx.token_instruction([27, 7]);
    let ciphertext = |range: std::ops::Range<usize>| {
        ElGamalCiphertext::try_from(PodElGamalCiphertext(data[range].try_into().unwrap())).unwrap()
    };
    assert_eq!(
        decrypt_auditor_amount(&auditor, &ciphertext(38..102), &ciphertext(102..166)).unwrap(),
        400
    );
    assert!(
        sent_tx.priority_fee.is_some_and(|fee| fee > 0),
        "the transfer transaction carries the priority fee"
    );

    let withdrawn = client.withdraw(&alice, &mint.mint, 100).await.unwrap();
    assert_eq!(
        withdrawn.signatures,
        vec![withdrawn.withdraw_signature],
        "one transaction, the proofs inside"
    );
    let withdraw_tx = sent_transaction(&rpc, &withdrawn.withdraw_signature).await;
    assert_eq!(
        withdraw_tx.programs_called(),
        vec![TOKEN_2022_PROGRAM_ID, ZK_PROOF_PROGRAM, ZK_PROOF_PROGRAM],
        "the withdraw, then its two proofs"
    );
    assert_eq!(
        client.decrypt_balance(&alice, &mint.mint).await.unwrap(),
        500
    );
    assert_eq!(public_balance(&rpc, &alice_account).await, 100);

    // With proof accounts instead (an RPC without v1 transactions): five transactions for a
    // transfer and four for a withdraw, with the priority fee as an instruction.
    let separate = ConfidentialClient::new(rpc.clone(), payer.clone())
        .with_compute_unit_price(1_000)
        .with_single_transaction(false);
    let sent = separate
        .transfer(&alice, &mint.mint, &bob.pubkey(), 50)
        .await
        .unwrap();
    assert_eq!(
        sent.signatures.len(),
        5,
        "four proof transactions and the transfer"
    );
    let sent_tx = sent_transaction(&rpc, &sent.transfer_signature).await;
    assert_ne!(sent_tx.version, 1);
    assert!(
        sent_tx.programs.contains(&COMPUTE_BUDGET),
        "the transfer transaction carries the priority fee"
    );
    let data = sent_tx.token_instruction([27, 7]);
    let ciphertext = |range: std::ops::Range<usize>| {
        ElGamalCiphertext::try_from(PodElGamalCiphertext(data[range].try_into().unwrap())).unwrap()
    };
    assert_eq!(
        decrypt_auditor_amount(&auditor, &ciphertext(38..102), &ciphertext(102..166)).unwrap(),
        50
    );
    let withdrawn = separate.withdraw(&alice, &mint.mint, 50).await.unwrap();
    assert_eq!(
        withdrawn.signatures.len(),
        4,
        "three proof transactions and the withdraw"
    );
    assert_eq!(
        client.decrypt_balance(&alice, &mint.mint).await.unwrap(),
        400
    );
    assert_eq!(public_balance(&rpc, &alice_account).await, 150);

    // Every proof account was closed, and its rent went back to the payer.
    assert_eq!(proof_accounts_of(&rpc, &payer.pubkey()).await, 0);
}

#[tokio::test]
async fn repairs_an_aes_copy_left_behind_by_a_credit_during_an_apply() {
    let Some(rpc) = on_chain() else { return };
    let payer: Arc<dyn Signer + Send + Sync> = Arc::new(funded(&rpc).await);
    let client = ConfidentialClient::new(rpc.clone(), payer.clone());
    let mint = create_mint(&rpc, payer.clone(), None, None).await;
    let (alice, bob) = (funded(&rpc).await, funded(&rpc).await);
    for owner in [&alice, &bob] {
        let account = client
            .configure_account(owner, &mint.mint)
            .await
            .unwrap()
            .token_account;
        mint.mint_to(&account, 1_000).await;
        client.deposit(owner, &mint.mint, 1_000).await.unwrap();
        client
            .apply_pending_balance(owner, &mint.mint)
            .await
            .unwrap();
    }
    let keys = ConfidentialKeys::derive(&alice).unwrap();
    let alice_account = client.token_account(&alice.pubkey(), &mint.mint);

    // Bob pays Alice 300, and Alice's apply carries the copy she computed before the payment
    // arrived (1,000). Token-2022 accepts it: the encrypted balance is 1,300, the copy 1,000.
    client
        .transfer(&bob, &mint.mint, &alice.pubkey(), 300)
        .await
        .unwrap();
    let stale = ct_instruction::apply_pending_balance(
        &TOKEN_2022_PROGRAM_ID,
        &alice_account,
        0,
        &PodAeCiphertext::from(keys.ae.encrypt(1_000)),
        &alice.pubkey(),
        &[],
    )
    .unwrap();
    send(&rpc, &[stale], &alice).await;
    assert_eq!(aes_copy(&rpc, &alice_account, &keys).await, 1_000);

    // The crate reads the real balance, and a transfer of more than the stale copy goes through
    // and writes a correct copy.
    assert_eq!(
        client.decrypt_balance(&alice, &mint.mint).await.unwrap(),
        1_300
    );
    client
        .transfer(&alice, &mint.mint, &bob.pubkey(), 1_200)
        .await
        .unwrap();
    assert_eq!(aes_copy(&rpc, &alice_account, &keys).await, 100);
    client.withdraw(&alice, &mint.mint, 100).await.unwrap();
    assert_eq!(public_balance(&rpc, &alice_account).await, 100);
}

#[tokio::test]
async fn prepares_a_withdraw_that_the_owner_signs_separately() {
    let Some(rpc) = on_chain() else { return };
    let payer: Arc<dyn Signer + Send + Sync> = Arc::new(funded(&rpc).await);
    let client = ConfidentialClient::new(rpc.clone(), payer.clone());
    let mint = create_mint(&rpc, payer.clone(), None, None).await;
    let alice = funded(&rpc).await;
    let account = client
        .configure_account(&alice, &mint.mint)
        .await
        .unwrap()
        .token_account;
    mint.mint_to(&account, 1_000).await;
    client.deposit(&alice, &mint.mint, 1_000).await.unwrap();
    client
        .apply_pending_balance(&alice, &mint.mint)
        .await
        .unwrap();
    let keys = ConfidentialKeys::derive(&alice).unwrap();

    // More than the balance is refused before any proof account exists.
    assert_eq!(
        code(
            client
                .prepare_withdraw(&mint.mint, &account, &keys, 1_001)
                .await
        ),
        ErrorCode::InsufficientFunds
    );
    assert_eq!(proof_accounts_of(&rpc, &payer.pubkey()).await, 0);

    // The payer verifies the proofs; the owner signs only the withdraw, as a program would.
    let prepared = client
        .prepare_withdraw(&mint.mint, &account, &keys, 400)
        .await
        .unwrap();
    assert_eq!(proof_accounts_of(&rpc, &payer.pubkey()).await, 2);
    send(
        &rpc,
        &[prepared.instruction(&alice.pubkey()).unwrap()],
        &alice,
    )
    .await;
    let closed = client
        .close_proof_accounts(&prepared.proof_accounts())
        .await;
    assert_eq!(closed.closed.len(), 2);
    assert_eq!(proof_accounts_of(&rpc, &payer.pubkey()).await, 0);
    assert_eq!(public_balance(&rpc, &account).await, 400);
    assert_eq!(
        client.decrypt_balance(&alice, &mint.mint).await.unwrap(),
        600
    );
}

#[tokio::test]
async fn refuses_recipients_that_cannot_take_a_confidential_transfer() {
    let Some(rpc) = on_chain() else { return };
    let payer: Arc<dyn Signer + Send + Sync> = Arc::new(funded(&rpc).await);
    let client = ConfidentialClient::new(rpc.clone(), payer.clone());
    // New accounts wait for the confidential-transfer authority's approval.
    let mint = create_mint_approving(&rpc, payer.clone(), None, None, false).await;
    let (alice, bob) = (funded(&rpc).await, funded(&rpc).await);
    let alice_account = client
        .configure_account(&alice, &mint.mint)
        .await
        .unwrap()
        .token_account;
    let bob_account = client
        .configure_account(&bob, &mint.mint)
        .await
        .unwrap()
        .token_account;
    let approve = |account: &Pubkey| {
        ct_instruction::approve_account(
            &TOKEN_2022_PROGRAM_ID,
            account,
            &mint.mint,
            &mint.authority.pubkey(),
            &[],
        )
        .unwrap()
    };
    send(&rpc, &[approve(&alice_account)], &mint.authority).await;
    mint.mint_to(&alice_account, 100).await;
    client.deposit(&alice, &mint.mint, 100).await.unwrap();
    client
        .apply_pending_balance(&alice, &mint.mint)
        .await
        .unwrap();

    // Bob's account is not approved yet.
    assert_eq!(
        code(client.transfer(&alice, &mint.mint, &bob.pubkey(), 10).await),
        ErrorCode::AccountNotApproved
    );
    // Approved, but Bob has turned confidential credits off.
    send(&rpc, &[approve(&bob_account)], &mint.authority).await;
    let disable = ct_instruction::disable_confidential_credits(
        &TOKEN_2022_PROGRAM_ID,
        &bob_account,
        &bob.pubkey(),
        &[],
    )
    .unwrap();
    send(&rpc, &[disable], &bob).await;
    assert_eq!(
        code(client.transfer(&alice, &mint.mint, &bob.pubkey(), 10).await),
        ErrorCode::RecipientRejectsConfidential
    );
    // Both refusals came before anything was created.
    assert_eq!(proof_accounts_of(&rpc, &payer.pubkey()).await, 0);
    assert_eq!(
        client.decrypt_balance(&alice, &mint.mint).await.unwrap(),
        100
    );
}

/// The owner's AES copy of the available balance, as stored.
async fn aes_copy(
    rpc: &solana_client::nonblocking::rpc_client::RpcClient,
    account: &Pubkey,
    keys: &ConfidentialKeys,
) -> u64 {
    use spl_token_2022_interface::{
        extension::{
            confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
            StateWithExtensionsOwned,
        },
        state::Account,
    };
    let data = rpc.get_account(account).await.unwrap().data;
    let state = StateWithExtensionsOwned::<Account>::unpack(data).unwrap();
    let ct = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();
    let copy = solana_zk_sdk::encryption::auth_encryption::AeCiphertext::try_from(
        ct.decryptable_available_balance,
    )
    .unwrap();
    keys.ae.decrypt(&copy).unwrap()
}

#[tokio::test]
async fn refuses_before_signing_anything() {
    let Some(rpc) = on_chain() else { return };
    let payer: Arc<dyn Signer + Send + Sync> = Arc::new(funded(&rpc).await);
    let client = ConfidentialClient::new(rpc.clone(), payer.clone());
    let mint = create_mint(&rpc, payer.clone(), None, None).await;
    let (alice, bob, carol) = (
        solana_sdk::signature::Keypair::new(),
        solana_sdk::signature::Keypair::new(),
        solana_sdk::signature::Keypair::new(),
    );
    let alice_account = client
        .configure_account(&alice, &mint.mint)
        .await
        .unwrap()
        .token_account;
    client.configure_account(&bob, &mint.mint).await.unwrap();
    mint.mint_to(&alice_account, 50).await;
    let lamports_before = rpc.get_balance(&payer.pubkey()).await.unwrap();

    assert_eq!(
        code(client.configure_account(&alice, &mint.mint).await),
        ErrorCode::AccountAlreadyConfigured
    );
    assert_eq!(
        code(client.deposit(&alice, &mint.mint, 0).await),
        ErrorCode::InvalidInput
    );
    assert_eq!(
        code(client.deposit(&alice, &mint.mint, 1 << 48).await),
        ErrorCode::AmountTooLarge
    );
    assert_eq!(
        code(client.deposit(&alice, &mint.mint, 51).await),
        ErrorCode::InsufficientFunds
    );
    assert_eq!(
        code(client.deposit(&carol, &mint.mint, 1).await),
        ErrorCode::AccountNotFound
    );
    assert_eq!(
        code(client.transfer(&alice, &mint.mint, &bob.pubkey(), 1).await),
        ErrorCode::InsufficientFunds
    );
    let missing = client
        .transfer(&alice, &mint.mint, &carol.pubkey(), 1)
        .await
        .unwrap_err();
    assert_eq!(missing.code(), ErrorCode::AccountNotFound);
    assert!(
        missing
            .to_string()
            .contains("the recipient's token account"),
        "{missing}"
    );
    assert_eq!(
        code(client.withdraw(&alice, &mint.mint, 1).await),
        ErrorCode::InsufficientFunds
    );
    let bob_keys = ConfidentialKeys::derive(&bob).unwrap();
    assert_eq!(
        code(
            client
                .decrypt_balance_of(&mint.mint, &alice_account, &bob_keys)
                .await
        ),
        ErrorCode::KeysMismatch
    );
    assert_eq!(
        code(client.deposit(&alice, &Pubkey::new_unique(), 1).await),
        ErrorCode::AccountNotFound
    );

    assert_eq!(
        rpc.get_balance(&payer.pubkey()).await.unwrap(),
        lamports_before,
        "nothing was sent"
    );
}

#[tokio::test]
async fn goes_through_a_transfer_hook_and_cleans_up_when_the_hook_refuses() {
    let Some(rpc) = on_chain() else { return };
    if rpc.get_account(&SENTINEL).await.is_err() {
        eprintln!("skipping: Sentinel is not loaded on the validator (--bpf-program {SENTINEL} test/fixtures/sentinel.so)");
        return;
    }
    let payer: Arc<dyn Signer + Send + Sync> = Arc::new(funded(&rpc).await);
    let client = ConfidentialClient::new(rpc.clone(), payer.clone());
    let mint = create_mint(&rpc, payer.clone(), None, Some(SENTINEL)).await;
    // Sentinel cannot check a confidential amount, so it refuses confidential transfers until the
    // issuer opts in.
    setup_sentinel(&rpc, &mint, false).await;
    let (alice, bob) = (
        solana_sdk::signature::Keypair::new(),
        solana_sdk::signature::Keypair::new(),
    );
    let alice_account = client
        .configure_account(&alice, &mint.mint)
        .await
        .unwrap()
        .token_account;
    client.configure_account(&bob, &mint.mint).await.unwrap();
    mint.mint_to(&alice_account, 1_000).await;
    client.deposit(&alice, &mint.mint, 1_000).await.unwrap();
    client
        .apply_pending_balance(&alice, &mint.mint)
        .await
        .unwrap();

    // In one transaction, the hook's refusal shows in the simulation: nothing is sent, and
    // there are no proof accounts to clean up.
    let refused = client
        .transfer(&alice, &mint.mint, &bob.pubkey(), 300)
        .await
        .unwrap_err();
    assert_eq!(refused.code(), ErrorCode::TransactionFailed, "{refused}");
    assert_eq!(refused.step(), Some("transfer"));
    assert!(
        refused
            .logs()
            .iter()
            .any(|l| l.contains(&format!("Program {SENTINEL} invoke"))),
        "Sentinel ran as the hook"
    );
    assert!(refused.proof_accounts().is_none());
    assert!(refused.signatures().is_empty(), "nothing was sent");

    // With proof accounts, the proofs go through, then the hook refuses the transfer: the crate
    // closes the proof accounts and says which step failed.
    let separate =
        ConfidentialClient::new(rpc.clone(), payer.clone()).with_single_transaction(false);
    let refused = separate
        .transfer(&alice, &mint.mint, &bob.pubkey(), 300)
        .await
        .unwrap_err();
    assert_eq!(refused.code(), ErrorCode::TransactionFailed, "{refused}");
    assert_eq!(refused.step(), Some("transfer"));
    assert!(
        refused
            .logs()
            .iter()
            .any(|l| l.contains(&format!("Program {SENTINEL} invoke"))),
        "Sentinel ran as the hook"
    );
    let proofs = refused.proof_accounts().expect("proof accounts reported");
    assert_eq!((proofs.closed.len(), proofs.left_open.len()), (3, 0));
    assert_eq!(
        refused.signatures().len(),
        5,
        "four proof transactions and one that closed them"
    );
    assert_eq!(proof_accounts_of(&rpc, &payer.pubkey()).await, 0);
    assert_eq!(
        client.decrypt_balance(&alice, &mint.mint).await.unwrap(),
        1_000
    );

    // With the opt-in, the same transfer goes through Sentinel.
    set_sentinel_confidential(&rpc, &mint, true).await;
    let sent = client
        .transfer(&alice, &mint.mint, &bob.pubkey(), 300)
        .await
        .unwrap();
    assert_eq!(sent.signatures.len(), 1, "one transaction through the hook");
    let sent_tx = sent_transaction(&rpc, &sent.transfer_signature).await;
    assert_eq!(sent_tx.version, 1);
    assert!(
        sent_tx.programs.contains(&SENTINEL),
        "the transfer passed Sentinel's accounts"
    );
    eprintln!(
        "a confidential transfer through the hook: {} bytes, {} accounts",
        sent_tx.size,
        sent_tx.programs.len()
    );
    client
        .apply_pending_balance(&bob, &mint.mint)
        .await
        .unwrap();
    assert_eq!(client.decrypt_balance(&bob, &mint.mint).await.unwrap(), 300);
}

#[tokio::test]
async fn recovers_proof_accounts_left_behind() {
    let Some(rpc) = on_chain() else { return };
    let payer: Arc<dyn Signer + Send + Sync> = Arc::new(funded(&rpc).await);
    let client = ConfidentialClient::new(rpc.clone(), payer.clone());
    let mint = create_mint(&rpc, payer.clone(), None, None).await;
    let (alice, bob) = (
        solana_sdk::signature::Keypair::new(),
        solana_sdk::signature::Keypair::new(),
    );
    let alice_account = client
        .configure_account(&alice, &mint.mint)
        .await
        .unwrap()
        .token_account;
    let bob_account = client
        .configure_account(&bob, &mint.mint)
        .await
        .unwrap()
        .token_account;
    mint.mint_to(&alice_account, 10).await;
    client.deposit(&alice, &mint.mint, 10).await.unwrap();
    client
        .apply_pending_balance(&alice, &mint.mint)
        .await
        .unwrap();

    // A process that prepared a transfer and stopped: three proof accounts stay open.
    let keys = ConfidentialKeys::derive(&alice).unwrap();
    let prepared = client
        .prepare_transfer(&mint.mint, &alice_account, &keys, &bob_account, 5)
        .await
        .unwrap();
    assert_eq!(proof_accounts_of(&rpc, &payer.pubkey()).await, 3);
    let before = rpc.get_balance(&payer.pubkey()).await.unwrap();

    let recovered = client.recover_proof_accounts().await.unwrap();
    let mut closed = recovered.closed.clone();
    closed.sort();
    let mut expected = prepared.proof_accounts();
    expected.sort();
    assert_eq!(closed, expected);
    assert!(recovered.left_open.is_empty());
    assert!(
        rpc.get_balance(&payer.pubkey()).await.unwrap() > before,
        "the rent came back"
    );
    assert_eq!(proof_accounts_of(&rpc, &payer.pubkey()).await, 0);
}

fn code<T>(result: arcantis::Result<T>) -> ErrorCode {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.code(),
    }
}

/// A sent transaction as the chain has it: its version (`1`, or `0` for legacy and v0), its size,
/// every account it names, its instructions, and the priority fee of a v1 transaction.
struct SentTransaction {
    version: u8,
    size: usize,
    programs: Vec<Pubkey>,
    instructions: Vec<(Pubkey, Vec<u8>)>,
    priority_fee: Option<u64>,
}

impl SentTransaction {
    /// The data of the Token-2022 instruction starting with `prefix`.
    fn token_instruction(&self, prefix: [u8; 2]) -> Vec<u8> {
        self.instructions
            .iter()
            .find(|(program, data)| *program == TOKEN_2022_PROGRAM_ID && data.starts_with(&prefix))
            .expect("the instruction")
            .1
            .clone()
    }

    /// The program of each instruction, in order.
    fn programs_called(&self) -> Vec<Pubkey> {
        self.instructions
            .iter()
            .map(|(program, _)| *program)
            .collect()
    }
}

/// Read a transaction of any version. The pinned client cannot decode v1 transactions, so it is
/// asked for as base64 and a v1 one is read with `solana-message` 6.
async fn sent_transaction(
    rpc: &solana_client::nonblocking::rpc_client::RpcClient,
    signature: &Signature,
) -> SentTransaction {
    use base64::Engine as _;
    use solana_client::rpc_request::RpcRequest;
    let response: serde_json::Value = rpc
        .send(
            RpcRequest::GetTransaction,
            serde_json::json!([
                signature.to_string(),
                {"encoding": "base64", "commitment": "confirmed", "maxSupportedTransactionVersion": 1}
            ]),
        )
        .await
        .unwrap();
    let wire = base64::engine::general_purpose::STANDARD
        .decode(
            response["transaction"][0]
                .as_str()
                .expect("a base64 transaction"),
        )
        .unwrap();
    if wire[0] == 0x81 {
        let signatures = usize::from(wire[1]);
        let message: solana_message::VersionedMessage =
            wincode::deserialize(&wire[..wire.len() - 64 * signatures]).unwrap();
        let solana_message::VersionedMessage::V1(message) = message else {
            panic!("not a v1 message")
        };
        let keys: Vec<Pubkey> = message
            .account_keys
            .iter()
            .map(|k| Pubkey::new_from_array(k.to_bytes()))
            .collect();
        let instructions = message
            .instructions
            .iter()
            .map(|ix| (keys[usize::from(ix.program_id_index)], ix.data.clone()))
            .collect();
        SentTransaction {
            version: 1,
            size: wire.len(),
            programs: keys,
            instructions,
            priority_fee: message.config.priority_fee,
        }
    } else {
        use solana_client::rpc_config::{RpcTransactionConfig, UiTransactionEncoding};
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
            .unwrap()
            .transaction
            .transaction
            .decode()
            .unwrap();
        let keys = tx.message.static_account_keys().to_vec();
        let instructions = tx
            .message
            .instructions()
            .iter()
            .map(|ix| (keys[usize::from(ix.program_id_index)], ix.data.clone()))
            .collect();
        SentTransaction {
            version: 0,
            size: wire.len(),
            programs: keys,
            instructions,
            priority_fee: None,
        }
    }
}
