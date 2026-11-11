// SPDX-License-Identifier: BUSL-1.1
//! [`ConfidentialClient`]: configure, deposit, apply, read, transfer and withdraw, for accounts
//! owned by a wallet; and the same steps prepared for accounts owned by a program.
use std::sync::Arc;

use solana_client::{
    client_error::ClientError,
    nonblocking::rpc_client::RpcClient,
    rpc_config::{
        RpcAccountInfoConfig, RpcProgramAccountsConfig, UiAccountEncoding, UiDataSliceConfig,
    },
    rpc_filter::{Memcmp, RpcFilterType},
};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Signature,
    signer::Signer,
};
use solana_zk_elgamal_proof_interface::instruction::ProofInstruction;
use solana_zk_sdk::{
    encryption::elgamal::{ElGamalCiphertext, ElGamalPubkey},
    zk_elgamal_proof_program::{
        build_pubkey_validity_proof_data, build_zero_ciphertext_proof_data,
    },
};
use solana_zk_sdk_pod::encryption::{
    auth_encryption::PodAeCiphertext, elgamal::PodElGamalCiphertext,
};
use spl_associated_token_account_interface::{
    address::get_associated_token_address_with_program_id,
    instruction::create_associated_token_account_idempotent,
};
use spl_token_2022_interface::{
    extension::{
        confidential_transfer::{
            instruction as ct_instruction, ConfidentialTransferAccount,
            DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER, MAXIMUM_DEPOSIT_TRANSFER_AMOUNT,
            PENDING_BALANCE_LO_BIT_LENGTH,
        },
        ExtensionType,
    },
    instruction::{close_account as close_token_account, reallocate},
    state::AccountState,
};
use spl_token_client::zk_proofs::confidential_transfer::{
    TransferAccountInfo, WithdrawAccountInfo,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::{
    transfer::TransferProofData, withdraw::WithdrawProofData,
};

use crate::accounts::{
    assert_can_receive, assert_can_send, assert_keys_match, available_balance,
    read_configured_account, read_mint, read_token_account, MintInfo,
};
use crate::error::{redact_urls, without_url, Error, ErrorCode, ProofAccounts, Result};
use crate::keys::ConfidentialKeys;
use crate::proofs::{close_instructions, close_proof_accounts, ProofSetup};
use crate::send::{Sender, POLL, SETTLE_TIMEOUT};

/// The Token-2022 program.
pub const TOKEN_2022_PROGRAM_ID: Pubkey = spl_token_2022_interface::ID;

/// Confidential transfers of Token-2022 tokens.
///
/// Holds an RPC client and the payer, who pays every fee and the temporary rent of the proof
/// accounts (it gets the rent back). Owners sign their own operations.
///
/// The client is `Send` and `Sync`, and so are the futures of its methods: signers are taken as
/// `Signer + Sync` (a `Keypair` is), so that a call can run on a multi-threaded runtime or be
/// spawned.
///
/// ```no_run
/// # use std::sync::Arc;
/// # use arcantis::solana_client::{nonblocking::rpc_client::RpcClient, rpc_config::CommitmentConfig};
/// # use arcantis::solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};
/// # use arcantis::ConfidentialClient;
/// # async fn run(payer: Keypair, alice: Keypair, bob: Pubkey, mint: Pubkey) -> arcantis::Result<()> {
/// let rpc = Arc::new(RpcClient::new_with_commitment("https://api.devnet.solana.com".into(), CommitmentConfig::confirmed()));
/// let client = ConfidentialClient::new(rpc, Arc::new(payer)).with_compute_unit_price(10_000);
///
/// client.configure_account(&alice, &mint).await?;
/// client.deposit(&alice, &mint, 1_000).await?;
/// client.apply_pending_balance(&alice, &mint).await?;
/// let sent = client.transfer(&alice, &mint, &bob, 400).await?;
/// client.withdraw(&alice, &mint, 100).await?;
/// assert_eq!(client.decrypt_balance(&alice, &mint).await?, 500);
/// # Ok(()) }
/// ```
pub struct ConfidentialClient {
    rpc: Arc<RpcClient>,
    payer: Arc<dyn Signer + Send + Sync>,
    compute_unit_price: Option<u64>,
    max_retries: u32,
    single_transaction: bool,
    apply_pending: bool,
    checked_apply: bool,
}

/// The result of [`ConfidentialClient::configure_account`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConfigureAccountResult {
    pub token_account: Pubkey,
    pub signature: Signature,
}

/// The result of [`ConfidentialClient::transfer`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TransferResult {
    pub source_token_account: Pubkey,
    pub destination_token_account: Pubkey,
    /// Every transaction, in order: just the transfer when it went in one transaction; otherwise
    /// the proofs, the transfer, and any separate cleanup.
    pub signatures: Vec<Signature>,
    /// The transaction with the Token-2022 transfer.
    pub transfer_signature: Signature,
    /// Proof accounts that may still be open although the transfer went through, because closing
    /// them in a separate transaction failed or its outcome is unknown. Always empty when the
    /// transfer went in one transaction, and normally empty otherwise: the
    /// transfer closes them in its own transaction when they fit, and otherwise a separate
    /// transaction does. [`ConfidentialClient::recover_proof_accounts`] closes them.
    pub proof_accounts_left_open: Vec<Pubkey>,
}

/// The result of [`ConfidentialClient::withdraw`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WithdrawResult {
    pub token_account: Pubkey,
    pub signatures: Vec<Signature>,
    pub withdraw_signature: Signature,
    /// As [`TransferResult::proof_accounts_left_open`].
    pub proof_accounts_left_open: Vec<Pubkey>,
}

/// The result of [`ConfidentialClient::recover_proof_accounts`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct RecoverProofAccountsResult {
    pub closed: Vec<Pubkey>,
    /// Found but not seen closed: the closing transaction failed, or its outcome is unknown.
    /// Run again.
    pub left_open: Vec<Pubkey>,
    /// Rent returned to the payer.
    pub lamports: u64,
}

/// A confidential transfer whose proofs are verified into proof accounts and ready to be used by
/// a Token-2022 transfer instruction, sent directly ([`Self::instruction`]) or through a program
/// that owns the source account. Close the proof accounts afterwards with
/// [`ConfidentialClient::close_proof_accounts`].
#[derive(Clone, Debug)]
pub struct PreparedTransfer {
    pub mint: Pubkey,
    pub source_token_account: Pubkey,
    pub destination_token_account: Pubkey,
    pub equality_proof: Pubkey,
    pub ciphertext_validity_proof: Pubkey,
    pub range_proof: Pubkey,
    /// The source's available balance after the transfer, encrypted with its AES key.
    pub new_decryptable_available_balance: [u8; 36],
    /// The amount's low 16 bits as the transfer instruction carries them for the mint's
    /// auditor: a Pedersen commitment (32 bytes) and the auditor's decryption handle (32 bytes).
    /// When the mint has no auditor the handle is zero, but the commitment is not.
    pub auditor_ciphertext_lo: [u8; 64],
    /// The same for the amount's high 32 bits.
    pub auditor_ciphertext_hi: [u8; 64],
    /// The transactions that created the proof accounts.
    pub signatures: Vec<Signature>,
}

impl PreparedTransfer {
    pub fn proof_accounts(&self) -> Vec<Pubkey> {
        vec![
            self.equality_proof,
            self.ciphertext_validity_proof,
            self.range_proof,
        ]
    }

    /// The Token-2022 transfer instruction, signed by `authority` (the source account's owner).
    /// It has no transfer-hook accounts; add them with [`ConfidentialClient::transfer_hook_accounts`].
    pub fn instruction(&self, authority: &Pubkey) -> Result<Instruction> {
        let instructions = ct_instruction::transfer(
            &TOKEN_2022_PROGRAM_ID,
            &self.source_token_account,
            &self.mint,
            &self.destination_token_account,
            &PodAeCiphertext(self.new_decryptable_available_balance),
            &PodElGamalCiphertext(self.auditor_ciphertext_lo),
            &PodElGamalCiphertext(self.auditor_ciphertext_hi),
            authority,
            &[],
            ProofLocation::ContextStateAccount(&self.equality_proof),
            ProofLocation::ContextStateAccount(&self.ciphertext_validity_proof),
            ProofLocation::ContextStateAccount(&self.range_proof),
        )
        .map_err(|e| {
            Error::new(
                ErrorCode::InvalidInput,
                "transfer",
                format!("cannot build the transfer instruction: {e}"),
            )
        })?;
        Ok(instructions
            .into_iter()
            .next()
            .expect("one instruction with proof accounts"))
    }
}

/// A withdraw whose proofs are verified into proof accounts. See [`PreparedTransfer`].
#[derive(Clone, Debug)]
pub struct PreparedWithdraw {
    pub mint: Pubkey,
    pub token_account: Pubkey,
    pub amount: u64,
    pub decimals: u8,
    pub equality_proof: Pubkey,
    pub range_proof: Pubkey,
    pub new_decryptable_available_balance: [u8; 36],
    pub signatures: Vec<Signature>,
}

impl PreparedWithdraw {
    pub fn proof_accounts(&self) -> Vec<Pubkey> {
        vec![self.equality_proof, self.range_proof]
    }

    /// The Token-2022 withdraw instruction, signed by `authority` (the account's owner).
    pub fn instruction(&self, authority: &Pubkey) -> Result<Instruction> {
        let instructions = ct_instruction::withdraw(
            &TOKEN_2022_PROGRAM_ID,
            &self.token_account,
            &self.mint,
            self.amount,
            self.decimals,
            &PodAeCiphertext(self.new_decryptable_available_balance),
            authority,
            &[],
            ProofLocation::ContextStateAccount(&self.equality_proof),
            ProofLocation::ContextStateAccount(&self.range_proof),
        )
        .map_err(|e| {
            Error::new(
                ErrorCode::InvalidInput,
                "withdraw",
                format!("cannot build the withdraw instruction: {e}"),
            )
        })?;
        Ok(instructions
            .into_iter()
            .next()
            .expect("one instruction with proof accounts"))
    }
}

/// What a program-owned account needs to be configured: the ElGamal public key, verified into a
/// proof account, and the AES encryption of a zero balance.
#[derive(Clone, Debug)]
pub struct PreparedConfigure {
    pub pubkey_validity_proof: Pubkey,
    pub elgamal_pubkey: [u8; 32],
    pub decryptable_zero_balance: [u8; 36],
    pub signatures: Vec<Signature>,
}

/// What `ApplyPendingBalance` needs, computed with the owner's keys.
#[derive(Clone, Copy, Debug)]
pub struct PendingBalanceUpdate {
    pub expected_pending_balance_credit_counter: u64,
    pub new_decryptable_available_balance: [u8; 36],
}

/// A transfer's proofs, generated and not yet sent anywhere.
struct TransferProofs {
    data: TransferProofData,
    new_decryptable_available_balance: [u8; 36],
    /// Apply the pending balance first, in the same transaction (one-transaction transfers only).
    apply: Option<PendingBalanceUpdate>,
}

impl TransferProofs {
    /// The transfer with its three proofs inside the same transaction: the Token-2022 transfer
    /// first (after the apply, if any), then the proof verifications it reads at offsets 1, 2 and
    /// 3. Add the transfer hook's accounts to the instruction at [`Self::action_index`].
    fn inline_instructions(
        &self,
        mint: &Pubkey,
        source: &Pubkey,
        destination: &Pubkey,
        authority: &Pubkey,
    ) -> Result<Vec<Instruction>> {
        let validity = &self.data.ciphertext_validity_proof_data_with_ciphertext;
        let mut instructions =
            apply_instructions(self.apply.as_ref(), source, authority, "transfer")?;
        instructions.extend(
            ct_instruction::transfer(
                &TOKEN_2022_PROGRAM_ID,
                source,
                mint,
                destination,
                &PodAeCiphertext(self.new_decryptable_available_balance),
                &validity.ciphertext_lo,
                &validity.ciphertext_hi,
                authority,
                &[],
                ProofLocation::InstructionOffset(offset(1), &self.data.equality_proof_data),
                ProofLocation::InstructionOffset(offset(2), &validity.proof_data),
                ProofLocation::InstructionOffset(offset(3), &self.data.range_proof_data),
            )
            .map_err(|e| build_error("transfer", e))?,
        );
        Ok(instructions)
    }

    /// Where the transfer instruction is among [`Self::inline_instructions`].
    fn action_index(&self) -> usize {
        usize::from(self.apply.is_some())
    }
}

/// A withdraw's proofs, generated and not yet sent anywhere.
struct WithdrawProofs {
    data: WithdrawProofData,
    amount: u64,
    decimals: u8,
    new_decryptable_available_balance: [u8; 36],
    /// As for a transfer: apply the pending balance first, in the same transaction.
    apply: Option<PendingBalanceUpdate>,
}

impl WithdrawProofs {
    /// The withdraw with its two proofs inside the same transaction, at offsets 1 and 2 (after
    /// the apply, if any).
    fn inline_instructions(
        &self,
        mint: &Pubkey,
        token: &Pubkey,
        authority: &Pubkey,
    ) -> Result<Vec<Instruction>> {
        let mut instructions =
            apply_instructions(self.apply.as_ref(), token, authority, "withdraw")?;
        instructions.extend(
            ct_instruction::withdraw(
                &TOKEN_2022_PROGRAM_ID,
                token,
                mint,
                self.amount,
                self.decimals,
                &PodAeCiphertext(self.new_decryptable_available_balance),
                authority,
                &[],
                ProofLocation::InstructionOffset(offset(1), &self.data.equality_proof_data),
                ProofLocation::InstructionOffset(offset(2), &self.data.range_proof_data),
            )
            .map_err(|e| build_error("withdraw", e))?,
        );
        Ok(instructions)
    }
}

/// The ApplyPendingBalance that goes first in a transaction, or nothing.
fn apply_instructions(
    apply: Option<&PendingBalanceUpdate>,
    token: &Pubkey,
    authority: &Pubkey,
    operation: &'static str,
) -> Result<Vec<Instruction>> {
    let Some(update) = apply else {
        return Ok(Vec::new());
    };
    Ok(vec![ct_instruction::apply_pending_balance(
        &TOKEN_2022_PROGRAM_ID,
        token,
        update.expected_pending_balance_credit_counter,
        &PodAeCiphertext(update.new_decryptable_available_balance),
        authority,
        &[],
    )
    .map_err(|e| build_error(operation, e))?])
}

fn offset(n: i8) -> std::num::NonZeroI8 {
    std::num::NonZeroI8::new(n).expect("a proof offset is not zero")
}

impl ConfidentialClient {
    /// A client over `rpc`, with `payer` paying fees and proof-account rent. Use an RPC client
    /// with `confirmed` commitment unless you have a reason not to.
    pub fn new(rpc: Arc<RpcClient>, payer: Arc<dyn Signer + Send + Sync>) -> Self {
        Self {
            rpc,
            payer,
            compute_unit_price: None,
            max_retries: 0,
            single_transaction: true,
            apply_pending: true,
            checked_apply: true,
        }
    }

    /// Priority fee in micro-lamports per compute unit, added to every transaction that has
    /// room for it (the range-proof transactions do not).
    pub fn with_compute_unit_price(mut self, micro_lamports: u64) -> Self {
        self.compute_unit_price = Some(micro_lamports);
        self
    }

    /// How many times to send a transaction again when its blockhash expired before it was
    /// confirmed. Default 0.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Whether [`Self::transfer`] and [`Self::withdraw`] send their proofs inside the transfer's
    /// or withdraw's own transaction, a v1 transaction of up to 4,096 bytes (default `true`).
    /// With `false` they verify the proofs into proof accounts first, in separate transactions,
    /// for an RPC that does not take v1 transactions. Either way they fall back to proof accounts
    /// by themselves when one transaction would be too large (a transfer hook with many
    /// accounts).
    pub fn with_single_transaction(mut self, single_transaction: bool) -> Self {
        self.single_transaction = single_transaction;
        self
    }

    /// Whether a one-transaction [`Self::transfer`] or [`Self::withdraw`] also spends what is
    /// pending (default `true`): it applies the pending balance first, in the same transaction,
    /// and builds its proofs from the balance after it, so a recipient of earlier payments never
    /// has to call [`Self::apply_pending_balance`]. If another credit lands while the transaction
    /// is on its way, Token-2022 refuses the whole transaction and the call builds it again (up
    /// to three times). With proof accounts only the available balance is spent.
    pub fn with_apply_pending(mut self, apply_pending: bool) -> Self {
        self.apply_pending = apply_pending;
        self
    }

    /// Whether [`Self::apply_pending_balance`] checks its apply with a withdraw of zero in the same
    /// v1 transaction (default `true`), so that a credit landing meanwhile cannot leave the
    /// account's two copies of its balance apart: Token-2022 then refuses both and the call reads
    /// the account again. It costs about 130,000 compute units more. Ignored without
    /// [`Self::with_single_transaction`], and for a frozen account or a paused mint, which receive
    /// nothing.
    pub fn with_checked_apply(mut self, checked_apply: bool) -> Self {
        self.checked_apply = checked_apply;
        self
    }

    pub fn rpc(&self) -> &Arc<RpcClient> {
        &self.rpc
    }

    pub fn payer(&self) -> Pubkey {
        self.payer.pubkey()
    }

    /// The owner's associated token account for `mint`: the account every operation uses.
    pub fn token_account(&self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        get_associated_token_address_with_program_id(owner, mint, &TOKEN_2022_PROGRAM_ID)
    }

    fn sender(&self, operation: &'static str) -> Sender<'_> {
        Sender {
            rpc: &self.rpc,
            payer: self.payer.as_ref(),
            compute_unit_price: self.compute_unit_price,
            max_retries: self.max_retries,
            operation,
            poll: POLL,
            settle_timeout: SETTLE_TIMEOUT,
        }
    }

    /// Create the owner's token account if needed and configure it for confidential transfers,
    /// with the owner's standard keys. One transaction.
    pub async fn configure_account(
        &self,
        owner: &(dyn Signer + Sync),
        mint: &Pubkey,
    ) -> Result<ConfigureAccountResult> {
        let operation = "configure_account";
        read_mint(&self.rpc, &TOKEN_2022_PROGRAM_ID, mint, operation).await?;
        let owner_key = owner.pubkey();
        let token = self.token_account(&owner_key, mint);
        let existing = read_token_account(&self.rpc, &token, mint, operation).await?;
        if existing
            .as_ref()
            .is_some_and(|a| a.confidential().is_some())
        {
            return Err(Error::new(
                ErrorCode::AccountAlreadyConfigured,
                operation,
                format!("token account {token} is already configured for confidential transfers"),
            ));
        }
        let keys = ConfidentialKeys::derive(owner).map_err(|e| e.within(operation))?;

        let mut instructions = Vec::new();
        if existing.is_none() {
            instructions.push(create_associated_token_account_idempotent(
                &self.payer(),
                &owner_key,
                mint,
                &TOKEN_2022_PROGRAM_ID,
            ));
        }
        instructions.push(
            reallocate(
                &TOKEN_2022_PROGRAM_ID,
                &token,
                &self.payer(),
                &owner_key,
                &[],
                &[ExtensionType::ConfidentialTransferAccount],
            )
            .map_err(|e| build_error(operation, e))?,
        );
        let proof = build_pubkey_validity_proof_data(&keys.elgamal).map_err(|e| {
            Error::new(
                ErrorCode::InvalidInput,
                operation,
                format!("cannot prove the ElGamal key: {e}"),
            )
        })?;
        instructions.extend(
            ct_instruction::configure_account(
                &TOKEN_2022_PROGRAM_ID,
                &token,
                mint,
                &keys.ae.encrypt(0).into(),
                DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER,
                &owner_key,
                &[],
                ProofLocation::InstructionOffset(1.try_into().expect("non-zero"), &proof),
            )
            .map_err(|e| build_error(operation, e))?,
        );
        let signature = self
            .sender(operation)
            .send(&instructions, &[owner], operation)
            .await?;
        Ok(ConfigureAccountResult {
            token_account: token,
            signature,
        })
    }

    /// Move `amount` of the owner's public balance into the confidential pending balance.
    pub async fn deposit(
        &self,
        owner: &(dyn Signer + Sync),
        mint: &Pubkey,
        amount: u64,
    ) -> Result<Signature> {
        let operation = "deposit";
        check_amount(amount, operation, true)?;
        let mint_info = read_mint(&self.rpc, &TOKEN_2022_PROGRAM_ID, mint, operation).await?;
        mint_info.assert_not_paused(mint, operation)?;
        let decimals = mint_info.decimals;
        let owner_key = owner.pubkey();
        let token = self.token_account(&owner_key, mint);
        let (account, ct) =
            read_configured_account(&self.rpc, &token, mint, operation, "your").await?;
        assert_can_receive(&ct, &token, operation, "your")?;
        if account.state.base.amount < amount {
            return Err(Error::new(
                ErrorCode::InsufficientFunds,
                operation,
                format!(
                    "the public balance of {token} is {}, less than {amount}",
                    account.state.base.amount
                ),
            ));
        }
        let instruction = ct_instruction::deposit(
            &TOKEN_2022_PROGRAM_ID,
            &token,
            mint,
            amount,
            decimals,
            &owner_key,
            &[],
        )
        .map_err(|e| build_error(operation, e))?;
        self.sender(operation)
            .send(&[instruction], &[owner], operation)
            .await
    }

    /// Move the owner's pending balance (incoming deposits and transfers) into the available
    /// balance.
    ///
    /// By default the apply is checked ([`Self::with_checked_apply`]): a withdraw of zero follows
    /// it in the same v1 transaction, with a proof about the exact balance the apply should leave,
    /// so a deposit or transfer landing meanwhile makes Token-2022 refuse both instead of leaving
    /// the account's two copies of its balance apart; the call then reads the account again (up to
    /// three times). [`Self::transfer`] and [`Self::withdraw`] apply what is pending by themselves,
    /// so most applications never need this.
    pub async fn apply_pending_balance(
        &self,
        owner: &(dyn Signer + Sync),
        mint: &Pubkey,
    ) -> Result<Signature> {
        let operation = "apply_pending_balance";
        let owner_key = owner.pubkey();
        let token = self.token_account(&owner_key, mint);
        let keys = ConfidentialKeys::derive(owner).map_err(|e| e.within(operation))?;
        let checked = self.single_transaction && self.checked_apply;
        let mint_info = if checked {
            Some(read_mint(&self.rpc, &TOKEN_2022_PROGRAM_ID, mint, operation).await?)
        } else {
            None
        };
        let mut attempt = 1;
        loop {
            let (account, ct) =
                read_configured_account(&self.rpc, &token, mint, operation, "your").await?;
            assert_keys_match(&keys, &ct, &token, operation)?;
            let applied = applied_balance(&ct, &keys, &token, operation)?;
            let frozen = account.state.base.state == AccountState::Frozen;
            if let Some(mint_info) = mint_info.as_ref().filter(|m| !m.paused && !frozen) {
                let info = WithdrawAccountInfo {
                    available_balance: applied.available_balance,
                    decryptable_available_balance: PodAeCiphertext::from(
                        keys.ae.encrypt(applied.value),
                    ),
                };
                let data = info
                    .generate_proof_data(0, &keys.elgamal, &keys.ae)
                    .map_err(|e| proof_error(operation, e))?;
                let new_balance = info
                    .new_decryptable_available_balance(0, &keys.ae)
                    .map_err(|e| proof_error(operation, e))?;
                let proofs = WithdrawProofs {
                    data,
                    amount: 0,
                    decimals: mint_info.decimals,
                    new_decryptable_available_balance: PodAeCiphertext::from(new_balance).0,
                    apply: Some(applied.update),
                };
                let instructions = proofs
                    .inline_instructions(mint, &token, &owner_key)
                    .map_err(|e| e.within(operation))?;
                match self
                    .sender(operation)
                    .send_single(&instructions, &[owner], operation)
                    .await
                {
                    Ok(Some(signature)) => return Ok(signature),
                    Ok(None) => {}
                    Err(e) if attempt < PENDING_CHANGED_ATTEMPTS && balance_changed(&e) => {
                        attempt += 1;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            let instructions =
                apply_instructions(Some(&applied.update), &token, &owner_key, operation)?;
            return self
                .sender(operation)
                .send(&instructions, &[owner], operation)
                .await;
        }
    }

    /// The owner's available confidential balance plus what is pending: what [`Self::transfer`]
    /// and [`Self::withdraw`] can spend. Reads only; signs only the key derivation.
    pub async fn decrypt_balance_with_pending(
        &self,
        owner: &(dyn Signer + Sync),
        mint: &Pubkey,
    ) -> Result<u64> {
        let operation = "decrypt_balance";
        let keys = ConfidentialKeys::derive(owner).map_err(|e| e.within(operation))?;
        let token = self.token_account(&owner.pubkey(), mint);
        let (_, ct) = read_configured_account(&self.rpc, &token, mint, operation, "your").await?;
        assert_keys_match(&keys, &ct, &token, operation)?;
        balance_after_apply(&ct, &keys, &token, operation)
    }

    /// The owner's available confidential balance. Reads only; signs only the key derivation.
    pub async fn decrypt_balance(&self, owner: &(dyn Signer + Sync), mint: &Pubkey) -> Result<u64> {
        let operation = "decrypt_balance";
        let keys = ConfidentialKeys::derive(owner).map_err(|e| e.within(operation))?;
        self.decrypt_balance_of(mint, &self.token_account(&owner.pubkey(), mint), &keys)
            .await
    }

    /// The available confidential balance of any token account, with its keys.
    pub async fn decrypt_balance_of(
        &self,
        mint: &Pubkey,
        token_account: &Pubkey,
        keys: &ConfidentialKeys,
    ) -> Result<u64> {
        let operation = "decrypt_balance";
        let (_, ct) =
            read_configured_account(&self.rpc, token_account, mint, operation, "the").await?;
        assert_keys_match(keys, &ct, token_account, operation)?;
        available_balance(&ct, keys, token_account, operation)
    }

    /// Confidentially transfer `amount` from the owner's account to `destination_owner`'s.
    ///
    /// By default the transfer goes in one v1 transaction (up to 4,096 bytes) with its three
    /// proofs inside: one signature from the owner, one from the payer when it is someone else,
    /// no proof accounts and nothing to clean up if it fails. The compute budget is set from a
    /// simulation. When that one transaction would be too large (a transfer hook with many
    /// accounts), or [`Self::with_single_transaction`] turned it off, the proofs are verified into
    /// proof accounts first (four transactions), then the transfer closes them in its own
    /// transaction; if a step fails, the proof accounts created so far are closed and the error
    /// says which ([`Error::proof_accounts`]).
    ///
    /// The amount is also encrypted to the mint's auditor, when it has one, and a mint's transfer
    /// hook gets the accounts it asks for, unless it asks for a signer of the transfer
    /// ([`Self::transfer_hook_accounts`]). Every check, the hook's accounts included, comes before
    /// anything is sent.
    pub async fn transfer(
        &self,
        owner: &(dyn Signer + Sync),
        mint: &Pubkey,
        destination_owner: &Pubkey,
        amount: u64,
    ) -> Result<TransferResult> {
        self.transfer_inner(owner, mint, destination_owner, amount, None)
            .await
    }

    /// [`Self::transfer`] to a recipient whose ElGamal key the application already knows (from
    /// its own records of the recipient, not from this RPC). If the RPC reports another key for
    /// the recipient's account, the transfer is refused ([`ErrorCode::RecipientKeyMismatch`])
    /// before anything is encrypted or signed: an RPC that substituted its own key would
    /// otherwise receive the amount encrypted to that key.
    pub async fn transfer_to_known_key(
        &self,
        owner: &(dyn Signer + Sync),
        mint: &Pubkey,
        destination_owner: &Pubkey,
        amount: u64,
        destination_elgamal_pubkey: &[u8; 32],
    ) -> Result<TransferResult> {
        self.transfer_inner(
            owner,
            mint,
            destination_owner,
            amount,
            Some(destination_elgamal_pubkey),
        )
        .await
    }

    async fn transfer_inner(
        &self,
        owner: &(dyn Signer + Sync),
        mint: &Pubkey,
        destination_owner: &Pubkey,
        amount: u64,
        pinned_destination_key: Option<&[u8; 32]>,
    ) -> Result<TransferResult> {
        let operation = "transfer";
        check_amount(amount, operation, true)?;
        let mint_info = read_mint(&self.rpc, &TOKEN_2022_PROGRAM_ID, mint, operation).await?;
        let owner_key = owner.pubkey();
        let source = self.token_account(&owner_key, mint);
        let destination = self.token_account(destination_owner, mint);
        let keys = ConfidentialKeys::derive(owner).map_err(|e| e.within(operation))?;

        if self.single_transaction {
            for attempt in 1..=PENDING_CHANGED_ATTEMPTS {
                // The transfer hook's accounts are resolved and checked before the proofs are made.
                let (proofs, hook_accounts) = self
                    .transfer_proofs(
                        operation,
                        mint,
                        &mint_info,
                        &source,
                        &keys,
                        &destination,
                        amount,
                        Some(&owner_key),
                        TransferProofOptions {
                            apply_pending: self.apply_pending,
                            pinned_destination_key,
                        },
                    )
                    .await?;
                let mut instructions = proofs
                    .inline_instructions(mint, &source, &destination, &owner_key)
                    .map_err(|e| e.within(operation))?;
                instructions[proofs.action_index()]
                    .accounts
                    .extend(hook_accounts.iter().cloned());
                match self
                    .sender(operation)
                    .send_single(&instructions, &[owner], operation)
                    .await
                {
                    Ok(Some(signature)) => {
                        return Ok(TransferResult {
                            source_token_account: source,
                            destination_token_account: destination,
                            signatures: vec![signature],
                            transfer_signature: signature,
                            proof_accounts_left_open: Vec::new(),
                        })
                    }
                    // Too large for one transaction: proof accounts below.
                    Ok(None) => break,
                    // A credit landed during the apply: nothing changed, build it again.
                    Err(e) if attempt < PENDING_CHANGED_ATTEMPTS && balance_changed(&e) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        // With proof accounts the proofs are verified in earlier transactions, so the transfer
        // spends the available balance only.
        let (proofs, hook_accounts) = self
            .transfer_proofs(
                operation,
                mint,
                &mint_info,
                &source,
                &keys,
                &destination,
                amount,
                Some(&owner_key),
                TransferProofOptions {
                    apply_pending: false,
                    pinned_destination_key,
                },
            )
            .await?;
        let prepared = self
            .transfer_proof_accounts(operation, mint, &source, &destination, proofs)
            .await?;
        let mut instruction = prepared
            .instruction(&owner_key)
            .map_err(|e| e.within(operation))?;
        instruction.accounts.extend(hook_accounts);
        let (transfer_signature, signatures, proof_accounts_left_open) = self
            .run_with_proofs(
                operation,
                instruction,
                owner,
                &prepared.proof_accounts(),
                prepared.signatures.clone(),
            )
            .await?;
        Ok(TransferResult {
            source_token_account: source,
            destination_token_account: destination,
            signatures,
            transfer_signature,
            proof_accounts_left_open,
        })
    }

    /// Move `amount` of the owner's available confidential balance back to the public balance.
    /// One v1 transaction with its two proofs inside, as in [`Self::transfer`]; otherwise two
    /// proof transactions and a third that withdraws, with the cleanup of [`Self::transfer`].
    pub async fn withdraw(
        &self,
        owner: &(dyn Signer + Sync),
        mint: &Pubkey,
        amount: u64,
    ) -> Result<WithdrawResult> {
        let operation = "withdraw";
        check_amount(amount, operation, false)?;
        let mint_info = read_mint(&self.rpc, &TOKEN_2022_PROGRAM_ID, mint, operation).await?;
        let owner_key = owner.pubkey();
        let token = self.token_account(&owner_key, mint);
        let keys = ConfidentialKeys::derive(owner).map_err(|e| e.within(operation))?;

        if self.single_transaction {
            for attempt in 1..=PENDING_CHANGED_ATTEMPTS {
                let proofs = self
                    .withdraw_proofs(
                        operation,
                        &mint_info,
                        mint,
                        &token,
                        &keys,
                        amount,
                        self.apply_pending,
                    )
                    .await?;
                let instructions = proofs
                    .inline_instructions(mint, &token, &owner_key)
                    .map_err(|e| e.within(operation))?;
                match self
                    .sender(operation)
                    .send_single(&instructions, &[owner], operation)
                    .await
                {
                    Ok(Some(signature)) => {
                        return Ok(WithdrawResult {
                            token_account: token,
                            signatures: vec![signature],
                            withdraw_signature: signature,
                            proof_accounts_left_open: Vec::new(),
                        })
                    }
                    Ok(None) => break,
                    Err(e) if attempt < PENDING_CHANGED_ATTEMPTS && balance_changed(&e) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        let proofs = self
            .withdraw_proofs(operation, &mint_info, mint, &token, &keys, amount, false)
            .await?;
        let prepared = self
            .withdraw_proof_accounts(operation, mint, &token, proofs)
            .await?;
        let instruction = prepared
            .instruction(&owner_key)
            .map_err(|e| e.within(operation))?;
        let (withdraw_signature, signatures, proof_accounts_left_open) = self
            .run_with_proofs(
                operation,
                instruction,
                owner,
                &prepared.proof_accounts(),
                prepared.signatures.clone(),
            )
            .await?;
        Ok(WithdrawResult {
            token_account: token,
            signatures,
            withdraw_signature,
            proof_accounts_left_open,
        })
    }

    /// Close every proof account whose authority is the payer, returning its rent: those of a
    /// transfer or withdraw whose process stopped partway, and those an error or a result
    /// reported as left open ([`ProofAccounts::left_open`], [`ProofAccounts::unknown`],
    /// [`TransferResult::proof_accounts_left_open`]).
    ///
    /// It finds them by their authority, which a proof account only has once its proof is
    /// verified into it. So it does not find a range-proof account whose verification never
    /// landed ([`ProofAccounts::unverified`]): that one has no authority and cannot be closed.
    ///
    /// Do not run it while a transfer or withdraw paid by the same payer is in progress: it would
    /// close that transfer's proof accounts too, and the transfer would fail.
    pub async fn recover_proof_accounts(&self) -> Result<RecoverProofAccountsResult> {
        let operation = "recover_proof_accounts";
        let sender = self.sender(operation);
        let found = self
            .rpc
            .get_program_ui_accounts_with_config(
                &solana_zk_elgamal_proof_interface::id(),
                RpcProgramAccountsConfig {
                    // A proof account starts with its authority's public key, written when the
                    // proof is verified into it (all zero before).
                    filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_base58_encoded(
                        0,
                        self.payer().as_ref(),
                    ))]),
                    account_config: RpcAccountInfoConfig {
                        commitment: Some(self.rpc.commitment()),
                        // Only the addresses and lamports are needed.
                        encoding: Some(UiAccountEncoding::Base64),
                        data_slice: Some(UiDataSliceConfig {
                            offset: 0,
                            length: 0,
                        }),
                        ..RpcAccountInfoConfig::default()
                    },
                    ..RpcProgramAccountsConfig::default()
                },
            )
            .await
            .map_err(|e| sender.rpc_error(e))?;
        let addresses: Vec<Pubkey> = found.iter().map(|(address, _)| *address).collect();
        let (outcome, _) = close_proof_accounts(&sender, &addresses).await;
        let lamports = found
            .iter()
            .filter(|(address, _)| outcome.closed.contains(address))
            .map(|(_, account)| account.lamports)
            .sum();
        let mut left_open = outcome.left_open;
        left_open.extend(outcome.unknown);
        Ok(RecoverProofAccountsResult {
            closed: outcome.closed,
            left_open,
            lamports,
        })
    }

    /// Close the owner's empty confidential token account and send its rent deposit to
    /// `destination` (the owner when `None`).
    ///
    /// The account must be empty: no public balance and nothing available or pending in its
    /// confidential balance; move everything out first with [`Self::transfer`] or
    /// [`Self::withdraw`] and an ordinary token transfer. A frozen account cannot be closed. One
    /// transaction: the apply when something is pending (it must add up to zero), `EmptyAccount`
    /// with a zero-ciphertext proof of the available balance after it, and `CloseAccount`.
    pub async fn close_account(
        &self,
        owner: &(dyn Signer + Sync),
        mint: &Pubkey,
        destination: Option<&Pubkey>,
    ) -> Result<Signature> {
        let operation = "close_account";
        let owner_key = owner.pubkey();
        let token = self.token_account(&owner_key, mint);
        let keys = ConfidentialKeys::derive(owner).map_err(|e| e.within(operation))?;
        let refuse = |what: String| Error::new(ErrorCode::InvalidInput, operation, what);
        let mut attempt = 1;
        loop {
            let (account, ct) =
                read_configured_account(&self.rpc, &token, mint, operation, "your").await?;
            if account.state.base.state == AccountState::Frozen {
                return Err(refuse(format!(
                    "your token account {token} is frozen; Token-2022 does not close it until the \
                     mint's freeze authority thaws it"
                )));
            }
            if account.state.base.amount > 0 {
                return Err(refuse(format!(
                    "your token account {token} still has a public balance; transfer it out \
                     before closing the account"
                )));
            }
            assert_keys_match(&keys, &ct, &token, operation)?;
            // What the available balance holds once anything pending is applied: it must be zero.
            let applied = applied_balance(&ct, &keys, &token, operation)?;
            if applied.value != 0 {
                return Err(refuse(format!(
                    "your token account {token} still has a confidential balance (available or \
                     pending); transfer or withdraw it before closing the account"
                )));
            }
            let pending = u64::from(ct.pending_balance_credit_counter) > 0;
            let balance = ElGamalCiphertext::try_from(if pending {
                applied.available_balance
            } else {
                ct.available_balance
            })
            .map_err(|_| {
                Error::new(
                    ErrorCode::DecryptionFailed,
                    operation,
                    format!("cannot parse the available balance of {token}"),
                )
            })?;
            let proof = build_zero_ciphertext_proof_data(&keys.elgamal, &balance)
                .map_err(|e| proof_error(operation, e))?;
            let mut instructions = apply_instructions(
                pending.then_some(&applied.update),
                &token,
                &owner_key,
                operation,
            )?;
            instructions.extend(
                ct_instruction::empty_account(
                    &TOKEN_2022_PROGRAM_ID,
                    &token,
                    &owner_key,
                    &[],
                    ProofLocation::InstructionOffset(1.try_into().expect("non-zero"), &proof),
                )
                .map_err(|e| build_error(operation, e))?,
            );
            instructions.push(
                close_token_account(
                    &TOKEN_2022_PROGRAM_ID,
                    &token,
                    destination.unwrap_or(&owner_key),
                    &owner_key,
                    &[],
                )
                .map_err(|e| build_error(operation, e))?,
            );
            match self
                .sender(operation)
                .send(&instructions, &[owner], operation)
                .await
            {
                Err(e) if pending && attempt < PENDING_CHANGED_ATTEMPTS && balance_changed(&e) => {
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Accounts owned by a program: the client prepares, the program signs through CPI.
    // ---------------------------------------------------------------------------------------

    /// Generate the proofs of a transfer from `source_token_account` (whose keys are `keys`) and
    /// verify them into proof accounts paid by the payer. Checks the same as [`Self::transfer`]
    /// before creating anything.
    pub async fn prepare_transfer(
        &self,
        mint: &Pubkey,
        source_token_account: &Pubkey,
        keys: &ConfidentialKeys,
        destination_token_account: &Pubkey,
        amount: u64,
    ) -> Result<PreparedTransfer> {
        let operation = "prepare_transfer";
        check_amount(amount, operation, true)?;
        let mint_info = read_mint(&self.rpc, &TOKEN_2022_PROGRAM_ID, mint, operation).await?;
        let (proofs, _) = self
            .transfer_proofs(
                operation,
                mint,
                &mint_info,
                source_token_account,
                keys,
                destination_token_account,
                amount,
                None,
                TransferProofOptions::default(),
            )
            .await?;
        self.transfer_proof_accounts(
            operation,
            mint,
            source_token_account,
            destination_token_account,
            proofs,
        )
        .await
    }

    /// Generate the proofs of a withdraw and verify them into proof accounts.
    pub async fn prepare_withdraw(
        &self,
        mint: &Pubkey,
        token_account: &Pubkey,
        keys: &ConfidentialKeys,
        amount: u64,
    ) -> Result<PreparedWithdraw> {
        let operation = "prepare_withdraw";
        check_amount(amount, operation, false)?;
        let mint_info = read_mint(&self.rpc, &TOKEN_2022_PROGRAM_ID, mint, operation).await?;
        let proofs = self
            .withdraw_proofs(
                operation,
                &mint_info,
                mint,
                token_account,
                keys,
                amount,
                false,
            )
            .await?;
        self.withdraw_proof_accounts(operation, mint, token_account, proofs)
            .await
    }

    /// Prove `keys`' ElGamal public key into a proof account, for configuring an account whose
    /// owner signs through a program.
    pub async fn prepare_configure(&self, keys: &ConfidentialKeys) -> Result<PreparedConfigure> {
        let operation = "prepare_configure";
        let proof = build_pubkey_validity_proof_data(&keys.elgamal).map_err(|e| {
            Error::new(
                ErrorCode::InvalidInput,
                operation,
                format!("cannot prove the ElGamal key: {e}"),
            )
        })?;
        let sender = self.sender(operation);
        let mut setup = ProofSetup::new(&sender);
        let account = match setup
            .create(ProofInstruction::VerifyPubkeyValidity, &proof, false)
            .await
        {
            Ok(account) => account,
            Err(e) => return Err(setup.fail(e).await),
        };
        Ok(PreparedConfigure {
            pubkey_validity_proof: account,
            elgamal_pubkey: keys.elgamal_pubkey().into(),
            decryptable_zero_balance: PodAeCiphertext::from(keys.ae.encrypt(0)).0,
            signatures: setup.signatures,
        })
    }

    /// What `ApplyPendingBalance` needs for `token_account`, computed with its keys.
    pub async fn pending_balance_update(
        &self,
        mint: &Pubkey,
        token_account: &Pubkey,
        keys: &ConfidentialKeys,
    ) -> Result<PendingBalanceUpdate> {
        self.pending_balance_update_inner("pending_balance_update", mint, token_account, keys)
            .await
    }

    /// The extra accounts a mint's transfer hook needs for a transfer, to append to the transfer
    /// instruction or to pass to a program that makes the transfer (as remaining accounts).
    /// Empty when the mint has no transfer hook.
    ///
    /// Refused ([`ErrorCode::InvalidInput`]) if the hook's list asks for `authority` or the
    /// payer, or asks for any account as a signer: a key that signs the transaction is a signer
    /// in every instruction of it, and a Token-2022 built with an older account resolver passes
    /// such an account on to the hook as a signer, which could then spend from it. A program
    /// whose transaction has other signers should check that none of them is in the list.
    pub async fn transfer_hook_accounts(
        &self,
        mint: &Pubkey,
        source_token_account: &Pubkey,
        destination_token_account: &Pubkey,
        authority: &Pubkey,
    ) -> Result<Vec<AccountMeta>> {
        let operation = "transfer_hook_accounts";
        let base = [
            *source_token_account,
            *mint,
            *destination_token_account,
            *authority,
        ];
        let mut instruction = Instruction {
            program_id: TOKEN_2022_PROGRAM_ID,
            accounts: base
                .iter()
                .map(|k| AccountMeta::new_readonly(*k, false))
                .collect(),
            data: Vec::new(),
        };
        let rpc = self.rpc.clone();
        spl_token_2022::offchain::add_extra_account_metas(
            &mut instruction,
            source_token_account,
            mint,
            destination_token_account,
            authority,
            u64::MAX, // what Token-2022 passes the hook for a confidential transfer
            move |address| {
                let rpc = rpc.clone();
                async move {
                    rpc.get_account_with_commitment(&address, rpc.commitment())
                        .await
                        .map(|r| r.value.map(|a| a.data))
                        // Without the URL, which can carry an API key.
                        .map_err(|e| {
                            Box::new(without_url(e)) as Box<dyn std::error::Error + Send + Sync>
                        })
                }
            },
        )
        .await
        .map_err(|e| match e.downcast::<ClientError>() {
            Ok(e) => Error::rpc(
                operation,
                &format!("cannot read the accounts of mint {mint}'s transfer hook"),
                *e,
            ),
            Err(e) => Error::new(
                ErrorCode::AccountNotFound,
                operation,
                format!(
                    "cannot resolve the accounts of mint {mint}'s transfer hook (is its \
                     extra-account-meta list set up?): {}",
                    redact_urls(&e.to_string())
                ),
            ),
        })?;
        let extra = instruction.accounts.split_off(base.len());
        refuse_signers_in_hook_accounts(mint, &extra, &[*authority, self.payer()], operation)?;
        Ok(extra)
    }

    /// Close proof accounts whose authority is the payer, returning their rent to it.
    pub async fn close_proof_accounts(&self, accounts: &[Pubkey]) -> ProofAccounts {
        close_proof_accounts(&self.sender("close_proof_accounts"), accounts)
            .await
            .0
    }

    // ---------------------------------------------------------------------------------------

    /// Check a transfer and generate its proofs, with nothing sent yet. For a transfer this client
    /// signs (`hook_authority`), also the transfer hook's accounts, checked.
    #[allow(clippy::too_many_arguments)]
    async fn transfer_proofs(
        &self,
        operation: &'static str,
        mint: &Pubkey,
        mint_info: &MintInfo,
        source: &Pubkey,
        keys: &ConfidentialKeys,
        destination: &Pubkey,
        amount: u64,
        hook_authority: Option<&Pubkey>,
        options: TransferProofOptions<'_>,
    ) -> Result<(TransferProofs, Vec<AccountMeta>)> {
        // Everything Token-2022 would refuse is checked before the proofs are paid for.
        mint_info.assert_not_paused(mint, operation)?;
        mint_info.assert_no_transfer_fee(mint, source, destination, operation)?;
        let (_, source_ct) =
            read_configured_account(&self.rpc, source, mint, operation, "your").await?;
        assert_keys_match(keys, &source_ct, source, operation)?;
        assert_can_send(&source_ct, source, operation, "your")?;
        let (_, destination_ct) =
            read_configured_account(&self.rpc, destination, mint, operation, "the recipient's")
                .await?;
        assert_can_receive(&destination_ct, destination, operation, "the recipient's")?;
        if let Some(pinned) = options.pinned_destination_key {
            if destination_ct.elgamal_pubkey.0 != *pinned {
                return Err(Error::new(
                    ErrorCode::RecipientKeyMismatch,
                    operation,
                    format!(
                        "the RPC reports another ElGamal key for the recipient's account {destination} than the \
                         pinned one. Nothing was encrypted or signed. Check the RPC, or the recipient's key if \
                         the recipient set up a new account."
                    ),
                ));
            }
        }
        let applied = if options.apply_pending {
            pending_to_apply(&source_ct, keys, source, operation)?
        } else {
            None
        };
        let available = match &applied {
            Some(applied) => applied.value,
            None => available_balance(&source_ct, keys, source, operation)?,
        };
        if amount > available {
            return Err(insufficient_funds(operation, source, available));
        }
        // For a transfer this client signs: the hook's accounts, resolved and checked now.
        let hook_accounts = match (hook_authority, mint_info.transfer_hook_program) {
            (Some(authority), Some(_)) => self
                .transfer_hook_accounts(mint, source, destination, authority)
                .await
                .map_err(|e| e.within(operation))?,
            _ => Vec::new(),
        };
        let destination_pubkey =
            ElGamalPubkey::try_from(destination_ct.elgamal_pubkey).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidInput,
                    operation,
                    format!("{destination} has a malformed ElGamal key"),
                )
            })?;

        // The proofs and the new AES copy are computed from the checked balance, so a copy that
        // fell behind (see `available_balance`) is repaired by this transfer.
        let info = TransferAccountInfo {
            available_balance: applied
                .as_ref()
                .map_or(source_ct.available_balance, |a| a.available_balance),
            decryptable_available_balance: PodAeCiphertext::from(keys.ae.encrypt(available)),
        };
        let data = info
            .generate_split_transfer_proof_data(
                amount,
                &keys.elgamal,
                &keys.ae,
                &destination_pubkey,
                mint_info.auditor.as_ref(),
            )
            .map_err(|e| proof_error(operation, e))?;
        let new_balance = info
            .new_decryptable_available_balance(amount, &keys.ae)
            .map_err(|e| proof_error(operation, e))?;
        let proofs = TransferProofs {
            data,
            new_decryptable_available_balance: PodAeCiphertext::from(new_balance).0,
            apply: applied.map(|a| a.update),
        };
        Ok((proofs, hook_accounts))
    }

    /// Verify a transfer's proofs into proof accounts paid by the payer.
    async fn transfer_proof_accounts(
        &self,
        operation: &'static str,
        mint: &Pubkey,
        source: &Pubkey,
        destination: &Pubkey,
        proofs: TransferProofs,
    ) -> Result<PreparedTransfer> {
        let TransferProofData {
            equality_proof_data,
            ciphertext_validity_proof_data_with_ciphertext: validity,
            range_proof_data,
        } = proofs.data;
        let sender = self.sender(operation);
        let mut setup = ProofSetup::new(&sender);
        let created = async {
            let equality = setup
                .create(
                    ProofInstruction::VerifyCiphertextCommitmentEquality,
                    &equality_proof_data,
                    false,
                )
                .await?;
            let validity_account = setup
                .create(
                    ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
                    &validity.proof_data,
                    false,
                )
                .await?;
            let range = setup
                .create(
                    ProofInstruction::VerifyBatchedRangeProofU128,
                    &range_proof_data,
                    true,
                )
                .await?;
            Ok::<_, Error>((equality, validity_account, range))
        }
        .await;
        let (equality_proof, ciphertext_validity_proof, range_proof) = match created {
            Ok(accounts) => accounts,
            Err(e) => return Err(setup.fail(e).await),
        };
        Ok(PreparedTransfer {
            mint: *mint,
            source_token_account: *source,
            destination_token_account: *destination,
            equality_proof,
            ciphertext_validity_proof,
            range_proof,
            new_decryptable_available_balance: proofs.new_decryptable_available_balance,
            auditor_ciphertext_lo: validity.ciphertext_lo.0,
            auditor_ciphertext_hi: validity.ciphertext_hi.0,
            signatures: setup.signatures,
        })
    }

    /// Check a withdraw and generate its proofs, with nothing sent yet.
    #[allow(clippy::too_many_arguments)]
    async fn withdraw_proofs(
        &self,
        operation: &'static str,
        mint_info: &MintInfo,
        mint: &Pubkey,
        token: &Pubkey,
        keys: &ConfidentialKeys,
        amount: u64,
        apply_pending: bool,
    ) -> Result<WithdrawProofs> {
        mint_info.assert_not_paused(mint, operation)?;
        let decimals = mint_info.decimals;
        let (_, ct) = read_configured_account(&self.rpc, token, mint, operation, "your").await?;
        assert_keys_match(keys, &ct, token, operation)?;
        assert_can_send(&ct, token, operation, "your")?;
        let applied = if apply_pending {
            pending_to_apply(&ct, keys, token, operation)?
        } else {
            None
        };
        let available = match &applied {
            Some(applied) => applied.value,
            None => available_balance(&ct, keys, token, operation)?,
        };
        if amount > available {
            return Err(insufficient_funds(operation, token, available));
        }
        // As in a transfer: from the checked balance, which repairs a copy that fell behind.
        let info = WithdrawAccountInfo {
            available_balance: applied
                .as_ref()
                .map_or(ct.available_balance, |a| a.available_balance),
            decryptable_available_balance: PodAeCiphertext::from(keys.ae.encrypt(available)),
        };
        let data = info
            .generate_proof_data(amount, &keys.elgamal, &keys.ae)
            .map_err(|e| proof_error(operation, e))?;
        let new_balance = info
            .new_decryptable_available_balance(amount, &keys.ae)
            .map_err(|e| proof_error(operation, e))?;
        Ok(WithdrawProofs {
            data,
            amount,
            decimals,
            new_decryptable_available_balance: PodAeCiphertext::from(new_balance).0,
            apply: applied.map(|a| a.update),
        })
    }

    /// Verify a withdraw's proofs into proof accounts paid by the payer.
    async fn withdraw_proof_accounts(
        &self,
        operation: &'static str,
        mint: &Pubkey,
        token: &Pubkey,
        proofs: WithdrawProofs,
    ) -> Result<PreparedWithdraw> {
        let WithdrawProofData {
            equality_proof_data,
            range_proof_data,
        } = proofs.data;
        let sender = self.sender(operation);
        let mut setup = ProofSetup::new(&sender);
        let created = async {
            let equality = setup
                .create(
                    ProofInstruction::VerifyCiphertextCommitmentEquality,
                    &equality_proof_data,
                    false,
                )
                .await?;
            let range = setup
                .create(
                    ProofInstruction::VerifyBatchedRangeProofU64,
                    &range_proof_data,
                    true,
                )
                .await?;
            Ok::<_, Error>((equality, range))
        }
        .await;
        let (equality_proof, range_proof) = match created {
            Ok(accounts) => accounts,
            Err(e) => return Err(setup.fail(e).await),
        };
        Ok(PreparedWithdraw {
            mint: *mint,
            token_account: *token,
            amount: proofs.amount,
            decimals: proofs.decimals,
            equality_proof,
            range_proof,
            new_decryptable_available_balance: proofs.new_decryptable_available_balance,
            signatures: setup.signatures,
        })
    }

    async fn pending_balance_update_inner(
        &self,
        operation: &'static str,
        mint: &Pubkey,
        token: &Pubkey,
        keys: &ConfidentialKeys,
    ) -> Result<PendingBalanceUpdate> {
        let (_, ct) = read_configured_account(&self.rpc, token, mint, operation, "your").await?;
        assert_keys_match(keys, &ct, token, operation)?;
        pending_update(&ct, keys, token, operation)
    }

    /// Send `instruction` (signed by `owner`) together with closing the proof accounts when it
    /// fits in one transaction, or followed by a separate close. On failure, close them anyway,
    /// unless the outcome of the instruction's transaction is unknown. Returns the instruction's
    /// signature, every signature, and the proof accounts that may still be open.
    async fn run_with_proofs(
        &self,
        operation: &'static str,
        instruction: Instruction,
        owner: &(dyn Signer + Sync),
        proof_accounts: &[Pubkey],
        mut signatures: Vec<Signature>,
    ) -> Result<(Signature, Vec<Signature>, Vec<Pubkey>)> {
        let sender = self.sender(operation);
        let mut together = vec![instruction.clone()];
        together.extend(close_instructions(&self.payer(), proof_accounts));
        let closes_with_it = sender.fits(&together, 0);
        let sent = if closes_with_it {
            sender.send(&together, &[owner], operation).await
        } else {
            sender.send(&[instruction], &[owner], operation).await
        };
        let signature = match sent {
            Ok(signature) => signature,
            Err(e) => return Err(self.abandon(operation, proof_accounts, signatures, e).await),
        };
        signatures.push(signature);
        let mut left_open = Vec::new();
        if !closes_with_it {
            let (outcome, closing) = close_proof_accounts(&sender, proof_accounts).await;
            signatures.extend(closing);
            // The transfer went through; proof accounts left open are only rent, which
            // recover_proof_accounts gets back later. Not an error: the result lists them.
            left_open = outcome.left_open;
            left_open.extend(outcome.unknown);
        }
        Ok((signature, signatures, left_open))
    }

    /// Close the proof accounts of a transfer or withdraw that will not happen, and attach the
    /// outcome to `error`.
    ///
    /// When the outcome of the transfer's own transaction is unknown, they are left alone and
    /// reported as [`ProofAccounts::unknown`]: if that transaction landed, it used them (and,
    /// when they fit in it, closed them), and closing them now could fail for that reason and be
    /// misreported; if it is still in flight, closing them would make it fail.
    async fn abandon(
        &self,
        operation: &'static str,
        proof_accounts: &[Pubkey],
        mut signatures: Vec<Signature>,
        error: Error,
    ) -> Error {
        if error.unknown_outcome().is_some() {
            let outcome = ProofAccounts {
                unknown: proof_accounts.to_vec(),
                ..ProofAccounts::default()
            };
            return error
                .with_proof_accounts(outcome)
                .with_signatures(signatures);
        }
        let (outcome, closing) =
            close_proof_accounts(&self.sender(operation), proof_accounts).await;
        signatures.extend(closing);
        error
            .with_proof_accounts(outcome)
            .with_signatures(signatures)
    }
}

fn pending_update(
    ct: &ConfidentialTransferAccount,
    keys: &ConfidentialKeys,
    token: &Pubkey,
    operation: &'static str,
) -> Result<PendingBalanceUpdate> {
    let total = balance_after_apply(ct, keys, token, operation)?;
    Ok(PendingBalanceUpdate {
        expected_pending_balance_credit_counter: u64::from(ct.pending_balance_credit_counter),
        new_decryptable_available_balance: PodAeCiphertext::from(keys.ae.encrypt(total)).0,
    })
}

/// The pending balance, decrypted (its low and high part).
fn pending_amount(
    ct: &ConfidentialTransferAccount,
    keys: &ConfidentialKeys,
    token: &Pubkey,
    operation: &'static str,
) -> Result<u64> {
    let fail = |part: &str| {
        Error::new(
            ErrorCode::DecryptionFailed,
            operation,
            format!(
                "could not decrypt the {part} of the pending balance of {token}. Incoming amounts may add up to more \
                 than can be decrypted at once (about 2^48 base units)."
            ),
        )
    };
    let decrypt = |pending: PodElGamalCiphertext| {
        ElGamalCiphertext::try_from(pending)
            .ok()
            .and_then(|c| c.decrypt_u32(keys.elgamal.secret()))
    };
    let lo = decrypt(ct.pending_balance_lo).ok_or_else(|| fail("low part"))?;
    let hi = decrypt(ct.pending_balance_hi).ok_or_else(|| fail("high part"))?;
    hi.checked_shl(PENDING_BALANCE_LO_BIT_LENGTH)
        .and_then(|h| h.checked_add(lo))
        .ok_or_else(|| fail("total"))
}

/// The available balance as it stands once what is pending now is applied: what a transfer or
/// withdraw spends when it applies the pending balance in its own transaction.
///
/// ApplyPendingBalance adds everything pending when it runs, while the owner writes the AES copy
/// from what it read beforehand; a credit landing in between leaves the copy behind (see
/// `available_balance`). So the apply goes in the same transaction as an instruction whose proof
/// is about the exact ElGamal balance after it, computed here with Token-2022's own arithmetic
/// (`add_with_lo_hi`). If a credit lands meanwhile, Token-2022 refuses the whole transaction
/// (`ConfidentialTransferBalanceMismatch`, 0x1b) and nothing changes. The TypeScript SDK does the
/// same (`src/internal/pendingBalance.ts`).
#[derive(Clone, Copy)]
struct AppliedBalance {
    value: u64,
    available_balance: PodElGamalCiphertext,
    update: PendingBalanceUpdate,
}

fn applied_balance(
    ct: &ConfidentialTransferAccount,
    keys: &ConfidentialKeys,
    token: &Pubkey,
    operation: &'static str,
) -> Result<AppliedBalance> {
    let value = balance_after_apply(ct, keys, token, operation)?;
    let available_balance = spl_token_confidential_transfer_ciphertext_arithmetic::add_with_lo_hi(
        &ct.available_balance,
        &ct.pending_balance_lo,
        &ct.pending_balance_hi,
    )
    .ok_or_else(|| {
        Error::new(
            ErrorCode::DecryptionFailed,
            operation,
            format!("the encrypted balances of {token} are malformed"),
        )
    })?;
    Ok(AppliedBalance {
        value,
        available_balance,
        update: PendingBalanceUpdate {
            expected_pending_balance_credit_counter: u64::from(ct.pending_balance_credit_counter),
            new_decryptable_available_balance: PodAeCiphertext::from(keys.ae.encrypt(value)).0,
        },
    })
}

/// The pending balance to apply with a transfer or withdraw, or `None` when nothing is pending or
/// the pending total cannot be decrypted here (the operation then spends the available balance).
fn pending_to_apply(
    ct: &ConfidentialTransferAccount,
    keys: &ConfidentialKeys,
    token: &Pubkey,
    operation: &'static str,
) -> Result<Option<AppliedBalance>> {
    if u64::from(ct.pending_balance_credit_counter) == 0 {
        return Ok(None);
    }
    match applied_balance(ct, keys, token, operation) {
        Ok(applied) => Ok(Some(applied)),
        Err(e) if e.code() == ErrorCode::DecryptionFailed => Ok(None),
        Err(e) => Err(e),
    }
}

/// How often an operation that applies the pending balance builds its transaction again.
const PENDING_CHANGED_ATTEMPTS: u32 = 3;

/// True if Token-2022 refused a transaction because the balance its proof is about changed in the
/// meantime (`ConfidentialTransferBalanceMismatch`, 0x1b). Such a transaction changed nothing.
fn balance_changed(e: &Error) -> bool {
    const MISMATCH: &str = "custom program error: 0x1b";
    e.code() == ErrorCode::TransactionFailed
        && (e.to_string().contains(MISMATCH) || e.logs().iter().any(|line| line.contains(MISMATCH)))
}

/// Available plus pending: the balance an apply leaves.
fn balance_after_apply(
    ct: &ConfidentialTransferAccount,
    keys: &ConfidentialKeys,
    token: &Pubkey,
    operation: &'static str,
) -> Result<u64> {
    // The checked available balance, so that an apply also repairs a copy an earlier apply left
    // behind (see `available_balance`).
    let available = available_balance(ct, keys, token, operation)?;
    available
        .checked_add(pending_amount(ct, keys, token, operation)?)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::DecryptionFailed,
                operation,
                format!("the balance of {token} after the apply does not fit in 64 bits"),
            )
        })
}

/// Per-transfer choices for `transfer_proofs`.
#[derive(Clone, Copy, Default)]
struct TransferProofOptions<'a> {
    apply_pending: bool,
    pinned_destination_key: Option<&'a [u8; 32]>,
}

fn check_amount(amount: u64, operation: &'static str, capped: bool) -> Result<()> {
    if amount == 0 {
        return Err(Error::new(
            ErrorCode::InvalidInput,
            operation,
            "the amount must be more than zero",
        ));
    }
    if capped && amount > MAXIMUM_DEPOSIT_TRANSFER_AMOUNT {
        return Err(Error::new(
            ErrorCode::AmountTooLarge,
            operation,
            format!("{amount} is more than one deposit or transfer can carry ({MAXIMUM_DEPOSIT_TRANSFER_AMOUNT}); split it"),
        ));
    }
    Ok(())
}

/// Fails if the accounts `mint`'s transfer hook asks for (`extra`) include one of `signers`, the
/// keys that sign the transfer's transaction, or ask for any account as a signer.
///
/// Signing is per transaction, not per instruction: the payer and the owner are signers wherever
/// they appear in it. Token-2022 hands the hook's accounts to the hook with the flags of the
/// hook's own list; one built with spl-tlv-account-resolution 0.11 clears the signer flag, but an
/// older build keeps it for an account not already in the hook call. A list that names the payer
/// as a signer would then let the hook move the payer's SOL, and one that names the owner its
/// tokens. Arcantis adds no signers for hooks (threat model, known limit 5), so such a list is
/// refused before anything is signed.
fn refuse_signers_in_hook_accounts(
    mint: &Pubkey,
    extra: &[AccountMeta],
    signers: &[Pubkey],
    operation: &'static str,
) -> Result<()> {
    for meta in extra {
        if signers.contains(&meta.pubkey) {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                operation,
                format!(
                    "mint {mint}'s transfer hook asks for account {}, which signs this transfer \
                     (the payer or the token account's owner). The hook could act with that \
                     signature, so the transfer is refused.",
                    meta.pubkey
                ),
            ));
        }
        if meta.is_signer {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                operation,
                format!(
                    "mint {mint}'s transfer hook asks for account {} as a signer; Arcantis adds \
                     no signers for transfer hooks",
                    meta.pubkey
                ),
            ));
        }
    }
    Ok(())
}

/// More than the available balance. The balance and the amount stay out of the message, which
/// may be logged; [`Error::available_balance`] has the balance.
fn insufficient_funds(operation: &'static str, token: &Pubkey, available: u64) -> Error {
    Error::new(
        ErrorCode::InsufficientFunds,
        operation,
        format!(
            "the available confidential balance of {token} is less than the amount \
             (Error::available_balance has it)"
        ),
    )
    .with_available_balance(available)
}

fn proof_error(operation: &'static str, e: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::DecryptionFailed,
        operation,
        format!("cannot generate the proofs from the account's balance: {e}"),
    )
}

fn build_error(operation: &'static str, e: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorCode::InvalidInput,
        operation,
        format!("cannot build the instruction: {e}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Keypair;

    fn send<T: Send>(_: &T) {}

    /// Compile-time: the client can be shared across threads, and its futures can be spawned on
    /// a multi-threaded runtime. The futures are built, never polled.
    #[tokio::test]
    async fn the_client_and_its_futures_are_send() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<ConfidentialClient>();
        let client = ConfidentialClient::new(
            Arc::new(RpcClient::new_mock("succeeds".to_string())),
            Arc::new(Keypair::new()),
        );
        let (owner, mint, other) = (Keypair::new(), Pubkey::new_unique(), Pubkey::new_unique());
        let keys = ConfidentialKeys::derive(&owner).unwrap();
        send(&client.configure_account(&owner, &mint));
        send(&client.deposit(&owner, &mint, 1));
        send(&client.apply_pending_balance(&owner, &mint));
        send(&client.decrypt_balance(&owner, &mint));
        send(&client.transfer(&owner, &mint, &other, 1));
        send(&client.withdraw(&owner, &mint, 1));
        send(&client.recover_proof_accounts());
        send(&client.prepare_transfer(&mint, &other, &keys, &other, 1));
        send(&client.prepare_withdraw(&mint, &other, &keys, 1));
        send(&client.prepare_configure(&keys));
        send(&client.transfer_hook_accounts(&mint, &other, &other, &other));
        send(&client.close_proof_accounts(&[other]));
    }

    #[test]
    fn refuses_a_hook_list_that_names_a_signer_of_the_transfer() {
        let [mint, payer, owner, other] = [(); 4].map(|_| Pubkey::new_unique());
        let check = |extra: &[AccountMeta]| {
            refuse_signers_in_hook_accounts(&mint, extra, &[owner, payer], "transfer")
                .map_err(|e| e.code())
        };
        assert_eq!(check(&[AccountMeta::new_readonly(other, false)]), Ok(()));
        // Whatever flags the list gives them: the payer and the owner sign the transaction.
        assert_eq!(
            check(&[
                AccountMeta::new_readonly(other, false),
                AccountMeta::new(payer, false)
            ]),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            check(&[AccountMeta::new_readonly(owner, false)]),
            Err(ErrorCode::InvalidInput)
        );
        assert_eq!(
            check(&[AccountMeta::new_readonly(other, true)]),
            Err(ErrorCode::InvalidInput)
        );
    }

    /// `transfer_hook_accounts` for a mint whose hook's extra-account-meta list asks for `asked`
    /// (read-only, not a signer), with a mock RPC serving the mint and the list.
    async fn hook_accounts_asking_for(
        asked: Pubkey,
        payer: Keypair,
        authority: Pubkey,
    ) -> Result<Vec<AccountMeta>> {
        use serde_json::json;
        use solana_client::rpc_request::RpcRequest;
        use spl_tlv_account_resolution::{account::ExtraAccountMeta, state::ExtraAccountMetaList};
        use spl_token_2022_interface::{
            extension::{
                transfer_hook::TransferHook, BaseStateWithExtensionsMut, StateWithExtensionsMut,
            },
            state::Mint,
        };
        use spl_transfer_hook_interface::instruction::ExecuteInstruction;

        let (mint, hook) = (Pubkey::new_unique(), Pubkey::new_unique());
        let types = [ExtensionType::TransferHook];
        let mut mint_data =
            vec![0; ExtensionType::try_calculate_account_len::<Mint>(&types).unwrap()];
        let mut state =
            StateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut mint_data).unwrap();
        state
            .init_extension::<TransferHook>(true)
            .unwrap()
            .program_id = Some(hook).try_into().unwrap();
        state.base = Mint {
            decimals: 2,
            is_initialized: true,
            ..Mint::default()
        };
        state.pack_base();
        state.init_account_type().unwrap();

        let metas = [ExtraAccountMeta::new_with_pubkey(&asked, false, false).unwrap()];
        let mut list = vec![0; ExtraAccountMetaList::size_of(metas.len()).unwrap()];
        ExtraAccountMetaList::init::<ExecuteInstruction>(&mut list, &metas).unwrap();

        let account = |owner: &Pubkey, data: &[u8]| {
            json!({
                "context": { "slot": 1 },
                "value": {
                    "lamports": 1,
                    "data": [bs58::encode(data).into_string(), "base58"],
                    "owner": owner.to_string(),
                    "executable": false,
                    "rentEpoch": 0,
                    "space": data.len(),
                }
            })
        };
        // Answered in order: the mint, then the hook's list.
        let mocks = vec![
            (
                RpcRequest::GetAccountInfo,
                account(&TOKEN_2022_PROGRAM_ID, &mint_data),
            ),
            (RpcRequest::GetAccountInfo, account(&hook, &list)),
        ]
        .into_iter()
        .collect();
        let client = ConfidentialClient::new(
            Arc::new(RpcClient::new_mock_with_mocks_map("succeeds", mocks)),
            Arc::new(payer),
        );
        client
            .transfer_hook_accounts(
                &mint,
                &Pubkey::new_unique(),
                &Pubkey::new_unique(),
                &authority,
            )
            .await
    }

    #[tokio::test]
    async fn refuses_a_transfer_hook_that_asks_for_the_payer_or_the_owner() {
        let (payer, owner, other) = (Keypair::new(), Pubkey::new_unique(), Pubkey::new_unique());
        let extra = hook_accounts_asking_for(other, Keypair::new(), owner)
            .await
            .unwrap();
        assert_eq!(extra[0].pubkey, other);
        assert!(!extra.iter().any(|meta| meta.is_signer));

        let e = hook_accounts_asking_for(payer.pubkey(), payer, owner)
            .await
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidInput, "{e}");
        let e = hook_accounts_asking_for(owner, Keypair::new(), owner)
            .await
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidInput, "{e}");
        assert!(e.to_string().contains("signs this transfer"), "{e}");
    }

    /// Every text an error carries: its message, its `Debug`, and those of its sources.
    fn texts(e: &Error) -> Vec<String> {
        let mut texts = vec![e.to_string(), format!("{e:?}")];
        let mut source = std::error::Error::source(e);
        while let Some(s) = source {
            texts.push(s.to_string());
            texts.push(format!("{s:?}"));
            source = s.source();
        }
        texts
    }

    /// RPC providers put API keys in the URL; reqwest prints the URL in its errors. Nothing
    /// listens on port 9 here, so every request fails without a network.
    #[tokio::test]
    async fn keeps_the_rpc_url_out_of_errors() {
        let url = "http://127.0.0.1:9/?api-key=SECRET";
        let rpc = Arc::new(RpcClient::new(url.to_string()));
        let raw = rpc.get_balance(&Pubkey::new_unique()).await.unwrap_err();
        assert!(
            format!("{raw} {raw:?}").contains("SECRET"),
            "the RPC client's own error names the URL, so this test means something: {raw:?}"
        );

        let client = ConfidentialClient::new(rpc, Arc::new(Keypair::new()));
        let (owner, mint) = (Keypair::new(), Pubkey::new_unique());
        let errors = [
            // read_mint, through fetch
            client.deposit(&owner, &mint, 1).await.unwrap_err(),
            // Sender::rpc_error
            client.recover_proof_accounts().await.unwrap_err(),
            // the transfer hook's account resolution
            client
                .transfer_hook_accounts(&mint, &mint, &mint, &mint)
                .await
                .unwrap_err(),
        ];
        for e in &errors {
            assert_eq!(e.code(), ErrorCode::Rpc, "{e}");
            for text in texts(e) {
                assert!(!text.contains("SECRET"), "{text}");
                assert!(!text.contains("api-key"), "{text}");
            }
        }
    }
}
