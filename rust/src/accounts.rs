// SPDX-License-Identifier: BUSL-1.1
//! Reading mints and token accounts before acting on them, so that a missing account, a missing
//! extension or a full pending balance fails with a clear error before anything is signed.
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_zk_sdk::encryption::{
    auth_encryption::AeCiphertext,
    elgamal::{ElGamalCiphertext, ElGamalPubkey},
};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey;
use spl_token_2022_interface::{
    extension::{
        confidential_transfer::{ConfidentialTransferAccount, ConfidentialTransferMint},
        pausable::PausableConfig,
        transfer_fee::TransferFeeConfig,
        transfer_hook, BaseStateWithExtensions, StateWithExtensionsOwned,
    },
    state::{Account, Mint},
};

use crate::error::{Error, ErrorCode, Result};
use crate::keys::ConfidentialKeys;

pub(crate) struct MintInfo {
    pub decimals: u8,
    pub auditor: Option<ElGamalPubkey>,
    pub transfer_hook_program: Option<Pubkey>,
    /// The mint's `PausableConfig` says it is paused: Token-2022 refuses deposits, transfers and
    /// withdrawals.
    pub paused: bool,
    /// The mint has a `TransferFeeConfig`: Token-2022 then takes only `TransferWithFee` between
    /// two accounts, which this crate does not build.
    pub transfer_fee: bool,
}

impl MintInfo {
    /// Fails if the mint is paused.
    pub fn assert_not_paused(&self, mint: &Pubkey, operation: &'static str) -> Result<()> {
        if self.paused {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                operation,
                format!(
                    "mint {mint} is paused: Token-2022 refuses deposits, transfers and withdrawals \
                     until its pause authority resumes it"
                ),
            ));
        }
        Ok(())
    }

    /// Fails if a transfer from `source` to `destination` would need `TransferWithFee`.
    pub fn assert_no_transfer_fee(
        &self,
        mint: &Pubkey,
        source: &Pubkey,
        destination: &Pubkey,
        operation: &'static str,
    ) -> Result<()> {
        if self.transfer_fee && source != destination {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                operation,
                format!(
                    "mint {mint} has a transfer fee (TransferFeeConfig): its confidential transfers \
                     need TransferWithFee, which this release does not build"
                ),
            ));
        }
        Ok(())
    }
}

pub(crate) async fn read_mint(
    rpc: &RpcClient,
    program_id: &Pubkey,
    mint: &Pubkey,
    operation: &'static str,
) -> Result<MintInfo> {
    let account = fetch(rpc, mint, operation).await?.ok_or_else(|| {
        Error::new(
            ErrorCode::AccountNotFound,
            operation,
            format!("mint {mint} does not exist"),
        )
    })?;
    parse_mint(program_id, mint, account, operation)
}

fn parse_mint(
    program_id: &Pubkey,
    mint: &Pubkey,
    account: solana_sdk::account::Account,
    operation: &'static str,
) -> Result<MintInfo> {
    let not_a_mint = || {
        Error::new(
            ErrorCode::InvalidInput,
            operation,
            format!("{mint} is not a Token-2022 mint"),
        )
    };
    if account.owner != *program_id {
        return Err(not_a_mint());
    }
    let state = StateWithExtensionsOwned::<Mint>::unpack(account.data).map_err(|_| not_a_mint())?;
    let auditor = match state.get_extension::<ConfidentialTransferMint>() {
        Ok(ct) => Option::<PodElGamalPubkey>::from(ct.auditor_elgamal_pubkey)
            .map(|pod| {
                ElGamalPubkey::try_from(pod).map_err(|_| {
                    Error::new(ErrorCode::InvalidInput, operation, format!("mint {mint} has a malformed auditor key"))
                })
            })
            .transpose()?,
        Err(_) => {
            return Err(Error::new(
                ErrorCode::InvalidInput,
                operation,
                format!("mint {mint} does not have confidential transfers enabled (no ConfidentialTransferMint extension)"),
            ))
        }
    };
    Ok(MintInfo {
        decimals: state.base.decimals,
        auditor,
        transfer_hook_program: transfer_hook::get_program_id(&state),
        paused: state
            .get_extension::<PausableConfig>()
            .is_ok_and(|pausable| bool::from(pausable.paused)),
        transfer_fee: state.get_extension::<TransferFeeConfig>().is_ok(),
    })
}

pub(crate) struct TokenAccount {
    pub state: StateWithExtensionsOwned<Account>,
}

impl TokenAccount {
    pub fn confidential(&self) -> Option<ConfidentialTransferAccount> {
        self.state
            .get_extension::<ConfidentialTransferAccount>()
            .ok()
            .copied()
    }
}

/// A token account, or None if it does not exist.
pub(crate) async fn read_token_account(
    rpc: &RpcClient,
    address: &Pubkey,
    mint: &Pubkey,
    operation: &'static str,
) -> Result<Option<TokenAccount>> {
    let Some(account) = fetch(rpc, address, operation).await? else {
        return Ok(None);
    };
    parse_token_account(address, mint, account, operation).map(Some)
}

fn parse_token_account(
    address: &Pubkey,
    mint: &Pubkey,
    account: solana_sdk::account::Account,
    operation: &'static str,
) -> Result<TokenAccount> {
    let not_a_token_account = || {
        Error::new(
            ErrorCode::InvalidInput,
            operation,
            format!("{address} is not a Token-2022 token account"),
        )
    };
    // Data shaped like a token account means nothing unless Token-2022 owns it.
    if account.owner != spl_token_2022_interface::ID {
        return Err(not_a_token_account());
    }
    let state = StateWithExtensionsOwned::<Account>::unpack(account.data)
        .map_err(|_| not_a_token_account())?;
    if state.base.mint != *mint {
        return Err(Error::new(
            ErrorCode::InvalidInput,
            operation,
            format!(
                "token account {address} belongs to mint {}, not {mint}",
                state.base.mint
            ),
        ));
    }
    Ok(TokenAccount { state })
}

/// A token account that must exist and be configured for confidential transfers. `whose` goes
/// into the message: "your", "the recipient's".
pub(crate) async fn read_configured_account(
    rpc: &RpcClient,
    address: &Pubkey,
    mint: &Pubkey,
    operation: &'static str,
    whose: &str,
) -> Result<(TokenAccount, ConfidentialTransferAccount)> {
    let account = read_token_account(rpc, address, mint, operation).await?.ok_or_else(|| {
        Error::new(
            ErrorCode::AccountNotFound,
            operation,
            format!("{whose} token account {address} does not exist. It is created by configure_account."),
        )
    })?;
    let ct = account.confidential().ok_or_else(|| {
        Error::new(
            ErrorCode::AccountNotConfigured,
            operation,
            format!(
                "{whose} token account {address} is missing the ConfidentialTransferAccount extension; \
                 it has to be set up with configure_account first."
            ),
        )
    })?;
    Ok((account, ct))
}

/// Fails unless the account can be the source of a transfer or withdraw: Token-2022 takes only
/// accounts the mint's confidential-transfer authority has approved.
pub(crate) fn assert_can_send(
    ct: &ConfidentialTransferAccount,
    address: &Pubkey,
    operation: &'static str,
    whose: &str,
) -> Result<()> {
    if !bool::from(ct.approved) {
        return Err(not_approved(address, operation, whose));
    }
    Ok(())
}

fn not_approved(address: &Pubkey, operation: &'static str, whose: &str) -> Error {
    Error::new(
        ErrorCode::AccountNotApproved,
        operation,
        format!(
            "{whose} token account {address} has not been approved for confidential transfers by the mint's \
             confidential-transfer authority."
        ),
    )
}

/// Fails unless the account can take one more incoming deposit or transfer.
pub(crate) fn assert_can_receive(
    ct: &ConfidentialTransferAccount,
    address: &Pubkey,
    operation: &'static str,
    whose: &str,
) -> Result<()> {
    if !bool::from(ct.approved) {
        return Err(not_approved(address, operation, whose));
    }
    if !bool::from(ct.allow_confidential_credits) {
        return Err(Error::new(
            ErrorCode::RecipientRejectsConfidential,
            operation,
            format!("{whose} token account {address} does not accept confidential credits."),
        ));
    }
    let received = u64::from(ct.pending_balance_credit_counter);
    if received >= u64::from(ct.maximum_pending_balance_credit_counter) {
        let next = if whose == "your" {
            "Run apply_pending_balance first."
        } else {
            "The recipient has to run apply_pending_balance first."
        };
        return Err(Error::new(
            ErrorCode::PendingBalanceLimit,
            operation,
            format!(
                "{whose} token account {address} has received {received} deposits or transfers since its pending \
                 balance was last applied, the most it takes. {next}"
            ),
        ));
    }
    Ok(())
}

/// Fails unless `keys` are the keys `ct` is configured with.
pub(crate) fn assert_keys_match(
    keys: &ConfidentialKeys,
    ct: &ConfidentialTransferAccount,
    address: &Pubkey,
    operation: &'static str,
) -> Result<()> {
    if PodElGamalPubkey::from(*keys.elgamal_pubkey()) != ct.elgamal_pubkey {
        return Err(Error::new(
            ErrorCode::KeysMismatch,
            operation,
            format!(
                "token account {address} is configured with another ElGamal key than the one derived from this \
                 signer. It was configured by another wallet, or with keys derived another way."
            ),
        ));
    }
    Ok(())
}

/// The account's available balance, as the owner's keys read it.
///
/// Token-2022 keeps the available balance twice: ElGamal-encrypted (what the proofs are about)
/// and as an AES copy the owner writes with every apply, transfer and withdraw. The copy falls
/// behind when a deposit or transfer arrives between the owner reading the account and its
/// `ApplyPendingBalance`: Token-2022 adds everything pending, records the expected and actual
/// credit counters, and keeps the copy the owner computed without that credit. Proofs built from
/// a stale copy are refused on chain.
///
/// So the copy is checked against the ElGamal balance first. If it is behind, the difference is
/// decrypted (a 32-bit discrete log, so differences below 2^32 base units) and added; the call
/// then writes a corrected copy, which repairs the account. A larger difference, or a copy ahead
/// of the balance, is `BalanceOutOfSync`. The TypeScript SDK does the same
/// (`src/internal/availableBalance.ts`).
pub(crate) fn available_balance(
    ct: &ConfidentialTransferAccount,
    keys: &ConfidentialKeys,
    address: &Pubkey,
    operation: &'static str,
) -> Result<u64> {
    let encrypted = ElGamalCiphertext::try_from(ct.available_balance).map_err(|_| {
        Error::new(
            ErrorCode::DecryptionFailed,
            operation,
            format!("the encrypted available balance of {address} is malformed"),
        )
    })?;
    let copy = AeCiphertext::try_from(ct.decryptable_available_balance)
        .ok()
        .and_then(|c| keys.ae.decrypt(&c));
    let base = copy.unwrap_or(0);
    // What the ElGamal balance holds beyond the copy: zero when they agree.
    let missed = encrypted
        .subtract_amount(base)
        .decrypt_u32(keys.elgamal.secret());
    match missed.and_then(|m| base.checked_add(m)) {
        Some(balance) => Ok(balance),
        None => Err(Error::new(
            ErrorCode::BalanceOutOfSync,
            operation,
            // The copy's value is a decrypted balance: it stays out of the message.
            format!(
                "the AES copy of the available balance of {address} {}, and the difference is too \
                 large to recover here (2^32 base units or more). This happens when deposits or \
                 transfers arrive while apply_pending_balance runs. The funds are in the encrypted \
                 balance; only the copy the SDK reads them from is out of date.",
                if copy.is_some() {
                    "does not match the encrypted balance"
                } else {
                    "cannot be decrypted"
                }
            ),
        )),
    }
}

async fn fetch(
    rpc: &RpcClient,
    address: &Pubkey,
    operation: &'static str,
) -> Result<Option<solana_sdk::account::Account>> {
    rpc.get_account_with_commitment(address, rpc.commitment())
        .await
        .map(|r| r.value)
        .map_err(|e| Error::rpc(operation, &format!("could not read account {address}"), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytemuck::Zeroable;
    use solana_sdk::{program_pack::Pack, signature::Keypair};
    use solana_zk_sdk::encryption::auth_encryption::AeKey;
    use spl_token_2022_interface::extension::{
        BaseStateWithExtensionsMut, ExtensionType, StateWithExtensionsMut,
    };

    fn account(
        keys: &ConfidentialKeys,
        encrypted: u64,
        copy: Option<u64>,
    ) -> ConfidentialTransferAccount {
        let mut ct = ConfidentialTransferAccount::zeroed();
        ct.available_balance = keys.elgamal.pubkey().encrypt(encrypted).into();
        ct.decryptable_available_balance = match copy {
            Some(value) => keys.ae.encrypt(value).into(),
            None => AeKey::new_rand().encrypt(1).into(),
        };
        ct
    }

    fn read(ct: &ConfidentialTransferAccount, keys: &ConfidentialKeys) -> Result<u64> {
        available_balance(ct, keys, &Pubkey::default(), "test")
    }

    #[test]
    fn reads_the_aes_copy_when_it_matches() {
        let keys = ConfidentialKeys::derive(&Keypair::new()).unwrap();
        assert_eq!(
            read(&account(&keys, 1_000, Some(1_000)), &keys).unwrap(),
            1_000
        );
    }

    #[test]
    fn reads_a_fresh_account() {
        let keys = ConfidentialKeys::derive(&Keypair::new()).unwrap();
        let mut ct = ConfidentialTransferAccount::zeroed();
        ct.decryptable_available_balance = keys.ae.encrypt(0).into();
        assert_eq!(read(&ct, &keys).unwrap(), 0);
    }

    #[test]
    fn adds_what_a_copy_that_fell_behind_missed() {
        let keys = ConfidentialKeys::derive(&Keypair::new()).unwrap();
        assert_eq!(
            read(&account(&keys, 1_300, Some(1_000)), &keys).unwrap(),
            1_300
        );
    }

    #[test]
    fn decrypts_a_small_balance_whose_copy_cannot_be_read() {
        let keys = ConfidentialKeys::derive(&Keypair::new()).unwrap();
        assert_eq!(read(&account(&keys, 500, None), &keys).unwrap(), 500);
    }

    #[test]
    fn refuses_a_difference_of_2_to_the_32_or_more_and_a_copy_ahead() {
        let keys = ConfidentialKeys::derive(&Keypair::new()).unwrap();
        let far_behind = read(&account(&keys, 1_000 + (1 << 33), Some(1_000)), &keys);
        assert_eq!(far_behind.unwrap_err().code(), ErrorCode::BalanceOutOfSync);
        let ahead = read(&account(&keys, 900, Some(1_000)), &keys);
        let ahead = ahead.unwrap_err();
        assert_eq!(ahead.code(), ErrorCode::BalanceOutOfSync);
        assert!(!ahead.to_string().contains("1000"), "{ahead}");
    }

    /// A Token-2022 mint with confidential transfers and `extensions`, which `init` sets up.
    fn mint_account(
        extensions: &[ExtensionType],
        init: impl FnOnce(&mut StateWithExtensionsMut<Mint>),
    ) -> solana_sdk::account::Account {
        let mut types = vec![ExtensionType::ConfidentialTransferMint];
        types.extend_from_slice(extensions);
        let mut data = vec![0; ExtensionType::try_calculate_account_len::<Mint>(&types).unwrap()];
        let mut state = StateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut data).unwrap();
        state
            .init_extension::<ConfidentialTransferMint>(true)
            .unwrap();
        init(&mut state);
        state.base = Mint {
            decimals: 2,
            is_initialized: true,
            ..Mint::default()
        };
        state.pack_base();
        state.init_account_type().unwrap();
        solana_sdk::account::Account {
            lamports: 1,
            data,
            owner: spl_token_2022_interface::ID,
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn reads_a_paused_mint_and_a_mint_with_a_transfer_fee() {
        let (mint, a, b) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let parse = |account| parse_mint(&spl_token_2022_interface::ID, &mint, account, "test");

        let plain = parse(mint_account(&[], |_| {})).unwrap();
        assert!(plain.assert_not_paused(&mint, "test").is_ok());
        assert!(plain.assert_no_transfer_fee(&mint, &a, &b, "test").is_ok());

        let paused = parse(mint_account(&[ExtensionType::Pausable], |state| {
            state.init_extension::<PausableConfig>(true).unwrap().paused = true.into();
        }))
        .unwrap();
        let e = paused.assert_not_paused(&mint, "test").unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidInput);
        assert!(e.to_string().contains("paused"), "{e}");

        let resumed = parse(mint_account(&[ExtensionType::Pausable], |state| {
            state.init_extension::<PausableConfig>(true).unwrap();
        }))
        .unwrap();
        assert!(resumed.assert_not_paused(&mint, "test").is_ok());

        let with_fee = parse(mint_account(&[ExtensionType::TransferFeeConfig], |state| {
            state.init_extension::<TransferFeeConfig>(true).unwrap();
        }))
        .unwrap();
        let e = with_fee
            .assert_no_transfer_fee(&mint, &a, &b, "test")
            .unwrap_err();
        assert!(e.to_string().contains("TransferWithFee"), "{e}");
        // A transfer to the same account needs no fee, and Token-2022 takes it.
        assert!(with_fee
            .assert_no_transfer_fee(&mint, &a, &a, "test")
            .is_ok());
    }

    #[test]
    fn takes_a_token_account_only_from_token_2022() {
        let (mint, address) = (Pubkey::new_unique(), Pubkey::new_unique());
        let mut data = vec![0; Account::LEN];
        Account {
            mint,
            owner: Pubkey::new_unique(),
            state: spl_token_2022_interface::state::AccountState::Initialized,
            ..Account::default()
        }
        .pack_into_slice(&mut data);
        let account = |owner| solana_sdk::account::Account {
            lamports: 1,
            data: data.clone(),
            owner,
            executable: false,
            rent_epoch: 0,
        };
        assert!(parse_token_account(
            &address,
            &mint,
            account(spl_token_2022_interface::ID),
            "test"
        )
        .is_ok());
        let e = parse_token_account(&address, &mint, account(Pubkey::new_unique()), "test")
            .err()
            .expect("refused");
        assert_eq!(e.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn refuses_a_source_that_is_not_approved() {
        let mut ct = ConfidentialTransferAccount::zeroed();
        let e = assert_can_send(&ct, &Pubkey::default(), "transfer", "your").unwrap_err();
        assert_eq!(e.code(), ErrorCode::AccountNotApproved);
        ct.approved = true.into();
        assert!(assert_can_send(&ct, &Pubkey::default(), "transfer", "your").is_ok());
    }
}
