// SPDX-License-Identifier: BUSL-1.1
//! Example: a program that holds a Token-2022 **confidential** balance and pays out of it.
//!
//! The vault's token account is owned by a PDA, so no wallet can move its tokens; only this
//! program can, when the vault's operator asks. Amounts stay encrypted throughout: the deposits
//! into the vault, its balance and its payouts. The mint's auditor, if it has one, can read every
//! amount.
//!
//! A PDA cannot sign the message the confidential keys come from, so the vault's keys are derived
//! by the operator's wallet with a seed that scopes them to the vault's token account
//! (`ConfidentialKeys::derive_for_pda_wallet` in the `arcantis` crate).
//! The operator's client uses those keys to generate the zero-knowledge proofs and verify them
//! into proof accounts; this program then makes the Token-2022 call, signing as the PDA. It never
//! sees a key.
//!
//! Instructions:
//! - `initialize`: create the vault for a mint, with its operator.
//! - `configure`: set up the vault's token account for confidential transfers.
//! - `apply_pending`: move incoming transfers into the vault's available balance.
//! - `pay`: confidentially transfer from the vault to any account of the mint. Transfer-hook
//!   accounts, if the mint has a hook, come as remaining accounts.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};

declare_id!("DzaS2RboEYWKC1EvuPPnWpDbjJesPheCw3KV14qVvoPn");

pub const TOKEN_2022: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

#[program]
pub mod confidential_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.operator = ctx.accounts.operator.key();
        vault.mint = ctx.accounts.mint.key();
        vault.bump = ctx.bumps.vault;
        Ok(())
    }

    /// Add the confidential-transfer extension to the vault's token account and configure it with
    /// the vault's ElGamal key, proved in `pubkey_validity_proof`.
    pub fn configure(ctx: Context<Configure>, decryptable_zero_balance: [u8; 36]) -> Result<()> {
        let a = &ctx.accounts;
        let seeds: &[&[u8]] = &[b"vault", a.mint.key.as_ref(), &[a.vault.bump]];
        invoke_signed(
            &token_2022::reallocate_for_confidential_transfers(
                a.vault_token.key,
                a.operator.key,
                &a.vault.key(),
            ),
            &[
                a.vault_token.to_account_info(),
                a.operator.to_account_info(),
                a.system_program.to_account_info(),
                a.vault.to_account_info(),
                a.token_program.to_account_info(),
            ],
            &[seeds],
        )?;
        invoke_signed(
            &token_2022::configure_account(
                a.vault_token.key,
                a.mint.key,
                a.pubkey_validity_proof.key,
                &a.vault.key(),
                &decryptable_zero_balance,
            ),
            &[
                a.vault_token.to_account_info(),
                a.mint.to_account_info(),
                a.pubkey_validity_proof.to_account_info(),
                a.vault.to_account_info(),
                a.token_program.to_account_info(),
            ],
            &[seeds],
        )?;
        Ok(())
    }

    /// Move the vault's pending balance into its available balance. The operator's client
    /// computes both arguments with the vault's keys.
    pub fn apply_pending(
        ctx: Context<ApplyPending>,
        expected_pending_balance_credit_counter: u64,
        new_decryptable_available_balance: [u8; 36],
    ) -> Result<()> {
        let a = &ctx.accounts;
        let seeds: &[&[u8]] = &[b"vault", a.vault.mint.as_ref(), &[a.vault.bump]];
        invoke_signed(
            &token_2022::apply_pending_balance(
                a.vault_token.key,
                &a.vault.key(),
                expected_pending_balance_credit_counter,
                &new_decryptable_available_balance,
            ),
            &[
                a.vault_token.to_account_info(),
                a.vault.to_account_info(),
                a.token_program.to_account_info(),
            ],
            &[seeds],
        )?;
        Ok(())
    }

    /// Confidentially transfer from the vault to `destination_token`. The amount is not an
    /// argument: it is in the proofs, which the operator's client verified into the three proof
    /// accounts, and in the new balance it computed.
    pub fn pay<'info>(
        ctx: Context<'_, '_, 'info, 'info, Pay<'info>>,
        new_decryptable_available_balance: [u8; 36],
        auditor_ciphertext_lo: [u8; 64],
        auditor_ciphertext_hi: [u8; 64],
    ) -> Result<()> {
        let a = &ctx.accounts;
        let seeds: &[&[u8]] = &[b"vault", a.mint.key.as_ref(), &[a.vault.bump]];
        let mut instruction = token_2022::transfer(
            a.vault_token.key,
            a.mint.key,
            a.destination_token.key,
            [
                a.equality_proof.key,
                a.ciphertext_validity_proof.key,
                a.range_proof.key,
            ],
            &a.vault.key(),
            &new_decryptable_available_balance,
            &auditor_ciphertext_lo,
            &auditor_ciphertext_hi,
        );
        let mut infos = vec![
            a.vault_token.to_account_info(),
            a.mint.to_account_info(),
            a.destination_token.to_account_info(),
            a.equality_proof.to_account_info(),
            a.ciphertext_validity_proof.to_account_info(),
            a.range_proof.to_account_info(),
            a.vault.to_account_info(),
            a.token_program.to_account_info(),
        ];
        // The mint's transfer hook: its program, its validation account and the accounts it asks
        // for, resolved by the client.
        for account in ctx.remaining_accounts {
            instruction.accounts.push(AccountMeta {
                pubkey: *account.key,
                is_signer: false,
                is_writable: account.is_writable,
            });
            infos.push(account.clone());
        }
        invoke_signed(&instruction, &infos, &[seeds])?;
        emit!(Paid {
            vault: a.vault.key(),
            destination: a.destination_token.key()
        });
        Ok(())
    }
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub operator: Pubkey,
    pub mint: Pubkey,
    pub bump: u8,
}

/// A payout, without its amount (that is encrypted in the transfer).
#[event]
pub struct Paid {
    pub vault: Pubkey,
    pub destination: Pubkey,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub operator: Signer<'info>,
    /// CHECK: a Token-2022 mint; Token-2022 checks it when the vault's account is configured.
    #[account(owner = TOKEN_2022)]
    pub mint: UncheckedAccount<'info>,
    #[account(init, payer = operator, space = 8 + Vault::INIT_SPACE, seeds = [b"vault", mint.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Configure<'info> {
    /// Pays for the larger token account.
    #[account(mut)]
    pub operator: Signer<'info>,
    #[account(has_one = operator, has_one = mint, seeds = [b"vault", mint.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: the vault's mint (has_one above).
    pub mint: UncheckedAccount<'info>,
    /// CHECK: a token account owned by the vault; Token-2022 checks the owner.
    #[account(mut)]
    pub vault_token: UncheckedAccount<'info>,
    /// CHECK: a proof account of the ZK ElGamal Proof Program; Token-2022 checks it.
    pub pubkey_validity_proof: UncheckedAccount<'info>,
    /// CHECK: Token-2022.
    #[account(address = TOKEN_2022)]
    pub token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ApplyPending<'info> {
    pub operator: Signer<'info>,
    #[account(has_one = operator)]
    pub vault: Account<'info, Vault>,
    /// CHECK: a token account owned by the vault; Token-2022 checks the owner.
    #[account(mut)]
    pub vault_token: UncheckedAccount<'info>,
    /// CHECK: Token-2022.
    #[account(address = TOKEN_2022)]
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Pay<'info> {
    pub operator: Signer<'info>,
    #[account(has_one = operator, has_one = mint)]
    pub vault: Account<'info, Vault>,
    /// CHECK: the vault's mint (has_one above).
    pub mint: UncheckedAccount<'info>,
    /// CHECK: a token account owned by the vault; Token-2022 checks the owner.
    #[account(mut)]
    pub vault_token: UncheckedAccount<'info>,
    /// CHECK: any confidential token account of the mint; Token-2022 checks it.
    #[account(mut)]
    pub destination_token: UncheckedAccount<'info>,
    /// CHECK: proof accounts of the ZK ElGamal Proof Program; Token-2022 checks them.
    pub equality_proof: UncheckedAccount<'info>,
    /// CHECK: as above.
    pub ciphertext_validity_proof: UncheckedAccount<'info>,
    /// CHECK: as above.
    pub range_proof: UncheckedAccount<'info>,
    /// CHECK: Token-2022.
    #[account(address = TOKEN_2022)]
    pub token_program: UncheckedAccount<'info>,
}

/// Token-2022 confidential-transfer instructions, built from their byte layout (Token-2022 v8 and
/// later; the transfer carries the amount encrypted to the auditor). Proofs are always in proof
/// accounts here, so every proof offset is 0.
pub mod token_2022 {
    use super::*;

    const CONFIDENTIAL_TRANSFER_EXTENSION: u8 = 27;
    const CONFIGURE_ACCOUNT: u8 = 2;
    const TRANSFER: u8 = 7;
    const APPLY_PENDING_BALANCE: u8 = 8;
    const REALLOCATE: u8 = 29;
    const CONFIDENTIAL_TRANSFER_ACCOUNT_EXTENSION: u16 = 5;
    const DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER: u64 = 65536;

    pub fn reallocate_for_confidential_transfers(
        account: &Pubkey,
        payer: &Pubkey,
        owner: &Pubkey,
    ) -> Instruction {
        let mut data = vec![REALLOCATE];
        data.extend_from_slice(&CONFIDENTIAL_TRANSFER_ACCOUNT_EXTENSION.to_le_bytes());
        Instruction {
            program_id: TOKEN_2022,
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new(*payer, true),
                AccountMeta::new_readonly(anchor_lang::system_program::ID, false),
                AccountMeta::new_readonly(*owner, true),
            ],
            data,
        }
    }

    pub fn configure_account(
        account: &Pubkey,
        mint: &Pubkey,
        pubkey_validity_proof: &Pubkey,
        owner: &Pubkey,
        decryptable_zero_balance: &[u8; 36],
    ) -> Instruction {
        let mut data = vec![CONFIDENTIAL_TRANSFER_EXTENSION, CONFIGURE_ACCOUNT];
        data.extend_from_slice(decryptable_zero_balance);
        data.extend_from_slice(&DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER.to_le_bytes());
        data.push(0); // proof in a proof account
        Instruction {
            program_id: TOKEN_2022,
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(*pubkey_validity_proof, false),
                AccountMeta::new_readonly(*owner, true),
            ],
            data,
        }
    }

    pub fn apply_pending_balance(
        account: &Pubkey,
        owner: &Pubkey,
        expected_pending_balance_credit_counter: u64,
        new_decryptable_available_balance: &[u8; 36],
    ) -> Instruction {
        let mut data = vec![CONFIDENTIAL_TRANSFER_EXTENSION, APPLY_PENDING_BALANCE];
        data.extend_from_slice(&expected_pending_balance_credit_counter.to_le_bytes());
        data.extend_from_slice(new_decryptable_available_balance);
        Instruction {
            program_id: TOKEN_2022,
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new_readonly(*owner, true),
            ],
            data,
        }
    }

    /// `proofs`: equality, ciphertext validity, range.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer(
        source: &Pubkey,
        mint: &Pubkey,
        destination: &Pubkey,
        proofs: [&Pubkey; 3],
        owner: &Pubkey,
        new_decryptable_available_balance: &[u8; 36],
        auditor_ciphertext_lo: &[u8; 64],
        auditor_ciphertext_hi: &[u8; 64],
    ) -> Instruction {
        let mut data = vec![CONFIDENTIAL_TRANSFER_EXTENSION, TRANSFER];
        data.extend_from_slice(new_decryptable_available_balance);
        data.extend_from_slice(auditor_ciphertext_lo);
        data.extend_from_slice(auditor_ciphertext_hi);
        data.extend_from_slice(&[0, 0, 0]); // all three proofs in proof accounts
        let mut accounts = vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
        ];
        accounts.extend(proofs.iter().map(|p| AccountMeta::new_readonly(**p, false)));
        accounts.push(AccountMeta::new_readonly(*owner, true));
        Instruction {
            program_id: TOKEN_2022,
            accounts,
            data,
        }
    }
}
