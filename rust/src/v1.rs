// SPDX-License-Identifier: BUSL-1.1
//! Version-1 transactions (SIMD-0385): up to 4,096 bytes, with the compute budget in the message
//! itself. They let a confidential transfer or withdraw carry its zero-knowledge proofs in the
//! same transaction, instead of verifying them into proof accounts first.
//!
//! The Solana client crates this crate pins predate them, so the message is compiled and
//! serialized with `solana-message` 6, signed as bytes and sent as base64. On the wire the
//! message comes first (it starts with the version byte, 0x81) and the signatures follow it, one
//! for each required signer and without a length prefix.
use solana_message::{v1, VersionedMessage};
use solana_sdk::{hash::Hash, instruction::Instruction, pubkey::Pubkey};

/// Largest v1 transaction on the wire.
pub(crate) const MAX_TRANSACTION_SIZE: usize = v1::MAX_TRANSACTION_SIZE;

/// The most accounts a transaction may lock; a message that names more is refused when it runs.
pub(crate) const MAX_ACCOUNTS: usize = 64;

/// The most compute units a transaction may ask for.
pub(crate) const MAX_COMPUTE_UNITS: u32 = 1_400_000;

/// The most account data a transaction may load (64 MiB).
pub(crate) const MAX_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

/// The compute budget of a v1 message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Budget {
    pub compute_unit_limit: u32,
    pub loaded_accounts_data_size_limit: u32,
    /// Total priority fee in lamports (v1 states the fee, not a price per compute unit).
    pub priority_fee: Option<u64>,
}

impl Budget {
    /// The largest budget, for a first simulation. `with_fee` reserves the room a priority fee
    /// takes in the message, so the size checked now is the size sent later.
    pub fn max(with_fee: bool) -> Self {
        Self {
            compute_unit_limit: MAX_COMPUTE_UNITS,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE,
            priority_fee: with_fee.then_some(0),
        }
    }

    /// The budget for the transaction that is sent: the simulation's figures with room for the
    /// account state to change a little before it runs (20% more compute, 10% more data), and
    /// the priority fee for `compute_unit_price` micro-lamports per unit, rounded up.
    pub fn from_simulation(
        units_consumed: Option<u64>,
        loaded_accounts_data_size: Option<u32>,
        compute_unit_price: Option<u64>,
    ) -> Self {
        let units = units_consumed
            .map(|u| u.saturating_mul(12).div_ceil(10))
            .unwrap_or(u64::from(MAX_COMPUTE_UNITS))
            .min(u64::from(MAX_COMPUTE_UNITS)) as u32;
        let loaded = loaded_accounts_data_size
            .map(|l| u64::from(l).saturating_mul(11).div_ceil(10))
            .unwrap_or(u64::from(MAX_LOADED_ACCOUNTS_DATA_SIZE))
            .min(u64::from(MAX_LOADED_ACCOUNTS_DATA_SIZE)) as u32;
        let priority_fee = compute_unit_price.filter(|p| *p > 0).map(|price| {
            (u128::from(price) * u128::from(units))
                .div_ceil(1_000_000)
                .min(u128::from(u64::MAX)) as u64
        });
        Self {
            compute_unit_limit: units,
            loaded_accounts_data_size_limit: loaded,
            priority_fee,
        }
    }

    fn config(&self) -> v1::TransactionConfig {
        let config = v1::TransactionConfig::empty()
            .with_compute_unit_limit(self.compute_unit_limit)
            .with_loaded_accounts_data_size_limit(self.loaded_accounts_data_size_limit);
        match self.priority_fee {
            Some(fee) => config.with_priority_fee(fee),
            None => config,
        }
    }
}

/// A compiled v1 message: its bytes (what the signers sign) and the keys that must sign it, in
/// the order their signatures go on the wire. The fee payer is the first.
#[derive(Clone, Debug)]
pub(crate) struct CompiledMessage {
    pub bytes: Vec<u8>,
    pub signers: Vec<Pubkey>,
    /// How many accounts the message names, programs included.
    pub accounts: usize,
}

impl CompiledMessage {
    /// The size of the signed transaction on the wire.
    pub fn transaction_size(&self) -> usize {
        self.bytes.len() + v1::SIGNATURE_SIZE * self.signers.len()
    }

    /// True if the transaction is small enough to send: at most 4,096 bytes and 64 accounts.
    pub fn fits(&self) -> bool {
        self.transaction_size() <= MAX_TRANSACTION_SIZE && self.accounts <= MAX_ACCOUNTS
    }

    /// The transaction on the wire: the message, then the signatures in signer order.
    pub fn wire(&self, signatures: &[[u8; 64]]) -> Vec<u8> {
        debug_assert_eq!(signatures.len(), self.signers.len());
        let mut wire = Vec::with_capacity(self.transaction_size());
        wire.extend_from_slice(&self.bytes);
        for signature in signatures {
            wire.extend_from_slice(signature);
        }
        wire
    }
}

/// Compile `instructions` into a v1 message paid by `payer`. `None` when they cannot be one (more
/// accounts than a message can name).
pub(crate) fn compile(
    payer: &Pubkey,
    instructions: &[Instruction],
    blockhash: &Hash,
    budget: Budget,
) -> Option<CompiledMessage> {
    let instructions: Vec<solana_message::Instruction> = instructions.iter().map(convert).collect();
    let message = v1::Message::try_compile_with_config(
        &address(payer),
        &instructions,
        solana_message::Hash::new_from_array(blockhash.to_bytes()),
        budget.config(),
    )
    .ok()?;
    let accounts = message.account_keys.len();
    let signers = message.account_keys[..usize::from(message.header.num_required_signatures)]
        .iter()
        .map(|key| Pubkey::new_from_array(key.to_bytes()))
        .collect();
    let bytes = VersionedMessage::V1(message).serialize();
    Some(CompiledMessage {
        bytes,
        signers,
        accounts,
    })
}

fn address(key: &Pubkey) -> solana_message::Address {
    solana_message::Address::new_from_array(key.to_bytes())
}

fn convert(instruction: &Instruction) -> solana_message::Instruction {
    solana_message::Instruction {
        program_id: address(&instruction.program_id),
        accounts: instruction
            .accounts
            .iter()
            .map(|meta| solana_message::AccountMeta {
                pubkey: address(&meta.pubkey),
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            })
            .collect(),
        data: instruction.data.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::{
        instruction::AccountMeta,
        signature::{Keypair, Signer},
    };

    fn sample(payer: &Pubkey, owner: &Pubkey) -> Vec<Instruction> {
        let program = Pubkey::new_unique();
        vec![
            Instruction::new_with_bytes(
                program,
                &[1, 2, 3],
                vec![
                    AccountMeta::new(Pubkey::new_unique(), false),
                    AccountMeta::new_readonly(*owner, true),
                ],
            ),
            Instruction::new_with_bytes(
                program,
                &[4; 300],
                vec![AccountMeta::new_readonly(*payer, false)],
            ),
        ]
    }

    #[test]
    fn a_message_starts_with_the_v1_version_byte_and_lists_its_signers_payer_first() {
        let (payer, owner) = (Keypair::new(), Keypair::new());
        let message = compile(
            &payer.pubkey(),
            &sample(&payer.pubkey(), &owner.pubkey()),
            &Hash::new_unique(),
            Budget::max(false),
        )
        .unwrap();
        assert_eq!(message.bytes[0], 0x81);
        assert_eq!(message.signers, vec![payer.pubkey(), owner.pubkey()]);
        assert!(message.fits());
    }

    #[test]
    fn the_wire_is_the_message_then_the_signatures_and_decodes_as_a_v1_transaction() {
        let (payer, owner) = (Keypair::new(), Keypair::new());
        let blockhash = Hash::new_unique();
        let instructions = sample(&payer.pubkey(), &owner.pubkey());
        let message = compile(
            &payer.pubkey(),
            &instructions,
            &blockhash,
            Budget {
                compute_unit_limit: 300_000,
                loaded_accounts_data_size_limit: 100_000,
                priority_fee: Some(5_000),
            },
        )
        .unwrap();
        let signatures: Vec<[u8; 64]> = [&payer, &owner]
            .iter()
            .map(|k| k.sign_message(&message.bytes).into())
            .collect();
        let wire = message.wire(&signatures);
        assert_eq!(wire.len(), message.transaction_size());

        // Read back with the same crate: the message, its budget and its instructions.
        let decoded: VersionedMessage = wincode::deserialize(&wire[..message.bytes.len()]).unwrap();
        let VersionedMessage::V1(v1) = decoded else {
            panic!("not a v1 message")
        };
        assert_eq!(v1.lifetime_specifier.to_bytes(), blockhash.to_bytes());
        assert_eq!(v1.config.compute_unit_limit, Some(300_000));
        assert_eq!(v1.config.loaded_accounts_data_size_limit, Some(100_000));
        assert_eq!(v1.config.priority_fee, Some(5_000));
        assert_eq!(v1.instructions.len(), 2);
        assert_eq!(v1.instructions[1].data, vec![4; 300]);
        // Each signature verifies over the message bytes.
        for (signature, signer) in signatures.iter().zip([&payer, &owner]) {
            assert!(solana_sdk::signature::Signature::from(*signature)
                .verify(&signer.pubkey().to_bytes(), &message.bytes));
        }
    }

    #[test]
    fn a_message_too_big_for_one_transaction_does_not_fit() {
        let payer = Keypair::new();
        let big = Instruction::new_with_bytes(Pubkey::new_unique(), &[0; 4_000], vec![]);
        let message = compile(
            &payer.pubkey(),
            &[big],
            &Hash::new_unique(),
            Budget::max(true),
        )
        .unwrap();
        assert!(!message.fits());
    }

    #[test]
    fn a_message_with_more_than_64_accounts_does_not_fit() {
        let payer = Keypair::new();
        let many = Instruction::new_with_bytes(
            Pubkey::new_unique(),
            &[],
            (0..64)
                .map(|_| AccountMeta::new_readonly(Pubkey::new_unique(), false))
                .collect(),
        );
        let message = compile(
            &payer.pubkey(),
            &[many],
            &Hash::new_unique(),
            Budget::max(false),
        )
        .unwrap();
        assert_eq!(message.accounts, 66, "the payer, the program and 64 others");
        assert!(message.transaction_size() <= MAX_TRANSACTION_SIZE);
        assert!(!message.fits());
    }

    #[test]
    fn the_budget_follows_the_simulation_with_room_and_rounds_the_fee_up() {
        let budget = Budget::from_simulation(Some(100_001), Some(1_000), Some(1_000));
        assert_eq!(budget.compute_unit_limit, 120_002);
        assert_eq!(budget.loaded_accounts_data_size_limit, 1_100);
        // 1,000 micro-lamports per unit for 120,002 units: 120.002 lamports, rounded up.
        assert_eq!(budget.priority_fee, Some(121));
        let capped = Budget::from_simulation(Some(2_000_000), None, None);
        assert_eq!(capped.compute_unit_limit, MAX_COMPUTE_UNITS);
        assert_eq!(
            capped.loaded_accounts_data_size_limit,
            MAX_LOADED_ACCOUNTS_DATA_SIZE
        );
        assert_eq!(capped.priority_fee, None);
    }
}
