// SPDX-License-Identifier: BUSL-1.1
//! Proof context-state accounts: a transfer or withdraw verifies its zero-knowledge proofs into
//! temporary accounts of the ZK ElGamal Proof Program first (the proofs are too large to travel
//! with the transfer), and closes them afterwards to get their rent back.
use std::mem::size_of;

use bytemuck::Pod;
use solana_sdk::{
    pubkey::Pubkey,
    signature::Signature,
    signer::{keypair::Keypair, Signer},
};
use solana_system_interface::instruction as system_instruction;
use solana_zk_elgamal_proof_interface::{
    instruction::{close_context_state, ContextStateInfo, ProofInstruction},
    proof_data::ZkProofData,
    state::ProofContextState,
};

use crate::error::{Error, ProofAccounts, Result};
use crate::send::Sender;

/// How many close instructions go into one transaction.
const CLOSES_PER_TRANSACTION: usize = 8;

/// Creates proof accounts one after the other and remembers what it created, so that a failure
/// partway can be cleaned up.
pub(crate) struct ProofSetup<'a> {
    sender: &'a Sender<'a>,
    /// Created and verified, with the payer as authority: these can be closed.
    pub verified: Vec<Pubkey>,
    /// Created, but the proof was not verified into them. The authority is written by the
    /// verification, so these have none (all zero): nobody can close them, and
    /// `recover_proof_accounts`, which looks for the payer as authority, does not find them.
    pub unverified: Vec<Pubkey>,
    /// In a transaction whose outcome is unknown: each may exist, verified or not, or not at all.
    pub unknown: Vec<Pubkey>,
    pub signatures: Vec<Signature>,
}

impl<'a> ProofSetup<'a> {
    pub fn new(sender: &'a Sender<'a>) -> Self {
        Self {
            sender,
            verified: Vec::new(),
            unverified: Vec::new(),
            unknown: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// Create a context-state account and verify `proof` into it. `split` sends the account
    /// creation and the verification as two transactions, for the range proofs, which are too
    /// large to share one (see `tests::range_proofs_do_not_fit_with_the_creation_of_their_account`).
    pub async fn create<ZK: Pod + ZkProofData<U>, U: Pod>(
        &mut self,
        instruction: ProofInstruction,
        proof: &ZK,
        split: bool,
    ) -> Result<Pubkey> {
        let payer = self.sender.payer.pubkey();
        let account = Keypair::new();
        let address = account.pubkey();
        let space = size_of::<ProofContextState<U>>();
        let rent = self
            .sender
            .rpc
            .get_minimum_balance_for_rent_exemption(space)
            .await
            .map_err(|e| self.sender.rpc_error(e).with_step("proofs"))?;
        let create = system_instruction::create_account(
            &payer,
            &address,
            rent,
            space as u64,
            &solana_zk_elgamal_proof_interface::id(),
        );
        let verify = instruction.encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &address,
                context_state_authority: &payer,
            }),
            proof,
        );
        if split {
            match self.sender.send(&[create], &[&account], "proofs").await {
                Ok(signature) => self.signatures.push(signature),
                Err(e) => {
                    if e.unknown_outcome().is_some() {
                        self.unknown.push(address);
                    }
                    return Err(e);
                }
            }
            match self.sender.send(&[verify], &[], "proofs").await {
                Ok(signature) => self.signatures.push(signature),
                Err(e) => {
                    if e.unknown_outcome().is_some() {
                        self.unknown.push(address);
                    } else {
                        self.unverified.push(address);
                    }
                    return Err(e);
                }
            }
        } else {
            match self
                .sender
                .send(&[create, verify], &[&account], "proofs")
                .await
            {
                Ok(signature) => self.signatures.push(signature),
                Err(e) => {
                    if e.unknown_outcome().is_some() {
                        self.unknown.push(address);
                    }
                    return Err(e);
                }
            }
        }
        self.verified.push(address);
        Ok(address)
    }

    /// Close what was created and attach the outcome to `error`. The verified accounts can be
    /// closed even when a proof transaction's outcome is unknown: no transaction in flight uses
    /// them, since the transfer or withdraw itself was not sent.
    pub async fn fail(self, error: Error) -> Error {
        let (mut accounts, closing_signatures) =
            close_proof_accounts(self.sender, &self.verified).await;
        accounts.unverified.extend(self.unverified);
        accounts.unknown.extend(self.unknown);
        let mut signatures = self.signatures;
        signatures.extend(closing_signatures);
        error
            .with_proof_accounts(accounts)
            .with_signatures(signatures)
    }
}

/// Close proof accounts whose authority is the sender's payer; their rent goes to the payer.
/// Closes several per transaction, and one by one when a batch fails. A batch whose outcome is
/// unknown is not sent again account by account: those accounts may be closed already.
pub(crate) async fn close_proof_accounts(
    sender: &Sender<'_>,
    accounts: &[Pubkey],
) -> (ProofAccounts, Vec<Signature>) {
    let payer = sender.payer.pubkey();
    let close = |account: &Pubkey| {
        close_context_state(
            ContextStateInfo {
                context_state_account: account,
                context_state_authority: &payer,
            },
            &payer,
        )
    };
    let mut outcome = ProofAccounts::default();
    let mut signatures = Vec::new();
    for batch in accounts.chunks(CLOSES_PER_TRANSACTION) {
        let instructions: Vec<_> = batch.iter().map(close).collect();
        match sender
            .send(&instructions, &[], "close proof accounts")
            .await
        {
            Ok(signature) => {
                signatures.push(signature);
                outcome.closed.extend_from_slice(batch);
            }
            Err(e) if e.unknown_outcome().is_some() => outcome.unknown.extend_from_slice(batch),
            Err(_) if batch.len() > 1 => {
                for account in batch {
                    match sender
                        .send(&[close(account)], &[], "close proof accounts")
                        .await
                    {
                        Ok(signature) => {
                            signatures.push(signature);
                            outcome.closed.push(*account);
                        }
                        Err(e) if e.unknown_outcome().is_some() => outcome.unknown.push(*account),
                        Err(_) => outcome.left_open.push(*account),
                    }
                }
            }
            Err(_) => outcome.left_open.extend_from_slice(batch),
        }
    }
    (outcome, signatures)
}

/// The instructions that close `accounts`, for appending to the transfer's own transaction.
pub(crate) fn close_instructions(
    payer: &Pubkey,
    accounts: &[Pubkey],
) -> Vec<solana_sdk::instruction::Instruction> {
    accounts
        .iter()
        .map(|account| {
            close_context_state(
                ContextStateInfo {
                    context_state_account: account,
                    context_state_authority: payer,
                },
                payer,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytemuck::Zeroable;
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_zk_elgamal_proof_interface::proof_data::{
        BatchedRangeProofU128Data, BatchedRangeProofU64Data, CiphertextCommitmentEqualityProofData,
    };

    use crate::send::{POLL, SETTLE_TIMEOUT};

    /// True if creating a proof account and verifying `proof` into it fit in one transaction.
    fn fits_in_one<ZK: Pod + ZkProofData<U>, U: Pod>(
        sender: &Sender<'_>,
        instruction: ProofInstruction,
        proof: &ZK,
    ) -> bool {
        let payer = sender.payer.pubkey();
        let account = Pubkey::new_unique();
        let create = system_instruction::create_account(
            &payer,
            &account,
            1,
            size_of::<ProofContextState<U>>() as u64,
            &solana_zk_elgamal_proof_interface::id(),
        );
        let verify = instruction.encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &account,
                context_state_authority: &payer,
            }),
            proof,
        );
        sender.fits(&[create, verify], 2)
    }

    /// Why a range-proof account is created and verified in two transactions, and so can be left
    /// unverified (`ProofAccounts::unverified`).
    #[test]
    fn range_proofs_do_not_fit_with_the_creation_of_their_account() {
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let payer = Keypair::new();
        let sender = Sender {
            rpc: &rpc,
            payer: &payer,
            compute_unit_price: None,
            max_retries: 0,
            operation: "test",
            poll: POLL,
            settle_timeout: SETTLE_TIMEOUT,
        };
        assert!(!fits_in_one(
            &sender,
            ProofInstruction::VerifyBatchedRangeProofU128,
            &BatchedRangeProofU128Data::zeroed()
        ));
        assert!(!fits_in_one(
            &sender,
            ProofInstruction::VerifyBatchedRangeProofU64,
            &BatchedRangeProofU64Data::zeroed()
        ));
        assert!(fits_in_one(
            &sender,
            ProofInstruction::VerifyCiphertextCommitmentEquality,
            &CiphertextCommitmentEqualityProofData::zeroed()
        ));
    }
}
