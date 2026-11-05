// SPDX-License-Identifier: BUSL-1.1
//! Sending transactions: priority fee where there is room, simulation first (so a failure comes
//! with the program logs), then send and confirm; an expired blockhash is retried when asked.
//!
//! Once a transaction may have reached a node, a failure to read what became of it is not
//! reported as a plain RPC error: the crate keeps asking until the transaction is confirmed or its
//! blockhash has expired, so that it can say whether it landed. Only when that cannot be learned
//! either is the outcome reported as unknown ([`Error::unknown_outcome`]).
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;
use solana_client::{
    client_error::{ClientError, ClientErrorKind},
    nonblocking::rpc_client::RpcClient,
    rpc_config::{CommitmentConfig, RpcSendTransactionConfig, RpcSimulateTransactionConfig},
    rpc_request::{RpcError, RpcRequest},
    rpc_response::{Response, RpcSimulateTransactionResult, TransactionConfirmationStatus},
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::{
    hash::Hash,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    signature::Signature,
    signer::Signer,
    transaction::{Transaction, TransactionError},
};

use crate::error::{redact_rpc_error, Error, ErrorCode, Result};
use crate::v1::{self, Budget, CompiledMessage};

/// Largest transaction on the wire.
const PACKET_DATA_SIZE: usize = 1232;

/// How often to ask whether a sent transaction is confirmed.
pub(crate) const POLL: Duration = Duration::from_millis(500);

/// After an RPC error on a transaction that may have been sent: how long to keep asking what
/// became of it. A blockhash expires after 150 slots, about a minute; this leaves room for an RPC
/// that recovers slowly.
pub(crate) const SETTLE_TIMEOUT: Duration = Duration::from_secs(180);

pub(crate) struct Sender<'a> {
    pub rpc: &'a RpcClient,
    pub payer: &'a (dyn Signer + Sync),
    pub compute_unit_price: Option<u64>,
    pub max_retries: u32,
    pub operation: &'static str,
    /// [`POLL`], shorter in tests.
    pub poll: Duration,
    /// [`SETTLE_TIMEOUT`], shorter in tests.
    pub settle_timeout: Duration,
}

impl Sender<'_> {
    pub fn rpc_error(&self, e: ClientError) -> Error {
        Error::rpc(self.operation, "RPC request failed", e)
    }

    /// Send one transaction of `instructions`, signed by the payer and those of `signers` the
    /// instructions need.
    pub async fn send(
        &self,
        instructions: &[Instruction],
        signers: &[&(dyn Signer + Sync)],
        step: &'static str,
    ) -> Result<Signature> {
        let mut attempt = 0;
        loop {
            match self.send_once(instructions, signers, step).await {
                Err(e)
                    if e.code() == ErrorCode::TransactionExpired && attempt < self.max_retries =>
                {
                    attempt += 1
                }
                other => return other,
            }
        }
    }

    /// Send `instructions` as one v1 transaction (up to 4,096 bytes; see [`crate::v1`]), signed
    /// by the payer and those of `signers` the instructions need, with its compute budget set
    /// from a simulation. `Ok(None)` when they do not fit in one, decided before anything is
    /// signed or sent.
    pub async fn send_single(
        &self,
        instructions: &[Instruction],
        signers: &[&(dyn Signer + Sync)],
        step: &'static str,
    ) -> Result<Option<Signature>> {
        let mut attempt = 0;
        loop {
            match self.send_single_once(instructions, signers, step).await {
                Err(e)
                    if e.code() == ErrorCode::TransactionExpired && attempt < self.max_retries =>
                {
                    attempt += 1
                }
                other => return other,
            }
        }
    }

    async fn send_single_once(
        &self,
        instructions: &[Instruction],
        signers: &[&(dyn Signer + Sync)],
        step: &'static str,
    ) -> Result<Option<Signature>> {
        let payer = self.payer.pubkey();
        let with_fee = self.compute_unit_price.is_some_and(|p| p > 0);
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| self.rpc_error(e))?;
        let Some(draft) = v1::compile(&payer, instructions, &blockhash, Budget::max(with_fee))
        else {
            return Ok(None);
        };
        if !draft.fits() {
            return Ok(None);
        }
        let chosen = self.signers_for(&draft, signers)?;

        // The first simulation, with the largest budget, measures what the transaction uses.
        let unsigned = draft.wire(&vec![[0u8; 64]; draft.signers.len()]);
        let estimate = self.simulate_bytes(&unsigned, step).await?;
        let budget = Budget::from_simulation(
            estimate.units_consumed,
            estimate.loaded_accounts_data_size,
            self.compute_unit_price,
        );
        let Some(message) = v1::compile(&payer, instructions, &blockhash, budget) else {
            return Ok(None);
        };
        if !message.fits() {
            return Ok(None);
        }

        let signatures = chosen
            .iter()
            .map(|signer| {
                signer
                    .try_sign_message(&message.bytes)
                    .map(<[u8; 64]>::from)
                    .map_err(|e| {
                        Error::new(
                            ErrorCode::InvalidInput,
                            self.operation,
                            format!("cannot sign the transaction: {e}"),
                        )
                        .with_source(e)
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let wire = message.wire(&signatures);
        let signature = Signature::from(signatures[0]);

        // As for any transaction: simulated first, so that a failure comes with the logs.
        self.simulate_bytes(&wire, step).await?;
        let sent = self
            .rpc
            .send::<String>(
                RpcRequest::SendTransaction,
                json!([
                    BASE64.encode(&wire),
                    {
                        "encoding": "base64",
                        "preflightCommitment": self.rpc.commitment().commitment,
                    }
                ]),
            )
            .await;
        if let Err(e) = sent {
            if let Some(err) = e.get_transaction_error() {
                let error = self.transaction_error(&err, step, "failed");
                return Err(with_redacted_source(error, e));
            }
            if !may_have_been_sent(&e) {
                return Err(self.rpc_error(e).with_step(step));
            }
            return self.settle(signature, &blockhash, step, e).await.map(Some);
        }
        self.confirm(signature, &blockhash, step).await.map(Some)
    }

    /// The signer for each key that must sign `message`, in order: the payer or one of `signers`.
    fn signers_for<'s>(
        &'s self,
        message: &CompiledMessage,
        signers: &[&'s (dyn Signer + Sync)],
    ) -> Result<Vec<&'s (dyn Signer + Sync)>> {
        message
            .signers
            .iter()
            .map(|key| {
                std::iter::once(self.payer)
                    .chain(signers.iter().copied())
                    .find(|signer| signer.pubkey() == *key)
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::InvalidInput,
                            self.operation,
                            format!("cannot sign the transaction: no signer for {key}"),
                        )
                    })
            })
            .collect()
    }

    /// Simulate a transaction given as bytes (a v1 transaction the pinned client cannot encode),
    /// without checking its signatures. A failure is an error with the program logs.
    async fn simulate_bytes(
        &self,
        wire: &[u8],
        step: &'static str,
    ) -> Result<RpcSimulateTransactionResult> {
        let simulation = self
            .rpc
            .send::<Response<RpcSimulateTransactionResult>>(
                RpcRequest::SimulateTransaction,
                json!([
                    BASE64.encode(wire),
                    {
                        "encoding": "base64",
                        "sigVerify": false,
                        "commitment": self.rpc.commitment().commitment,
                    }
                ]),
            )
            .await
            .map_err(|e| self.rpc_error(e))?
            .value;
        if let Some(err) = simulation.err.clone() {
            let logs = simulation.logs.clone().unwrap_or_default();
            let err = TransactionError::from(err);
            return Err(self
                .transaction_error(&err, step, "failed simulation")
                .with_logs(logs));
        }
        Ok(simulation)
    }

    /// True if the instructions fit in one transaction with these signers.
    pub fn fits(&self, instructions: &[Instruction], signer_count: usize) -> bool {
        let message = Message::new(instructions, Some(&self.payer.pubkey()));
        wire_size(
            &message,
            signer_count.max(usize::from(message.header.num_required_signatures)),
        ) <= PACKET_DATA_SIZE
    }

    async fn send_once(
        &self,
        instructions: &[Instruction],
        signers: &[&(dyn Signer + Sync)],
        step: &'static str,
    ) -> Result<Signature> {
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| self.rpc_error(e))?;
        let transaction = self.build(instructions, signers, blockhash)?;

        let simulation = self
            .rpc
            .simulate_transaction_with_config(
                &transaction,
                RpcSimulateTransactionConfig {
                    sig_verify: false,
                    commitment: Some(self.rpc.commitment()),
                    ..RpcSimulateTransactionConfig::default()
                },
            )
            .await
            .map_err(|e| self.rpc_error(e))?
            .value;
        if let Some(err) = simulation.err {
            let logs = simulation.logs.unwrap_or_default();
            let err = TransactionError::from(err);
            return Err(self
                .transaction_error(&err, step, "failed simulation")
                .with_logs(logs));
        }

        let signature = transaction.signatures[0];
        let sent = self
            .rpc
            .send_transaction_with_config(
                &transaction,
                RpcSendTransactionConfig {
                    preflight_commitment: Some(self.rpc.commitment().commitment),
                    ..RpcSendTransactionConfig::default()
                },
            )
            .await;
        if let Err(e) = sent {
            if let Some(err) = e.get_transaction_error() {
                // Refused in preflight: the node did not take it.
                let error = self.transaction_error(&err, step, "failed");
                return Err(with_redacted_source(error, e));
            }
            if !may_have_been_sent(&e) {
                return Err(self.rpc_error(e).with_step(step));
            }
            // The request may have reached a node, which sends the transaction on.
            return self.settle(signature, &blockhash, step, e).await;
        }
        self.confirm(signature, &blockhash, step).await
    }

    /// Wait until a sent transaction is confirmed, has failed, or its blockhash has expired.
    async fn confirm(
        &self,
        signature: Signature,
        blockhash: &Hash,
        step: &'static str,
    ) -> Result<Signature> {
        let blockhash = *blockhash;
        loop {
            let status = match self
                .rpc
                .get_signature_status_with_commitment(&signature, self.rpc.commitment())
                .await
            {
                Ok(status) => status,
                Err(e) => return self.settle(signature, &blockhash, step, e).await,
            };
            match status {
                Some(Ok(())) => return Ok(signature),
                Some(Err(err)) => return Err(self.transaction_error(&err, step, "failed")),
                None => {}
            }
            match self
                .rpc
                .is_blockhash_valid(&blockhash, CommitmentConfig::processed())
                .await
            {
                Ok(true) => tokio::time::sleep(self.poll).await,
                // No confirmation was seen before the blockhash expired. Usually the transaction
                // never landed, but it can land just before the expiry is noticed, and calling it
                // expired would let a retry send it a second time. Ask first.
                Ok(false) => {
                    let outcome = outcome_after_expiry(self.rpc, &signature).await;
                    return self.conclude(outcome, signature, step, None);
                }
                Err(e) => return self.settle(signature, &blockhash, step, e).await,
            }
        }
    }

    /// The outcome of a transaction that may have been sent, after `error` interrupted sending
    /// or confirming it.
    async fn settle(
        &self,
        signature: Signature,
        blockhash: &Hash,
        step: &'static str,
        error: ClientError,
    ) -> Result<Signature> {
        let outcome = outcome_after_rpc_error(
            self.rpc,
            &signature,
            blockhash,
            self.poll * 4,
            self.settle_timeout,
        )
        .await;
        self.conclude(outcome, signature, step, Some(error))
    }

    /// `outcome` as this call's result. `cause` is the RPC error that left the outcome open, if
    /// one did; otherwise the transaction was simply not seen confirmed in time.
    fn conclude(
        &self,
        outcome: AfterExpiry,
        signature: Signature,
        step: &'static str,
        cause: Option<ClientError>,
    ) -> Result<Signature> {
        let what = self.what(step);
        let (cause_text, source) = match cause {
            Some(e) => {
                let (text, source) = redact_rpc_error(e);
                (Some(text), source)
            }
            None => (None, None),
        };
        let error = match outcome {
            AfterExpiry::Landed => return Ok(signature),
            AfterExpiry::Failed(err) => self.transaction_error(&err, step, "failed"),
            AfterExpiry::NotFound => Error::new(
                ErrorCode::TransactionExpired,
                self.operation,
                match &cause_text {
                    None => format!(
                        "{what} was not confirmed before its blockhash expired, and did not land"
                    ),
                    Some(text) => format!(
                        "{what} could not be confirmed (RPC request failed: {text}); its blockhash \
                         has expired and it did not land"
                    ),
                },
            ),
            AfterExpiry::Unknown => Error::new(
                ErrorCode::TransactionFailed,
                self.operation,
                match &cause_text {
                    None => format!(
                        "{what} was not confirmed before its blockhash expired, and its status \
                         could not be read. Look up {signature} before running the operation again."
                    ),
                    Some(text) => format!(
                        "{what} was sent, but the RPC failed before its outcome could be read \
                         (RPC request failed: {text}), so it may or may not have landed. Look up \
                         {signature} before running the operation again."
                    ),
                },
            )
            .with_unknown_outcome(signature),
        }
        .with_step(step);
        Err(match source {
            Some(source) => error.with_source(source),
            None => error,
        })
    }

    fn what(&self, step: &'static str) -> String {
        if step == self.operation {
            "the transaction".into()
        } else {
            format!("step \"{step}\"")
        }
    }

    fn transaction_error(&self, err: &TransactionError, step: &'static str, verb: &str) -> Error {
        let code = if matches!(err, TransactionError::BlockhashNotFound) {
            ErrorCode::TransactionExpired
        } else {
            ErrorCode::TransactionFailed
        };
        Error::new(
            code,
            self.operation,
            format!("{} {verb}: {err}", self.what(step)),
        )
        .with_step(step)
    }

    fn build(
        &self,
        instructions: &[Instruction],
        signers: &[&(dyn Signer + Sync)],
        blockhash: Hash,
    ) -> Result<Transaction> {
        if let Some(price) = self.compute_unit_price.filter(|p| *p > 0) {
            let mut priced = Vec::with_capacity(instructions.len() + 1);
            priced.push(ComputeBudgetInstruction::set_compute_unit_price(price));
            priced.extend_from_slice(instructions);
            // The range-proof transactions have no room for the fee instruction; they go without.
            if self.fits(&priced, 0) {
                return self.sign(&priced, signers, blockhash);
            }
        }
        self.sign(instructions, signers, blockhash)
    }

    fn sign(
        &self,
        instructions: &[Instruction],
        signers: &[&(dyn Signer + Sync)],
        blockhash: Hash,
    ) -> Result<Transaction> {
        let message = Message::new(instructions, Some(&self.payer.pubkey()));
        let required: Vec<Pubkey> =
            message.account_keys[..usize::from(message.header.num_required_signatures)].to_vec();
        let mut chosen: Vec<&dyn Signer> = Vec::new();
        for signer in std::iter::once(self.payer).chain(signers.iter().copied()) {
            let key = signer.pubkey();
            if required.contains(&key) && !chosen.iter().any(|s| s.pubkey() == key) {
                chosen.push(signer);
            }
        }
        let mut transaction = Transaction::new_unsigned(message);
        transaction.try_sign(&chosen, blockhash).map_err(|e| {
            Error::new(
                ErrorCode::InvalidInput,
                self.operation,
                format!("cannot sign the transaction: {e}"),
            )
            .with_source(e)
        })?;
        Ok(transaction)
    }
}

/// `error` with `e`, the URL taken out, as its source.
fn with_redacted_source(error: Error, e: ClientError) -> Error {
    match redact_rpc_error(e).1 {
        Some(source) => error.with_source(source),
        None => error,
    }
}

/// False when the error of a `sendTransaction` request shows that the transaction did not reach
/// a node: no connection was made, or the node (or a gateway in front of it) answered and refused
/// the request. Otherwise the request may have gone through, and the transaction may land.
fn may_have_been_sent(e: &ClientError) -> bool {
    match e.kind() {
        ClientErrorKind::RpcError(RpcError::RpcResponseError { .. }) => false,
        ClientErrorKind::Reqwest(e) => {
            !(e.is_connect() || e.is_builder() || e.status().is_some_and(|s| s.is_client_error()))
        }
        _ => true,
    }
}

/// What became of a transaction whose blockhash expired before it was seen confirmed.
#[derive(Debug, PartialEq)]
pub(crate) enum AfterExpiry {
    /// It landed without an error.
    Landed,
    /// It landed with this error.
    Failed(TransactionError),
    /// It did not land, and with its blockhash expired it never will.
    NotFound,
    /// Its status could not be read, or it is only processed so far.
    Unknown,
}

pub(crate) async fn outcome_after_expiry(rpc: &RpcClient, signature: &Signature) -> AfterExpiry {
    let status = match rpc.get_signature_statuses_with_history(&[*signature]).await {
        Ok(response) => response.value.into_iter().next().flatten(),
        Err(_) => return AfterExpiry::Unknown,
    };
    match status {
        None => AfterExpiry::NotFound,
        Some(status) => match (status.err, status.confirmation_status) {
            (Some(err), _) => AfterExpiry::Failed(err),
            (None, Some(TransactionConfirmationStatus::Processed)) => AfterExpiry::Unknown,
            (None, _) => AfterExpiry::Landed,
        },
    }
}

/// What became of a transaction that may have been sent, after an RPC error: asks every `poll`
/// until it is seen confirmed, or its blockhash (`blockhash`) has expired and
/// [`outcome_after_expiry`] can tell. `Unknown` if neither could be read within `timeout`.
pub(crate) async fn outcome_after_rpc_error(
    rpc: &RpcClient,
    signature: &Signature,
    blockhash: &Hash,
    poll: Duration,
    timeout: Duration,
) -> AfterExpiry {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(response) = rpc.get_signature_statuses_with_history(&[*signature]).await {
            if let Some(status) = response.value.into_iter().next().flatten() {
                if matches!(
                    status.confirmation_status,
                    Some(TransactionConfirmationStatus::Confirmed)
                        | Some(TransactionConfirmationStatus::Finalized)
                ) {
                    return match status.err {
                        Some(err) => AfterExpiry::Failed(err),
                        None => AfterExpiry::Landed,
                    };
                }
            }
        }
        if let Ok(false) = rpc
            .is_blockhash_valid(blockhash, CommitmentConfig::processed())
            .await
        {
            return outcome_after_expiry(rpc, signature).await;
        }
        if Instant::now() >= deadline {
            return AfterExpiry::Unknown;
        }
        tokio::time::sleep(poll).await;
    }
}

fn wire_size(message: &Message, signatures: usize) -> usize {
    // short_vec length prefix (1 byte below 128 signatures) + signatures + message
    1 + 64 * signatures + message.serialize().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use solana_client::rpc_request::RpcRequest;
    use solana_sdk::signature::Keypair;
    use solana_system_interface::instruction::transfer;

    // The mock RPC answers getSignatureStatuses according to its URL.
    async fn outcome(url: &str) -> AfterExpiry {
        outcome_after_expiry(&RpcClient::new_mock(url.to_string()), &Signature::default()).await
    }

    #[tokio::test]
    async fn an_expired_transaction_that_landed_is_not_called_expired() {
        assert_eq!(outcome("succeeds").await, AfterExpiry::Landed);
        assert_eq!(outcome("sig_not_found").await, AfterExpiry::NotFound);
        assert!(matches!(
            outcome("instruction_error").await,
            AfterExpiry::Failed(TransactionError::InstructionError(0, _))
        ));
        assert_eq!(outcome("fails").await, AfterExpiry::Unknown);
    }

    /// Sends one transfer through a mock RPC whose answers are `url`'s (see
    /// `solana_rpc_client::mock_sender`), except that the first request of each kind in `mocks`
    /// gets the answer given there. A `null` answer is a failed request.
    async fn send_through(url: &str, mocks: Vec<(RpcRequest, Value)>) -> Result<Signature> {
        let rpc = RpcClient::new_mock_with_mocks(url.to_string(), mocks.into_iter().collect());
        let payer = Keypair::new();
        let sender = Sender {
            rpc: &rpc,
            payer: &payer,
            compute_unit_price: None,
            max_retries: 0,
            operation: "transfer",
            poll: Duration::from_millis(1),
            settle_timeout: Duration::from_millis(20),
        };
        sender
            .send(
                &[transfer(&payer.pubkey(), &Pubkey::new_unique(), 1)],
                &[],
                "transfer",
            )
            .await
    }

    fn blockhash_valid(valid: bool) -> Value {
        json!({ "context": { "slot": 1 }, "value": valid })
    }

    #[tokio::test]
    async fn a_transaction_that_landed_is_not_lost_to_an_rpc_error_while_confirming() {
        // The first status request fails; asking again finds the transaction finalized.
        let sent = send_through(
            "succeeds",
            vec![(RpcRequest::GetSignatureStatuses, Value::Null)],
        )
        .await;
        assert!(sent.is_ok(), "{sent:?}");
    }

    #[tokio::test]
    async fn a_transaction_that_did_not_land_is_expired_once_its_blockhash_is() {
        // sendTransaction fails in transit; the blockhash then expires and the transaction is
        // nowhere: safe to send again.
        let e = send_through(
            "sig_not_found",
            vec![
                (RpcRequest::SendTransaction, Value::Null),
                (RpcRequest::IsBlockhashValid, blockhash_valid(false)),
            ],
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::TransactionExpired, "{e}");
        assert!(e.is_retryable());
        assert_eq!(e.unknown_outcome(), None);
    }

    #[tokio::test]
    async fn an_outcome_that_cannot_be_read_is_unknown_and_names_the_transaction() {
        // sendTransaction fails in transit, the transaction is not found, and whether its
        // blockhash expired cannot be read: it may still land.
        let e = send_through(
            "sig_not_found",
            vec![(RpcRequest::SendTransaction, Value::Null)],
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::TransactionFailed, "{e}");
        assert!(!e.is_retryable());
        let signature = e.unknown_outcome().expect("the transaction is named");
        assert!(e.to_string().contains(&signature.to_string()), "{e}");
        assert_eq!(e.step(), Some("transfer"));
    }
}
