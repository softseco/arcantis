// SPDX-License-Identifier: BUSL-1.1
//! Errors, with the same codes as the TypeScript SDK's `ConfidentialTransfersError`.
//!
//! Every fallible function in this crate returns [`Error`]. Match on [`Error::code`] to react to
//! a specific failure; the message says what went wrong in words, naming the account involved.
//!
//! What an error prints (its message, `Debug` and source) leaves out what should not end up in a
//! log: decrypted balances ([`Error::available_balance`] has the one a caller may need), and the
//! path, query and user info of the RPC URL, where providers put API keys.
use std::fmt;

use solana_client::client_error::{ClientError, ClientErrorKind};
use solana_sdk::{pubkey::Pubkey, signature::Signature};

/// What went wrong. [`ErrorCode::as_str`] gives the TypeScript SDK's code for the same failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// An argument is invalid (zero amount, an account of another mint).
    InvalidInput,
    /// A token account or mint the call needs does not exist.
    AccountNotFound,
    /// The token account has no confidential-transfer extension; run `configure_account` first.
    AccountNotConfigured,
    /// `configure_account` on an account that is already configured.
    AccountAlreadyConfigured,
    /// The account is configured but not approved by the mint's confidential-transfer authority.
    AccountNotApproved,
    /// The recipient's account does not accept confidential transfers.
    RecipientRejectsConfidential,
    /// The account has taken as many incoming deposits and transfers as it allows before its
    /// pending balance is applied. Its owner has to run `apply_pending_balance` first.
    PendingBalanceLimit,
    /// More than the available (or, for a deposit, the public) balance.
    InsufficientFunds,
    /// Above what one deposit or transfer can carry: 2^48 - 1 base units.
    AmountTooLarge,
    /// The keys are not the keys the account is configured with.
    KeysMismatch,
    /// A balance could not be decrypted.
    DecryptionFailed,
    /// The AES copy of the available balance has fallen behind the encrypted balance by more than
    /// can be recovered (2^32 base units or more). Happens when credits arrive during an apply.
    BalanceOutOfSync,
    /// Data in a format or version this release does not know, refused rather than misread: for
    /// example a zk-sdk that would derive keys from a message other than `solana-conf-bal/v1`.
    UnsupportedFormat,
    /// The signer could not sign the key-derivation message.
    CannotSignMessages,
    /// The signer returned a signature that cannot be used to derive keys.
    BadMessageSignature,
    /// A transaction failed in simulation or on chain; [`Error::logs`] has the program logs.
    TransactionFailed,
    /// A transaction was not confirmed before its blockhash expired, and the RPC confirms it did
    /// not land. Safe to retry.
    TransactionExpired,
    /// The RPC request itself failed (network, rate limit, node error). Rust only.
    Rpc,
}

impl ErrorCode {
    /// The code as the TypeScript SDK spells it, e.g. `"PENDING_BALANCE_LIMIT"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::AccountNotFound => "ACCOUNT_NOT_FOUND",
            Self::AccountNotConfigured => "ACCOUNT_NOT_CONFIGURED",
            Self::AccountAlreadyConfigured => "ACCOUNT_ALREADY_CONFIGURED",
            Self::AccountNotApproved => "ACCOUNT_NOT_APPROVED",
            Self::RecipientRejectsConfidential => "RECIPIENT_REJECTS_CONFIDENTIAL",
            Self::PendingBalanceLimit => "PENDING_BALANCE_LIMIT",
            Self::InsufficientFunds => "INSUFFICIENT_FUNDS",
            Self::AmountTooLarge => "AMOUNT_TOO_LARGE",
            Self::KeysMismatch => "KEYS_MISMATCH",
            Self::DecryptionFailed => "DECRYPTION_FAILED",
            Self::BalanceOutOfSync => "BALANCE_OUT_OF_SYNC",
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::CannotSignMessages => "CANNOT_SIGN_MESSAGES",
            Self::BadMessageSignature => "BAD_MESSAGE_SIGNATURE",
            Self::TransactionFailed => "TRANSACTION_FAILED",
            Self::TransactionExpired => "TRANSACTION_EXPIRED",
            Self::Rpc => "RPC_ERROR",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What became of the proof accounts of a transfer or withdraw that failed partway, or of a call
/// to [`crate::ConfidentialClient::close_proof_accounts`].
///
/// When a step fails, the crate closes the proof accounts it created and their rent goes back to
/// the payer. [`crate::ConfidentialClient::recover_proof_accounts`] finds a proof account by its
/// authority, the payer, which an account only has once its proof is verified into it: it finds
/// those in `left_open`, and those in `unknown` that are still open, but not those in
/// `unverified`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProofAccounts {
    /// Closed; their rent is back with the payer.
    pub closed: Vec<Pubkey>,
    /// Still open, with the payer as authority: closing them failed.
    /// [`crate::ConfidentialClient::recover_proof_accounts`] closes them.
    pub left_open: Vec<Pubkey>,
    /// Created but never verified. A range proof is too large to share a transaction with the
    /// creation of its account, so it is verified in a second transaction; when that one did not
    /// land, the account is left with no authority. The payer cannot close it and recovery does
    /// not find it; its rent (about 0.003 SOL) stays in it.
    pub unverified: Vec<Pubkey>,
    /// Not closed because the outcome of a transaction that creates, uses or closes them is
    /// unknown ([`Error::unknown_outcome`]): each may be open or already gone. Once that
    /// transaction has been looked up, `recover_proof_accounts` closes those still open with the
    /// payer as authority.
    pub unknown: Vec<Pubkey>,
}

type Source = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The crate's error: a [`ErrorCode`], a message, and what is known about the failure.
pub struct Error(Box<Inner>);

struct Inner {
    code: ErrorCode,
    message: String,
    operation: &'static str,
    step: Option<&'static str>,
    logs: Vec<String>,
    signatures: Vec<Signature>,
    proof_accounts: Option<ProofAccounts>,
    unknown_outcome: Option<Signature>,
    available_balance: Option<u64>,
    retryable: bool,
    source: Option<Source>,
}

/// `Result` with this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn new(
        code: ErrorCode,
        operation: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self(Box::new(Inner {
            code,
            message: format!("{operation}: {}", message.into()),
            operation,
            step: None,
            logs: Vec::new(),
            signatures: Vec::new(),
            proof_accounts: None,
            unknown_outcome: None,
            available_balance: None,
            retryable: code == ErrorCode::TransactionExpired,
            source: None,
        }))
    }

    /// An RPC request that failed, `context` saying what it was for. The text and the source keep
    /// nothing of the RPC URL but its scheme and host (see [`redact_rpc_error`]).
    pub(crate) fn rpc(operation: &'static str, context: &str, e: ClientError) -> Self {
        let (text, source) = redact_rpc_error(e);
        let error = Self::new(ErrorCode::Rpc, operation, format!("{context}: {text}"));
        match source {
            Some(source) => error.with_source(source),
            None => error,
        }
    }

    pub(crate) fn with_unknown_outcome(mut self, signature: Signature) -> Self {
        self.0.unknown_outcome = Some(signature);
        self
    }

    pub(crate) fn with_available_balance(mut self, balance: u64) -> Self {
        self.0.available_balance = Some(balance);
        self
    }

    pub(crate) fn with_step(mut self, step: &'static str) -> Self {
        self.0.step = Some(step);
        self
    }

    pub(crate) fn with_logs(mut self, logs: Vec<String>) -> Self {
        self.0.logs = logs;
        self
    }

    pub(crate) fn with_signatures(mut self, signatures: Vec<Signature>) -> Self {
        self.0.signatures = signatures;
        self
    }

    pub(crate) fn with_proof_accounts(mut self, proof_accounts: ProofAccounts) -> Self {
        self.0.proof_accounts = Some(proof_accounts);
        self
    }

    pub(crate) fn with_source(mut self, source: impl Into<Source>) -> Self {
        self.0.source = Some(source.into());
        self
    }

    /// The same error, reported as part of another operation (its message keeps the details).
    pub(crate) fn within(self, operation: &'static str) -> Self {
        let mut inner = self.0;
        let detail = inner
            .message
            .split_once(": ")
            .map_or(inner.message.clone(), |(_, rest)| rest.to_string());
        inner.message = format!("{operation}: {detail}");
        inner.operation = operation;
        Self(inner)
    }

    /// What went wrong.
    pub fn code(&self) -> ErrorCode {
        self.0.code
    }

    /// The crate function that failed, e.g. `"transfer"`.
    pub fn operation(&self) -> &'static str {
        self.0.operation
    }

    /// For a transfer or withdraw: `"proofs"` (setting up the proof accounts) or the main step.
    pub fn step(&self) -> Option<&'static str> {
        self.0.step
    }

    /// Program logs of the failed transaction, when there are any.
    pub fn logs(&self) -> &[String] {
        &self.0.logs
    }

    /// Transactions of this call that did land before the failure.
    pub fn signatures(&self) -> &[Signature] {
        &self.0.signatures
    }

    /// For a transfer or withdraw that failed partway: what became of its proof accounts.
    pub fn proof_accounts(&self) -> Option<&ProofAccounts> {
        self.0.proof_accounts.as_ref()
    }

    /// A transaction this call sent whose outcome could not be learned: the RPC failed, or kept
    /// failing, before the transaction was seen confirmed or its blockhash expired. It may have
    /// landed. Look it up before running the call again, which could otherwise do the same thing
    /// twice. The code is then [`ErrorCode::TransactionFailed`], and the message names it too.
    pub fn unknown_outcome(&self) -> Option<Signature> {
        self.0.unknown_outcome
    }

    /// For [`ErrorCode::InsufficientFunds`] from a transfer or withdraw: the available
    /// confidential balance, as the owner's keys decrypt it. It is kept out of the message and of
    /// `Debug`, so that logging the error does not log a confidential balance.
    pub fn available_balance(&self) -> Option<u64> {
        self.0.available_balance
    }

    /// True when running the same call again can succeed as is (an expired blockhash).
    pub fn is_retryable(&self) -> bool {
        self.0.retryable
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = &self.0;
        f.debug_struct("Error")
            .field("code", &inner.code)
            .field("message", &inner.message)
            .field("operation", &inner.operation)
            .field("step", &inner.step)
            .field("logs", &inner.logs)
            .field("signatures", &inner.signatures)
            .field("proof_accounts", &inner.proof_accounts)
            .field("unknown_outcome", &inner.unknown_outcome)
            // The balance is confidential: say there is one, not what it is.
            .field(
                "available_balance",
                &inner.available_balance.map(|_| "<hidden>"),
            )
            .field("retryable", &inner.retryable)
            .field("source", &inner.source)
            .finish()
    }
}

/// `e` with the RPC URL taken out, as text and as a source to keep.
///
/// reqwest names the URL in its errors ("for url (…)", and in `Debug`), and RPC providers put API
/// keys in its query or path. The URL is dropped from reqwest's error, and any URL left in the
/// text is cut down to its scheme and host ([`redact_urls`]). The error is returned as a source
/// only if nothing in its `Debug` still needs cutting.
pub(crate) fn redact_rpc_error(e: ClientError) -> (String, Option<ClientError>) {
    let e = without_url(e);
    let text = redact_urls(&e.to_string());
    let debug = format!("{e:?}");
    let source = (redact_urls(&debug) == debug).then_some(e);
    (text, source)
}

/// `e` without the URL reqwest attaches to its errors. A middleware error is only text; the URLs
/// in it are cut down.
pub(crate) fn without_url(e: ClientError) -> ClientError {
    let ClientError { request, kind } = e;
    let kind = match *kind {
        ClientErrorKind::Reqwest(e) => ClientErrorKind::Reqwest(e.without_url()),
        ClientErrorKind::Middleware(e) => ClientErrorKind::Middleware(
            std::io::Error::other(redact_urls(&format!("{e:#}"))).into(),
        ),
        kind => kind,
    };
    ClientError {
        request,
        kind: Box::new(kind),
    }
}

/// `text` with every URL in it (`scheme://…`) cut down to its scheme and host: user info, path,
/// query and fragment are replaced by `/[redacted]`. A URL ends at a space, a quote, `<`, `>`,
/// a backtick or a parenthesis.
pub(crate) fn redact_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let start = at + 3;
        let end = rest[start..]
            .find(|c: char| c.is_whitespace() || "\"'<>`()".contains(c))
            .map_or(rest.len(), |i| start + i);
        let authority_end = rest[start..end]
            .find(['/', '?', '#'])
            .map_or(end, |i| start + i);
        let authority = &rest[start..authority_end];
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let after_host = &rest[authority_end..end];
        out.push_str(&rest[..start]);
        out.push_str(host);
        if host.len() < authority.len() || !(after_host.is_empty() || after_host == "/") {
            out.push_str("/[redacted]");
        } else {
            out.push_str(after_host);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.message)?;
        if let Some(last) = self
            .0
            .logs
            .iter()
            .rev()
            .find(|l| l.contains("failed") || l.contains("Error"))
        {
            write!(f, " (last log: {last})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spells_codes_like_the_typescript_sdk() {
        assert_eq!(
            ErrorCode::PendingBalanceLimit.as_str(),
            "PENDING_BALANCE_LIMIT"
        );
        assert_eq!(
            ErrorCode::RecipientRejectsConfidential.to_string(),
            "RECIPIENT_REJECTS_CONFIDENTIAL"
        );
    }

    #[test]
    fn names_the_operation_and_marks_expiry_as_retryable() {
        let e = Error::new(
            ErrorCode::TransactionExpired,
            "transfer",
            "blockhash expired",
        );
        assert_eq!(e.to_string(), "transfer: blockhash expired");
        assert!(e.is_retryable());
        assert!(!Error::new(ErrorCode::TransactionFailed, "deposit", "x").is_retryable());
    }

    #[test]
    fn keeps_a_decrypted_balance_out_of_what_it_prints() {
        let e = Error::new(
            ErrorCode::InsufficientFunds,
            "transfer",
            "the available confidential balance is less than the amount",
        )
        .with_available_balance(987_654_321);
        assert_eq!(e.available_balance(), Some(987_654_321));
        assert!(!e.to_string().contains("987654321"));
        assert!(!format!("{e:?}").contains("987654321"), "{e:?}");
        assert!(format!("{e:?}").contains("<hidden>"));
    }

    #[test]
    fn cuts_urls_down_to_scheme_and_host() {
        assert_eq!(
            redact_urls("error sending request for url (http://127.0.0.1:9/?api-key=SECRET)"),
            "error sending request for url (http://127.0.0.1:9/[redacted])"
        );
        assert_eq!(
            redact_urls("at https://user:pw@rpc.example.com/v2/KEY#x then \"wss://h:1/KEY\""),
            "at https://rpc.example.com/[redacted] then \"wss://h:1/[redacted]\""
        );
        assert_eq!(redact_urls("http://user:pw@host"), "http://host/[redacted]");
        assert_eq!(
            redact_urls("https://api.mainnet-beta.solana.com/ and http://[::1]:8899"),
            "https://api.mainnet-beta.solana.com/ and http://[::1]:8899"
        );
        assert_eq!(redact_urls("no url here"), "no url here");
    }
}
