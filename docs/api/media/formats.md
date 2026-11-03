# Arcantis: formats and versions

Every piece of encrypted or exported data Arcantis touches, who defines its format, how a reader
tells which format and version it has in front of it, and what happens when one of them changes.
Written on 30 October 2026 for Arcantis 1.0. The names and versions are also constants in the code:
`src/formats.ts` (`KEY_DERIVATION_SCHEME`, `CONFIDENTIAL_ACTIVITY_FORMAT`,
`CONFIDENTIAL_ACTIVITY_VERSION`) and `KEY_DERIVATION_SCHEME` in the Rust crate.

## Who defines what

Most of the encrypted data is not Arcantis's to define. Balances, amounts and proofs live in
Token-2022 accounts and instructions and in the ZK ElGamal Proof Program, in layouts those programs
fix. Arcantis builds and reads them; it cannot add a version byte to them, and does not need to,
because the programs identify them already.

| Data | Defined by | Shape | Identified by |
|---|---|---|---|
| An account's ElGamal public key | Token-2022 (`ConfidentialTransferAccount` extension) | 32 bytes, a ristretto255 point | the extension type |
| Available balance, pending balance (low and high parts) | Token-2022, same extension | twisted ElGamal ciphertexts, 64 bytes each: a Pedersen commitment and a decrypt handle | the extension type |
| The owner's copy of the available balance (`decryptableAvailableBalance`) | Token-2022, same extension | AES-128-GCM-SIV, 36 bytes: 12-byte nonce, 8-byte amount, 16-byte tag | the extension type |
| A mint's auditor key | Token-2022 (`ConfidentialTransferMint` extension) | 32 bytes, or none | the extension type |
| A transfer's amount | Token-2022 `Transfer` instruction and its proofs | low 16 and high 32 bits apart, as grouped ciphertexts with three handles (source, destination, auditor) in the validity proof; the auditor's ElGamal ciphertexts also in the instruction data | the instruction discriminators |
| Proofs | ZK ElGamal Proof Program | context-state accounts: ciphertext-commitment equality, batched grouped-ciphertext validity, batched range proofs | the proof type in each account |
| The keys | the standard derivation shared by the Solana zk-sdk, Token-2022's clients and wallets | a wallet's Ed25519 signature over `solana-conf-bal/v1` (then a public seed, for the seed-scoped keys), expanded with HKDF-SHA512 into a 32-byte ElGamal secret key and a 16-byte AES key | the message, which carries the version |
| The auditor report as JSON | Arcantis | `{"format": "arcantis.confidential-activity", "version": 1, ...}` | its `format` and `version` fields |
| The auditor report as CSV | Arcantis | one header row, then one row per entry | its header row |

The shared test vectors (`test-vectors/confidential-transfers.json`) pin the bytes of the key
derivation, the program-wallet seed, an auditor's amount and an AES balance. The TypeScript and Rust
tests both check them, so a dependency that changed any of those bytes would fail the tests before
it reached a release.

## Rules

1. **A format is recognised by what it carries, never guessed.** Token-2022 data by its extension
   type or instruction discriminator, a proof by its type, the keys by the derivation message, an
   Arcantis report by its `format` and `version`. Nothing is read as one format because it has the
   right length.
2. **What a release does not know is refused, not misread.** A JSON report in another format, or in
   a version written by a newer release, is refused by `parseConfidentialActivityJson` with
   `UNSUPPORTED_FORMAT`. Key derivation is refused with the same code if the installed zk-sdk would
   sign anything other than `solana-conf-bal/v1` (followed by the seed): such a library would give
   the wallet keys that match none of its accounts. An account without the
   `ConfidentialTransferAccount` extension is `ACCOUNT_NOT_CONFIGURED`.
3. **Writing uses the newest version; reading keeps every older one.** A release that brings
   version 2 of the JSON report writes version 2 and still reads version 1. A reader for a version
   is never removed while a supported release writes it.
4. **A change of keys is a new scheme, next to the old one.** A different derivation would sign a
   different message and give different keys, so it gets a new scheme name and the current one stays
   available for as long as accounts configured with it exist. Which keys an account uses is on
   chain: its ElGamal public key. Arcantis compares the keys it derived with that key before every
   proof and decryption (`KEYS_MISMATCH`), so with two schemes it can tell which one an account was
   configured with. Moving an account to new keys means withdrawing its confidential balance and
   configuring a new account with them.
5. **New cryptography in Token-2022 comes as new types, beside the old ones.** Token-2022 and the
   ZK ElGamal Proof Program identify their data by extension type, instruction and proof type (rule
   1). When they add a new kind, Arcantis adds it as a separate path and keeps the current one, so
   mints and accounts set up today keep working; the issuer chooses what a new mint uses.
6. **CSV columns are only ever added at the end.** The header row is version 1 today:
   `time_utc,slot,signature,kind,from_owner,from_account,to_owner,to_account,amount_base_units`,
   then `amount` when the mint's decimals are known, then `decrypted,note`. A test pins it, so a
   change to it is deliberate and recorded in the changelog.

## The JSON auditor report, version 1

Written by `confidentialActivityToJson` and by `arcantis audit-report --format json` (or `--out`
with a `.json` name); read by `parseConfidentialActivityJson`.

```json
{
  "format": "arcantis.confidential-activity",
  "version": 1,
  "mint": "<mint address>",
  "auditorElgamalPubkey": "<the auditor key the amounts were decrypted with, or null>",
  "decimals": 6,
  "generatedAt": "2026-10-30T13:00:00.000Z",
  "activity": [
    {
      "signature": "<transaction signature>",
      "slot": "312345678",
      "blockTime": "2026-10-30T12:00:00.000Z",
      "kind": "transfer",
      "fromToken": "<token account>",
      "fromOwner": "<owner, or null>",
      "toToken": "<token account>",
      "toOwner": "<owner, or null>",
      "amount": "300",
      "decrypted": true
    }
  ]
}
```

- `kind` is `deposit`, `transfer`, `withdraw` or `transfer-with-fee`.
- `slot` and `amount` are decimal strings, so that no reader rounds them; `amount` is in base units
  and `null` when it could not be decrypted, with the reason in `note`.
- Times are ISO 8601 in UTC; `blockTime` is `null` when the RPC did not know it.
- `decimals` and `auditorElgamalPubkey` are `null` when the writer did not give them.

## Versions in Arcantis 1.0

| Format | Version |
|---|---|
| Key derivation | `solana-conf-bal/v1` |
| JSON auditor report | `arcantis.confidential-activity`, version 1 |
| CSV auditor report | version 1 (the header above) |
