---
title: Auditors
---

# Reading a mint's confidential transfers as its auditor

A Token-2022 mint with confidential transfers can name an **auditor**: an ElGamal public key in
the mint's configuration. Every confidential transfer of that mint then carries its amount
encrypted three times, for the sender, for the recipient and for the auditor, and Token-2022
refuses a transfer whose auditor copy does not check out. The auditor can read every amount; it
cannot move anyone's tokens.

Since 3.3.0 the SDK turns that into a report: every deposit, confidential transfer and withdraw of
a mint, with the transferred amounts decrypted, as data or as CSV.

## The auditor key

The auditor's ElGamal key comes from a Solana wallet the auditor holds, the same way account keys
come from their owners' wallets, so it never has to be stored:

```ts
import { deriveAuditorElgamalKeypair, getAuditorElgamalPubkey } from "@softseco/arcantis";

const auditorKeypair = await deriveAuditorElgamalKeypair(auditorWallet);
const auditorElgamalPubkey = getAuditorElgamalPubkey(auditorKeypair); // goes into the mint's config
```

The mint's issuer puts `auditorElgamalPubkey` in the mint's confidential-transfer configuration
when creating it. `transfer()` reads it from the mint and encrypts every amount to it.

Use a wallet that does nothing but audit. The auditor key comes from the same signature a wallet
gives any site that reads its confidential balances, so a site the auditor's wallet signs that
message for gets the key to every amount on every mint naming that auditor. Keep the wallet on its
own device or hardware key, and connect it to nothing else.

## The report

```ts
import { listConfidentialActivity, confidentialActivityToCsv } from "@softseco/arcantis";

const activity = await listConfidentialActivity({ rpc, mint, auditorKeypair });
// [{ kind: "transfer", fromOwner, toOwner, amount: 300n, decrypted: true, signature, blockTime, ... }, ...]

const csv = confidentialActivityToCsv(activity, { decimals: 6 });
```

Each entry has the transaction signature, slot and time, the kind (`deposit`, `transfer`,
`withdraw`), the token accounts on both sides and their owners, and the amount in base units.
Deposits and withdraws have their amounts in the clear on chain; transfers are decrypted with the
auditor key (`decrypted: true`). Entries are oldest first.

Options: `since` and `until` (dates) for a period, `maxTransactions` to read only the latest part
of the history, `concurrency` to go easier on a rate-limited RPC.

## Without writing code

```bash
npx @softseco/arcantis audit-report \
  --mint <mint address> --keypair auditor-wallet.json --rpc https://your-endpoint \
  --since 2026-10-01 --until 2026-11-01 --out october.csv
```

`--keypair` is the auditor's Solana wallet file, the JSON array the Solana CLI writes. The CSV has
one row per entry, with the amount both in base units and in tokens.

For records you keep, or hand to another system, `--format json` (or an `--out` name ending in
`.json`) writes the same entries as a JSON report that names its format and version
(`"format": "arcantis.confidential-activity", "version": 1`), with the mint, the auditor key and
the time it was made. `parseConfidentialActivityJson` reads it back, and later releases keep
reading this version; [docs/formats.md](../docs/formats.md) describes it field by field.

## What it does not cover yet

- **Transfers on mints with a transfer fee** (`ConfidentialTransferWithFee`) are listed, without
  the amount.
- **Confidential mint and burn** (the `ConfidentialMintBurn` extension) are not listed.
- **A changed auditor key.** The report checks that the key is the mint's current auditor key.
  For a mint whose key was changed, pass `skipAuditorKeyCheck`: transfers encrypted to the old key
  are then listed without an amount, with a note.
- **Balances.** The report lists movements, not balances. With the full history, an account's
  confidential balance is its deposits and incoming transfers minus its outgoing transfers and
  withdraws.

The report reads the mint's history through `getSignaturesForAddress` and `getTransaction`, so it
needs an RPC that keeps that history for the period you ask for.
