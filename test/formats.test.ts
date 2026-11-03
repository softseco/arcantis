// SPDX-License-Identifier: BUSL-1.1
//
// The formats Arcantis writes or depends on (src/formats.ts, docs/formats.md): the key-derivation
// message the cryptography library signs, the versioned JSON auditor report, and the CSV columns.
// No validator needed.
import { ConfidentialKeys } from "@solana/zk-sdk/node";
import { type Address, type Signature } from "@solana/kit";
import { expect } from "chai";

import {
  CONFIDENTIAL_ACTIVITY_FORMAT,
  CONFIDENTIAL_ACTIVITY_VERSION,
  KEY_DERIVATION_SCHEME,
  confidentialActivityToCsv,
  confidentialActivityToJson,
  isConfidentialTransfersError,
  parseConfidentialActivityJson,
  type ConfidentialActivity,
} from "../src/index";
import { checkDerivationMessage } from "../src/keys";

const MINT = "So11111111111111111111111111111111111111112" as Address;
const AUDITOR = "Vote111111111111111111111111111111111111111" as Address;
const A = "11111111111111111111111111111112" as Address;
const B = "SysvarC1ock11111111111111111111111111111111" as Address;
const SIG = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW" as Signature;

const ACTIVITY: ConfidentialActivity[] = [
  {
    signature: SIG, slot: 1234n, blockTime: new Date("2026-10-30T12:00:00Z"), kind: "deposit",
    fromToken: A, fromOwner: B, toToken: A, toOwner: B, amount: 1000n, decrypted: false,
  },
  {
    signature: SIG, slot: 1240n, blockTime: null, kind: "transfer",
    fromToken: A, fromOwner: null, toToken: B, toOwner: null, amount: null, decrypted: false, note: "not encrypted to this auditor key",
  },
  {
    signature: SIG, slot: 1250n, blockTime: new Date("2026-10-30T12:01:00Z"), kind: "transfer",
    fromToken: A, fromOwner: B, toToken: B, toOwner: A, amount: (1n << 48n) - 1n, decrypted: true,
  },
];

function code(run: () => unknown): string | undefined {
  try {
    run();
  } catch (e) {
    return isConfidentialTransfersError(e) ? e.code : "not a ConfidentialTransfersError";
  }
  return undefined;
}

describe("formats: key derivation", () => {
  it("is the message the cryptography library signs", () => {
    expect(Buffer.from(ConfidentialKeys.signerMessage()).toString("utf8")).to.equal(KEY_DERIVATION_SCHEME);
    const seed = Uint8Array.from([7, 8, 9]);
    const seeded = ConfidentialKeys.signerMessageWithSeed(seed);
    expect(Buffer.from(seeded).toString("hex")).to.equal(Buffer.from(KEY_DERIVATION_SCHEME).toString("hex") + "070809");
    expect(checkDerivationMessage(seeded, seed)).to.equal(seeded);
  });

  it("refuses to derive keys from any other message", () => {
    const other = new TextEncoder().encode("solana-conf-bal/v2");
    expect(code(() => checkDerivationMessage(other, new Uint8Array()))).to.equal("UNSUPPORTED_FORMAT");
    // The standard message without the seed it was asked for, or with another seed.
    const standard = ConfidentialKeys.signerMessage();
    expect(code(() => checkDerivationMessage(standard, Uint8Array.from([1])))).to.equal("UNSUPPORTED_FORMAT");
    const seeded = ConfidentialKeys.signerMessageWithSeed(Uint8Array.from([1]));
    expect(code(() => checkDerivationMessage(seeded, Uint8Array.from([2])))).to.equal("UNSUPPORTED_FORMAT");
  });
});

describe("formats: the JSON auditor report", () => {
  const generatedAt = new Date("2026-10-30T13:00:00Z");
  const json = confidentialActivityToJson(ACTIVITY, { mint: MINT, auditorElgamalPubkey: AUDITOR, decimals: 6, generatedAt });

  it("names its format and version, and writes numbers as strings", () => {
    const raw = JSON.parse(json);
    expect(raw.format).to.equal(CONFIDENTIAL_ACTIVITY_FORMAT);
    expect(raw.version).to.equal(CONFIDENTIAL_ACTIVITY_VERSION).and.to.equal(1);
    expect(raw).to.include({ mint: MINT, auditorElgamalPubkey: AUDITOR, decimals: 6, generatedAt: "2026-10-30T13:00:00.000Z" });
    expect(raw.activity[0]).to.deep.equal({
      signature: SIG, slot: "1234", blockTime: "2026-10-30T12:00:00.000Z", kind: "deposit",
      fromToken: A, fromOwner: B, toToken: A, toOwner: B, amount: "1000", decrypted: false,
    });
    expect(raw.activity[2].amount).to.equal("281474976710655");
  });

  it("reads back what it wrote", () => {
    const report = parseConfidentialActivityJson(json);
    expect(report).to.deep.equal({
      format: CONFIDENTIAL_ACTIVITY_FORMAT,
      version: 1,
      mint: MINT,
      auditorElgamalPubkey: AUDITOR,
      decimals: 6,
      generatedAt,
      activity: ACTIVITY,
    });
    const bare = parseConfidentialActivityJson(confidentialActivityToJson([], { mint: MINT }));
    expect(bare).to.include({ auditorElgamalPubkey: null, decimals: null });
    expect(bare.activity).to.deep.equal([]);
  });

  it("refuses another format, and a version written by a newer release", () => {
    const raw = JSON.parse(json);
    expect(code(() => parseConfidentialActivityJson(JSON.stringify({ ...raw, format: "something-else" })))).to.equal("UNSUPPORTED_FORMAT");
    expect(code(() => parseConfidentialActivityJson(JSON.stringify(raw.activity)))).to.equal("UNSUPPORTED_FORMAT");
    expect(code(() => parseConfidentialActivityJson(JSON.stringify({ ...raw, version: 2 })))).to.equal("UNSUPPORTED_FORMAT");
  });

  it("refuses a damaged report", () => {
    const raw = JSON.parse(json);
    const damaged = (change: (r: typeof raw) => void) => {
      const copy = JSON.parse(json);
      change(copy);
      return code(() => parseConfidentialActivityJson(JSON.stringify(copy)));
    };
    expect(code(() => parseConfidentialActivityJson(json.slice(0, -10)))).to.equal("INVALID_INPUT");
    expect(damaged((r) => delete r.version)).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.version = 0))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.mint = "not-an-address"))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.activity = {}))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.activity[0].amount = "-5"))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.activity[0].slot = 1234))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.activity[0].kind = "mint"))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.activity[0].signature = "x"))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.activity[0].blockTime = "yesterday"))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.activity[0].decrypted = "no"))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.decimals = -1))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.decimals = 256))).to.equal("INVALID_INPUT");
    // Only a transfer's amount is encrypted, so only a transfer's can have been decrypted.
    expect(damaged((r) => (r.activity[0].decrypted = true))).to.equal("INVALID_INPUT");
    expect(damaged((r) => (r.activity[1].decrypted = true))).to.equal("INVALID_INPUT"); // no amount
  });

  it("reads the largest decimals and a decrypted transfer with fee", () => {
    const raw = JSON.parse(json);
    raw.decimals = 255;
    raw.activity[2].kind = "transfer-with-fee";
    const report = parseConfidentialActivityJson(JSON.stringify(raw));
    expect(report.decimals).to.equal(255);
    expect(report.activity[2]).to.include({ kind: "transfer-with-fee", decrypted: true });
  });
});

describe("formats: the CSV auditor report", () => {
  it("keeps its columns; new ones are only ever added at the end", () => {
    const [header] = confidentialActivityToCsv(ACTIVITY).split("\r\n");
    expect(header).to.equal("time_utc,slot,signature,kind,from_owner,from_account,to_owner,to_account,amount_base_units,decrypted,note");
    const [withDecimals] = confidentialActivityToCsv(ACTIVITY, { decimals: 6 }).split("\r\n");
    expect(withDecimals).to.equal(
      "time_utc,slot,signature,kind,from_owner,from_account,to_owner,to_account,amount_base_units,amount,decrypted,note",
    );
  });

  it("keeps a field a spreadsheet would run as a formula as text, and numbers as numbers", () => {
    const notes = ['=HYPERLINK("http://x","y")', "+1", "-1", "@SUM(A1)", "\tx", "\rx", "fine = here"];
    const csv = confidentialActivityToCsv(notes.map((note) => ({ ...ACTIVITY[2], note })), { decimals: 6 });
    const rows = csv.split("\r\n").slice(1, -1);
    expect(rows).to.have.length(notes.length);
    const noteOf = (row: string) => row.slice(row.indexOf(",yes,") + 5);
    expect(rows.map(noteOf)).to.deep.equal([
      `"'=HYPERLINK(""http://x"",""y"")"`, // prefixed, then quoted for its quotes and comma
      "'+1",
      "'-1",
      "'@SUM(A1)",
      "'\tx",
      `"'\rx"`, // quoted for its carriage return
      "fine = here",
    ]);
    for (const row of rows) expect(row).to.contain(",281474976710655,281474976.710655,yes,"); // amounts untouched
  });
});
