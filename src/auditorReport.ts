// SPDX-License-Identifier: BUSL-1.1
//
// The auditor's view of a mint: every deposit, confidential transfer and withdraw, with the
// amounts of the confidential transfers decrypted with the auditor's ElGamal key.
//
// Deposits and withdraws carry their amount in the clear. A confidential transfer carries it only
// encrypted, three times: for the sender, the recipient, and the mint's auditor. This module reads
// the mint's transaction history, finds those instructions (top-level and inside other programs'
// calls), and decrypts the auditor's copy of each transferred amount.
import {
  getBase58Encoder,
  isAddress,
  isSignature,
  isSome,
  type Address,
  type Rpc,
  type Signature,
  type SolanaRpcApi,
} from "@solana/kit";
import {
  CONFIDENTIAL_DEPOSIT_CONFIDENTIAL_TRANSFER_DISCRIMINATOR,
  CONFIDENTIAL_TRANSFER_CONFIDENTIAL_TRANSFER_DISCRIMINATOR,
  CONFIDENTIAL_TRANSFER_DISCRIMINATOR,
  CONFIDENTIAL_TRANSFER_WITH_FEE_CONFIDENTIAL_TRANSFER_DISCRIMINATOR,
  CONFIDENTIAL_WITHDRAW_CONFIDENTIAL_TRANSFER_DISCRIMINATOR,
  TOKEN_2022_PROGRAM_ADDRESS,
  getConfidentialDepositInstructionDataDecoder,
  getConfidentialTransferInstructionDataDecoder,
  getConfidentialWithdrawInstructionDataDecoder,
} from "@solana-program/token-2022";

import { getAuditorElgamalPubkey } from "./auditor";
import { ConfidentialTransfersError } from "./errors";
import { CONFIDENTIAL_ACTIVITY_FORMAT, CONFIDENTIAL_ACTIVITY_VERSION } from "./formats";
import { readMint } from "./internal/accounts";
import { ElGamalCiphertext, ElGamalKeypair, ensureZk } from "./internal/zk";

const TRANSFER_AMOUNT_LO_BIT_LENGTH = 16n;

export type ConfidentialActivityKind = "deposit" | "transfer" | "withdraw" | "transfer-with-fee";

/** One movement in or out of a confidential balance. */
export type ConfidentialActivity = {
  signature: Signature;
  slot: bigint;
  /** When the block was produced, if the RPC knows. */
  blockTime: Date | null;
  /**
   * `deposit`: public balance → confidential balance of the same account. `withdraw`: the other
   * way. `transfer`: confidential balance of one account → another. `transfer-with-fee`: a
   * transfer on a mint with a transfer fee; listed, but its amount is not decrypted (yet).
   */
  kind: ConfidentialActivityKind;
  fromToken: Address;
  /** Owner of `fromToken` at the time, if the transaction records it. */
  fromOwner: Address | null;
  toToken: Address;
  toOwner: Address | null;
  /** Amount in base units. Null when it could not be decrypted (see `note`). */
  amount: bigint | null;
  /** True when the amount was encrypted on chain and decrypted with the auditor key. */
  decrypted: boolean;
  note?: string;
};

export type ListConfidentialActivityInput = {
  /** RPC client. It must serve `getSignaturesForAddress` and `getTransaction` for the period. */
  rpc: Rpc<SolanaRpcApi>;
  mint: Address;
  /** The mint's auditor keypair, from {@link deriveAuditorElgamalKeypair}. */
  auditorKeypair: ElGamalKeypair;
  /** Only activity at or after this time. */
  since?: Date;
  /** Only activity before this time. */
  until?: Date;
  /**
   * Stop after reading this many of the mint's transactions (newest first): a whole number, 1 or
   * more. Default: all.
   */
  maxTransactions?: number;
  /** How many transactions to fetch at a time: a whole number, 1 or more. Default 4; lower it if the RPC rate-limits. */
  concurrency?: number;
  /**
   * Skip the check that `auditorKeypair` is the mint's current auditor key. Use it for a mint whose
   * auditor key was changed: transfers from before the change are then reported as not decryptable.
   */
  skipAuditorKeyCheck?: boolean;
  programAddress?: Address;
};

type RawInstruction = { programIdIndex: number; accounts?: readonly number[]; data: string };
type RawTransaction = {
  slot: bigint;
  blockTime: bigint | null;
  transaction: { message: { accountKeys: readonly Address[]; instructions: readonly RawInstruction[] } };
  meta: {
    err: unknown;
    innerInstructions?: ReadonlyArray<{ index: number; instructions: readonly RawInstruction[] }> | null;
    loadedAddresses?: { writable: readonly Address[]; readonly: readonly Address[] } | null;
    preTokenBalances?: ReadonlyArray<{ accountIndex: number; owner?: Address }> | null;
  } | null;
};

/**
 * Every deposit, confidential transfer and withdraw of `mint`, oldest first, with the transferred
 * amounts decrypted with the auditor's key. Failed transactions are left out. A transaction the
 * RPC lists for the mint but cannot return, or returns malformed, stops the report with RPC_ERROR
 * rather than leaving a gap in it.
 *
 * @example
 * ```ts
 * const auditorKeypair = await deriveAuditorElgamalKeypair(auditorWallet);
 * const activity = await listConfidentialActivity({ rpc, mint, auditorKeypair });
 * console.log(confidentialActivityToCsv(activity, { decimals: 6 }));
 * ```
 */
export async function listConfidentialActivity(input: ListConfidentialActivityInput): Promise<ConfidentialActivity[]> {
  const operation = "listConfidentialActivity";
  const invalid = (what: string) => new ConfidentialTransfersError("INVALID_INPUT", `${operation}: ${what}`, { operation });
  const wholeAndPositive = (n: unknown) => typeof n === "number" && Number.isSafeInteger(n) && n >= 1;
  if (input.concurrency !== undefined && !wholeAndPositive(input.concurrency)) {
    throw invalid(`concurrency must be a whole number, 1 or more, got ${input.concurrency}.`);
  }
  if (input.maxTransactions !== undefined && !wholeAndPositive(input.maxTransactions)) {
    throw invalid(`maxTransactions must be a whole number, 1 or more, got ${input.maxTransactions}.`);
  }
  for (const [name, date] of [["since", input.since], ["until", input.until]] as const) {
    if (date !== undefined && !(date instanceof Date && !Number.isNaN(date.getTime()))) throw invalid(`${name} is not a valid Date.`);
  }
  await ensureZk();
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;

  if (!input.skipAuditorKeyCheck) {
    const mint = await readMint(input.rpc, input.mint, operation);
    const extensions = isSome(mint.data.extensions) ? mint.data.extensions.value : [];
    const ct = extensions.find((e) => e.__kind === "ConfidentialTransferMint");
    const auditor = ct && isSome(ct.auditorElgamalPubkey) ? ct.auditorElgamalPubkey.value : null;
    const ours = getAuditorElgamalPubkey(input.auditorKeypair);
    if (auditor !== ours) {
      throw new ConfidentialTransfersError(
        "KEYS_MISMATCH",
        `${operation}: mint ${input.mint} ` +
          (auditor ? `has auditor key ${auditor}, not ${ours}.` : "has no auditor key, so nobody can read its transfer amounts.") +
          " Pass skipAuditorKeyCheck if the auditor key was changed and you want the transfers this key can read.",
        { operation },
      );
    }
  }

  const signatures = await signaturesOf(input);
  const secret = input.auditorKeypair.secret();
  const base58 = getBase58Encoder();
  // Entries per transaction, in the order the RPC lists them: newest first.
  const perTransaction: ConfidentialActivity[][] = [];

  const concurrency = input.concurrency ?? 4;
  for (let i = 0; i < signatures.length; i += concurrency) {
    const batch = signatures.slice(i, i + concurrency);
    const transactions = await Promise.all(
      batch.map((s) =>
        input.rpc
          .getTransaction(s, { commitment: "confirmed", encoding: "json", maxSupportedTransactionVersion: 1 })
          .send() as unknown as Promise<RawTransaction | null>,
      ),
    );
    transactions.forEach((tx, k) => {
      const signature = batch[k];
      const entries: ConfidentialActivity[] = [];
      perTransaction.push(entries);
      if (!tx || !tx.meta) {
        // The RPC listed it for the mint; leaving it out would leave a gap nobody sees.
        throw new ConfidentialTransfersError(
          "RPC_ERROR",
          `${operation}: the RPC lists transaction ${signature} for mint ${input.mint} but ` +
            (tx ? "returns it without its status" : "cannot return it") +
            ", so the report would be incomplete. Use an RPC that keeps the mint's full transaction history.",
          { operation, signature },
        );
      }
      if (tx.meta.err) return;
      const keys = [
        ...tx.transaction.message.accountKeys,
        ...(tx.meta.loadedAddresses?.writable ?? []),
        ...(tx.meta.loadedAddresses?.readonly ?? []),
      ];
      // An owner the RPC gives that is not an address is left out (the entry's owner is then null).
      const owners = new Map<number, Address>();
      for (const b of tx.meta.preTokenBalances ?? []) if (isAddressString(b.owner)) owners.set(b.accountIndex, b.owner);
      // Each top-level instruction, followed by the instructions it invoked (other programs can
      // make confidential transfers through cross-program calls).
      const inner = new Map<number, readonly RawInstruction[]>();
      for (const group of tx.meta.innerInstructions ?? []) inner.set(group.index, group.instructions);
      const all = tx.transaction.message.instructions.flatMap((ix, i) => [ix, ...(inner.get(i) ?? [])]);
      for (const ix of all) {
        if (keys[ix.programIdIndex] !== programAddress) continue;
        const accounts = ix.accounts ?? [];
        const data = new Uint8Array(base58.encode(ix.data));
        if (data[0] !== CONFIDENTIAL_TRANSFER_DISCRIMINATOR || accounts.length < 2) continue;
        // In every client, the token account comes first and the mint second; for a transfer the
        // destination is third. The accounts after that differ between clients.
        if (keys[accounts[1]] !== input.mint) continue;
        const entry = toActivity(data, accounts, keys, owners, secret);
        if (!entry) continue;
        if (!isAddressString(entry.fromToken) || !isAddressString(entry.toToken)) {
          // A movement of the mint whose accounts cannot be named: refused, like a missing transaction.
          throw new ConfidentialTransfersError(
            "RPC_ERROR",
            `${operation}: the RPC returned transaction ${signature} with a ${entry.kind} whose token accounts are not addresses.`,
            { operation, signature },
          );
        }
        entries.push({
          signature,
          slot: BigInt(tx.slot),
          blockTime: tx.blockTime == null ? null : new Date(Number(tx.blockTime) * 1000),
          ...entry,
        });
      }
    });
  }

  // Oldest first; within a transaction, in instruction order.
  return perTransaction.reverse().flat();
}

/** A string that is a base58 address (what the RPC gives is not taken on trust). */
function isAddressString(value: unknown): value is Address {
  return typeof value === "string" && isAddress(value);
}

function toActivity(
  data: Uint8Array,
  accounts: readonly number[],
  keys: readonly Address[],
  owners: Map<number, Address>,
  secret: ReturnType<ElGamalKeypair["secret"]>,
): Omit<ConfidentialActivity, "signature" | "slot" | "blockTime"> | null {
  const at = (i: number) => ({ token: keys[accounts[i]], owner: owners.get(accounts[i]) ?? null });
  switch (data[1]) {
    case CONFIDENTIAL_DEPOSIT_CONFIDENTIAL_TRANSFER_DISCRIMINATOR: {
      const { amount } = getConfidentialDepositInstructionDataDecoder().decode(data);
      const a = at(0);
      return { kind: "deposit", fromToken: a.token, fromOwner: a.owner, toToken: a.token, toOwner: a.owner, amount, decrypted: false };
    }
    case CONFIDENTIAL_WITHDRAW_CONFIDENTIAL_TRANSFER_DISCRIMINATOR: {
      const { amount } = getConfidentialWithdrawInstructionDataDecoder().decode(data);
      const a = at(0);
      return { kind: "withdraw", fromToken: a.token, fromOwner: a.owner, toToken: a.token, toOwner: a.owner, amount, decrypted: false };
    }
    case CONFIDENTIAL_TRANSFER_CONFIDENTIAL_TRANSFER_DISCRIMINATOR: {
      const decoded = getConfidentialTransferInstructionDataDecoder().decode(data);
      const from = at(0);
      const to = at(2);
      const base = { kind: "transfer" as const, fromToken: from.token, fromOwner: from.owner, toToken: to.token, toOwner: to.owner };
      try {
        const lo = ElGamalCiphertext.fromBytes(new Uint8Array(decoded.transferAmountAuditorCiphertextLo));
        const hi = ElGamalCiphertext.fromBytes(new Uint8Array(decoded.transferAmountAuditorCiphertextHi));
        if (!lo || !hi) throw new Error("malformed ciphertext");
        const amount = secret.decrypt(lo) + (secret.decrypt(hi) << TRANSFER_AMOUNT_LO_BIT_LENGTH);
        return { ...base, amount, decrypted: true };
      } catch {
        return { ...base, amount: null, decrypted: false, note: "not encrypted to this auditor key" };
      }
    }
    case CONFIDENTIAL_TRANSFER_WITH_FEE_CONFIDENTIAL_TRANSFER_DISCRIMINATOR: {
      const from = at(0);
      const to = at(2);
      return {
        kind: "transfer-with-fee", fromToken: from.token, fromOwner: from.owner, toToken: to.token, toOwner: to.owner,
        amount: null, decrypted: false, note: "transfer with fee: amount not decrypted by this version",
      };
    }
    default:
      return null;
  }
}

async function signaturesOf(input: ListConfidentialActivityInput): Promise<Signature[]> {
  const out: Signature[] = [];
  const sinceSeconds = input.since ? BigInt(Math.floor(input.since.getTime() / 1000)) : undefined;
  const untilSeconds = input.until ? BigInt(Math.floor(input.until.getTime() / 1000)) : undefined;
  let before: Signature | undefined;
  for (;;) {
    const page = await input.rpc.getSignaturesForAddress(input.mint, { before, limit: 1000, commitment: "confirmed" }).send();
    if (page.length === 0) break;
    for (const s of page) {
      if (input.maxTransactions !== undefined && out.length >= input.maxTransactions) return out;
      const time = s.blockTime == null ? undefined : BigInt(s.blockTime);
      if (sinceSeconds !== undefined && time !== undefined && time < sinceSeconds) return out; // older than wanted: done
      if (untilSeconds !== undefined && time !== undefined && time >= untilSeconds) continue;
      if (s.err) continue;
      out.push(s.signature);
    }
    before = page[page.length - 1].signature;
    if (page.length < 1000) break;
  }
  return out;
}

export type ConfidentialActivityCsvOptions = {
  /** Mint decimals; adds an `amount` column in tokens next to the base units. */
  decimals?: number;
};

/**
 * The activity as CSV (RFC 4180, comma-separated, one header row), ready for a spreadsheet. Times
 * are UTC in ISO 8601. A text field that a spreadsheet would take for a formula (one starting with
 * =, +, -, @, a tab or a carriage return) is written with a leading ', so that it is shown as text.
 */
export function confidentialActivityToCsv(activity: readonly ConfidentialActivity[], options: ConfidentialActivityCsvOptions = {}): string {
  const header = ["time_utc", "slot", "signature", "kind", "from_owner", "from_account", "to_owner", "to_account", "amount_base_units"];
  if (options.decimals !== undefined) header.push("amount");
  header.push("decrypted", "note");
  const rows = activity.map((a) => {
    const row = [
      a.blockTime ? a.blockTime.toISOString() : "",
      a.slot.toString(),
      a.signature,
      a.kind,
      a.fromOwner ?? "",
      a.fromToken,
      a.toOwner ?? "",
      a.toToken,
      a.amount === null ? "" : a.amount.toString(),
    ];
    if (options.decimals !== undefined) row.push(a.amount === null ? "" : formatUnits(a.amount, options.decimals));
    row.push(a.decrypted ? "yes" : "no", a.note ?? "");
    return row.map(csvField).join(",");
  });
  return [header.join(","), ...rows].join("\r\n") + "\r\n";
}

/** An auditor report as stored in JSON: one mint's activity, and what the report was made from. */
export type ConfidentialActivityReport = {
  format: typeof CONFIDENTIAL_ACTIVITY_FORMAT;
  /** The version of the JSON format the report was written in. */
  version: number;
  mint: Address;
  /** The auditor ElGamal public key the amounts were decrypted with, when the writer gave it. */
  auditorElgamalPubkey: Address | null;
  /** The mint's decimals, when the writer gave them. Amounts are in base units either way. */
  decimals: number | null;
  generatedAt: Date;
  activity: ConfidentialActivity[];
};

export type ConfidentialActivityJsonOptions = {
  mint: Address;
  auditorElgamalPubkey?: Address;
  decimals?: number;
  /** Default: now. */
  generatedAt?: Date;
};

const ACTIVITY_KINDS: readonly ConfidentialActivityKind[] = ["deposit", "transfer", "withdraw", "transfer-with-fee"];
/** The kinds whose amount is on chain only encrypted, so that `decrypted` can be true. */
const ENCRYPTED_AMOUNT_KINDS: readonly ConfidentialActivityKind[] = ["transfer", "transfer-with-fee"];

/**
 * The activity as a JSON report that names its format and version
 * (`"format": "arcantis.confidential-activity", "version": 1`), so that a later release can still
 * read it, and refuses one it cannot. Slots and amounts are decimal strings, times ISO 8601 in
 * UTC. {@link parseConfidentialActivityJson} reads it back.
 */
export function confidentialActivityToJson(
  activity: readonly ConfidentialActivity[],
  options: ConfidentialActivityJsonOptions,
): string {
  const report = {
    format: CONFIDENTIAL_ACTIVITY_FORMAT,
    version: CONFIDENTIAL_ACTIVITY_VERSION,
    mint: options.mint,
    auditorElgamalPubkey: options.auditorElgamalPubkey ?? null,
    decimals: options.decimals ?? null,
    generatedAt: (options.generatedAt ?? new Date()).toISOString(),
    activity: activity.map((a) => ({
      signature: a.signature,
      slot: a.slot.toString(),
      blockTime: a.blockTime ? a.blockTime.toISOString() : null,
      kind: a.kind,
      fromToken: a.fromToken,
      fromOwner: a.fromOwner,
      toToken: a.toToken,
      toOwner: a.toOwner,
      amount: a.amount === null ? null : a.amount.toString(),
      decrypted: a.decrypted,
      ...(a.note === undefined ? {} : { note: a.note }),
    })),
  };
  return JSON.stringify(report, null, 2) + "\n";
}

/**
 * Read a report written by {@link confidentialActivityToJson}, in this release's version or an
 * earlier one. A file in another format, or in a version written by a newer release, is refused
 * with UNSUPPORTED_FORMAT; a damaged one with INVALID_INPUT.
 */
export function parseConfidentialActivityJson(text: string): ConfidentialActivityReport {
  const operation = "parseConfidentialActivityJson";
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (e) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `${operation}: not JSON (${(e as Error).message})`, { operation, cause: e });
  }
  const report = value as Record<string, unknown> | null;
  if (!report || typeof report !== "object" || report.format !== CONFIDENTIAL_ACTIVITY_FORMAT) {
    const format = report && typeof report === "object" ? JSON.stringify(report.format) : "none";
    throw new ConfidentialTransfersError(
      "UNSUPPORTED_FORMAT",
      `${operation}: not an Arcantis confidential-activity report (format: ${format}).`,
      { operation },
    );
  }
  const version = report.version;
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `${operation}: the report has no valid version.`, { operation });
  }
  if (version > CONFIDENTIAL_ACTIVITY_VERSION) {
    throw new ConfidentialTransfersError(
      "UNSUPPORTED_FORMAT",
      `${operation}: the report is in version ${version} of the format, written by a newer release; ` +
        `this release reads versions 1 to ${CONFIDENTIAL_ACTIVITY_VERSION}.`,
      { operation },
    );
  }
  // Version 1 is the only one so far. A later version gets its own reader here, and this one stays.
  return readReportV1(report, operation);
}

function readReportV1(report: Record<string, unknown>, operation: string): ConfidentialActivityReport {
  const fail = (what: string): never => {
    throw new ConfidentialTransfersError("INVALID_INPUT", `${operation}: ${what}`, { operation });
  };
  const str = (v: unknown, what: string) => (typeof v === "string" && v.length > 0 ? v : fail(`${what} is missing or not a string`));
  const addr = (v: unknown, what: string) => (typeof v === "string" && isAddress(v) ? v : fail(`${what} is not an address`));
  const addrOrNull = (v: unknown, what: string) => (v === null || v === undefined ? null : addr(v, what));
  const time = (v: unknown, what: string) => {
    const d = new Date(str(v, what));
    return Number.isNaN(d.getTime()) ? fail(`${what} is not a time`) : d;
  };
  const whole = (v: unknown, what: string) => (typeof v === "string" && /^\d+$/.test(v) ? BigInt(v) : fail(`${what} is not a whole number`));
  const decimals = report.decimals;
  // A mint's decimals are one byte in Token-2022.
  if (
    decimals !== null &&
    decimals !== undefined &&
    !(typeof decimals === "number" && Number.isInteger(decimals) && decimals >= 0 && decimals <= 255)
  ) {
    fail("decimals is not a whole number from 0 to 255");
  }
  if (!Array.isArray(report.activity)) fail("activity is missing or not a list");
  const activity = (report.activity as unknown[]).map((entry, i): ConfidentialActivity => {
    const e = (entry && typeof entry === "object" ? entry : fail(`activity[${i}] is not an object`)) as Record<string, unknown>;
    const at = (field: string) => `activity[${i}].${field}`;
    const kind = e.kind as ConfidentialActivityKind;
    if (!ACTIVITY_KINDS.includes(kind)) fail(`${at("kind")} is not one of ${ACTIVITY_KINDS.join(", ")}`);
    if (typeof e.decrypted !== "boolean") fail(`${at("decrypted")} is not true or false`);
    const amount = e.amount === null || e.amount === undefined ? null : whole(e.amount, at("amount"));
    // Only a transfer's amount is encrypted; a deposit's or a withdrawal's is public, never decrypted.
    if (e.decrypted === true && !ENCRYPTED_AMOUNT_KINDS.includes(kind)) {
      fail(`${at("decrypted")} is true for a ${kind}, whose amount is not encrypted`);
    }
    if (e.decrypted === true && amount === null) fail(`${at("decrypted")} is true but there is no amount`);
    return {
      signature: (typeof e.signature === "string" && isSignature(e.signature) ? e.signature : fail(`${at("signature")} is not a signature`)) as Signature,
      slot: whole(e.slot, at("slot")),
      blockTime: e.blockTime === null || e.blockTime === undefined ? null : time(e.blockTime, at("blockTime")),
      kind,
      fromToken: addr(e.fromToken, at("fromToken")),
      fromOwner: addrOrNull(e.fromOwner, at("fromOwner")),
      toToken: addr(e.toToken, at("toToken")),
      toOwner: addrOrNull(e.toOwner, at("toOwner")),
      amount,
      decrypted: e.decrypted as boolean,
      ...(typeof e.note === "string" ? { note: e.note } : {}),
    };
  });
  return {
    format: CONFIDENTIAL_ACTIVITY_FORMAT,
    version: report.version as number,
    mint: addr(report.mint, "mint"),
    auditorElgamalPubkey: addrOrNull(report.auditorElgamalPubkey, "auditorElgamalPubkey"),
    decimals: (decimals ?? null) as number | null,
    generatedAt: time(report.generatedAt, "generatedAt"),
    activity,
  };
}

function formatUnits(amount: bigint, decimals: number): string {
  if (decimals === 0) return amount.toString();
  const s = amount.toString().padStart(decimals + 1, "0");
  return `${s.slice(0, -decimals)}.${s.slice(-decimals)}`;
}

/**
 * One CSV field. A field that a spreadsheet would read as a formula (starting with =, +, -, @, a
 * tab or a carriage return) gets a leading ' so that it stays text: a note in a report read
 * back from a file is not the SDK's own text. Slots and amounts are whole numbers of 0 or more,
 * so they never start with one of these and stay numbers.
 */
function csvField(value: string): string {
  const text = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}
