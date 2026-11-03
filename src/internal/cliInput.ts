// SPDX-License-Identifier: BUSL-1.1
//
// Reading the `arcantis` command's arguments and keypair file (src/cli.ts). Kept apart from the
// command so the tests can check it without running it. Every error here is an Error whose message
// the command prints as is, so none of them may quote the keypair file.
import { createKeyPairSignerFromBytes, type KeyPairSigner } from "@solana/kit";

/** `YYYY-MM-DD`, or `YYYY-MM-DDTHH:MM[:SS[.fff]]` with an optional `Z` or `±HH:MM`. */
const ISO_TIME = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})?)?$/;

/**
 * A `--since` or `--until` value: an ISO 8601 date or time, read as UTC unless it names another
 * offset (JavaScript would read a time without one as local time). Anything else, and a day that
 * does not exist (2026-02-30), is refused.
 */
export function parseUtcTime(value: string, name: string): Date {
  const match = ISO_TIME.exec(value);
  const refuse = () => new Error(`--${name}: not an ISO date or time (e.g. 2026-10-01 or 2026-10-01T12:00:00Z): ${value}`);
  if (!match) throw refuse();
  const [, year, month, day, hour, , , offset] = match;
  const date = new Date(hour !== undefined && offset === undefined ? `${value}Z` : value);
  // The calendar day as written must exist: Date rolls 2026-02-30 over to 2 March.
  const calendar = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)));
  if (
    Number.isNaN(date.getTime()) ||
    calendar.getUTCFullYear() !== Number(year) ||
    calendar.getUTCMonth() !== Number(month) - 1 ||
    calendar.getUTCDate() !== Number(day)
  ) {
    throw refuse();
  }
  return date;
}

/** A `--max` or `--concurrency` value: a whole number, 1 or more, written in digits. */
export function parsePositiveInteger(value: string, name: string): number {
  const n = Number(value);
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(n) || n < 1) {
    throw new Error(`--${name}: not a whole number of 1 or more: ${value}`);
  }
  return n;
}

/**
 * The signer in a Solana CLI keypair file (a JSON array of 64 numbers). An error names the file but
 * never shows what is in it: a damaged keypair file can still hold most of a secret key.
 */
export async function keypairFromFile(text: string, path: string): Promise<KeyPairSigner> {
  const refuse = () => new Error(`--keypair ${path}: not a JSON keypair file (expected an array of 64 numbers)`);
  let bytes: unknown;
  try {
    bytes = JSON.parse(text);
  } catch {
    throw refuse();
  }
  if (!Array.isArray(bytes) || bytes.length !== 64 || !bytes.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) {
    throw refuse();
  }
  try {
    return await createKeyPairSignerFromBytes(new Uint8Array(bytes));
  } catch {
    throw new Error(`--keypair ${path}: not a valid keypair (its public key does not match its secret key)`);
  }
}
