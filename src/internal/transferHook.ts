// SPDX-License-Identifier: BUSL-1.1
//
// Transfer-hook account resolution for confidential transfers.
//
// Token-2022 calls a mint's transfer hook on a confidential transfer exactly as it does on a public
// one, and the amount it passes is u64::MAX because the real amount is encrypted. The hook's own
// accounts are not part of the confidential-transfer instruction, so the client has to resolve them
// from the mint's ExtraAccountMetaList and append them, or the transfer fails with MissingAccount.
//
// The resolution rules are the ones in the SPL transfer-hook interface (spl-tlv-account-resolution):
// a literal address, an address stored in the instruction data or in an account's data, a PDA of
// the hook program, or a PDA of another account in the list, with seeds built from literals, the
// instruction data, an account key, or a slice of an account's data. Anything that does not
// resolve is an error before signing, as in the Rust crate, which uses the SPL library itself.
import {
  AccountRole,
  getAddressDecoder,
  getAddressEncoder,
  getBase64Encoder,
  getProgramDerivedAddress,
  type Address,
  type Rpc,
  type SolanaRpcApi,
} from "@solana/kit";
import { TOKEN_2022_PROGRAM_ADDRESS, fetchMint } from "@solana-program/token-2022";

import { ConfidentialTransfersError } from "../errors";

/** Seed used for every mint's ExtraAccountMetaList account. */
export const EXTRA_ACCOUNT_METAS_SEED = "extra-account-metas";

/** Token-2022 invokes a hook for a confidential transfer with this amount, since the real one is encrypted. */
export const CONFIDENTIAL_TRANSFER_HOOK_AMOUNT = 0xffffffffffffffffn;

/** The transfer-hook interface's `Execute` instruction discriminator. */
const EXECUTE_DISCRIMINATOR = new Uint8Array([105, 37, 101, 197, 75, 251, 102, 26]);

const SYSTEM_PROGRAM = "11111111111111111111111111111111" as Address;
const TLV_HEADER = 12; // 8-byte type discriminator + u32 byte length
const META_ENTRY = 35; // u8 discriminator + 32-byte address config + is_signer + is_writable

export type ResolvedAccount = { address: Address; role: AccountRole };

type Meta = { discriminator: number; addressConfig: Uint8Array; isWritable: boolean; isSigner: boolean };

const addressEncoder = getAddressEncoder();
const addressDecoder = getAddressDecoder();

function accountData(value: { data: readonly [string, string] | string } | null): Uint8Array | null {
  if (value == null) return null;
  const raw = Array.isArray(value.data) ? value.data[0] : (value.data as unknown as string);
  return new Uint8Array(getBase64Encoder().encode(raw));
}

async function fetchData(
  rpc: Rpc<SolanaRpcApi>,
  address: Address,
): Promise<Uint8Array | null> {
  const { value } = await rpc.getAccountInfo(address, { encoding: "base64" }).send();
  return accountData(value as never);
}

/** The mint's transfer-hook program, or null when the mint has no hook. */
export async function getTransferHookProgram(
  rpc: Rpc<SolanaRpcApi>,
  mint: Address,
): Promise<Address | null> {
  const { data } = await fetchMint(rpc, mint);
  const extensions = (data as { extensions?: { __option: string; value?: unknown[] } }).extensions;
  const list = (extensions?.__option === "Some" ? extensions.value : []) ?? [];
  for (const extension of list as Array<Record<string, unknown>>) {
    if (extension.__kind !== "TransferHook") continue;
    const raw = extension.programId as Address | { __option: string; value?: Address };
    const programId =
      typeof raw === "string" ? raw : raw?.__option === "Some" ? (raw.value as Address) : null;
    if (programId == null || programId === SYSTEM_PROGRAM) return null;
    return programId;
  }
  return null;
}

/** The PDA holding a mint's ExtraAccountMetaList for a hook program. */
export async function findExtraAccountMetaListPda(
  mint: Address,
  hookProgram: Address,
): Promise<Address> {
  const [address] = await getProgramDerivedAddress({
    programAddress: hookProgram,
    seeds: [new TextEncoder().encode(EXTRA_ACCOUNT_METAS_SEED), addressEncoder.encode(mint)],
  });
  return address;
}

/**
 * Refuse hook accounts that also sign the transaction carrying the transfer: the payer, the owner,
 * or a proof account's keypair. Signer status is per transaction, so such an account would reach
 * the hook as a signer whenever its extra-account-meta list marks it as one, and the hook could
 * then, for example, spend the payer's lamports. Token-2022 hands the hook the owner as a
 * non-signer, but nothing protects the payer; the SDK refuses them all, before anything is signed.
 * Throws INVALID_INPUT.
 */
export function assertHookAccountsAreNotSigners(
  hookAccounts: ReadonlyArray<Address | ResolvedAccount>,
  signers: Iterable<Address>,
  operation: string,
): void {
  const signing = new Set(signers);
  const both = [...new Set(hookAccounts.map((a) => (typeof a === "string" ? a : a.address)))].filter((a) => signing.has(a));
  if (both.length === 0) return;
  throw new ConfidentialTransfersError(
    "INVALID_INPUT",
    `${operation}: the mint's transfer hook asks for ${both.join(", ")}, which also signs this transaction (as payer, ` +
      "owner or proof account). The hook could receive it as a signer, so the SDK does not sign this. If it is the " +
      "payer, use another payer; if it is the owner, this mint's hook cannot be used through the SDK.",
    { operation },
  );
}

/** A hook whose accounts cannot be resolved: the same code the Rust crate uses. */
function hookError(mint: Address, problem: string): ConfidentialTransfersError {
  return new ConfidentialTransfersError(
    "ACCOUNT_NOT_FOUND",
    `cannot resolve the accounts of mint ${mint}'s transfer hook: ${problem}`,
    { operation: "resolveTransferHookAccounts" },
  );
}

/**
 * The entries of an ExtraAccountMetaList account: a TLV list whose entry for the hook's `Execute`
 * instruction (type = the Execute discriminator) holds a u32 count and 35-byte entries.
 */
function parseMetaList(data: Uint8Array, problem: (what: string) => Error): Meta[] {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  for (let offset = 0; offset + TLV_HEADER <= data.length; ) {
    const type = data.subarray(offset, offset + 8);
    const length = view.getUint32(offset + 8, true);
    const value = data.subarray(offset + TLV_HEADER, offset + TLV_HEADER + length);
    if (value.length !== length) throw problem("its extra-account-meta list is cut short");
    if (type.every((byte, i) => byte === EXECUTE_DISCRIMINATOR[i])) {
      if (value.length < 4) throw problem("its extra-account-meta list is cut short");
      const count = new DataView(value.buffer, value.byteOffset, value.byteLength).getUint32(0, true);
      if (4 + count * META_ENTRY > value.length) throw problem(`its extra-account-meta list claims ${count} entries but holds fewer`);
      const metas: Meta[] = [];
      for (let i = 0; i < count; i++) {
        const start = 4 + i * META_ENTRY;
        metas.push({
          discriminator: value[start]!,
          addressConfig: value.subarray(start + 1, start + 33),
          isSigner: value[start + 33] === 1,
          isWritable: value[start + 34] === 1,
        });
      }
      return metas;
    }
    if (type.every((byte) => byte === 0)) break; // the rest of the account is unused space
    offset += TLV_HEADER + length;
  }
  throw problem("its extra-account-meta list has no entry for the Execute instruction");
}

/** `length` bytes of `bytes` from `start`, or an error saying what was too short. */
function slice(bytes: Uint8Array, start: number, length: number, what: string, problem: (what: string) => Error): Uint8Array {
  if (start + length > bytes.length) throw problem(`${what} is too short (${bytes.length} bytes, needs ${start + length})`);
  return bytes.subarray(start, start + length);
}

type FetchData = (address: Address) => Promise<Uint8Array | null>;

async function dataOf(fetch: FetchData, account: ResolvedAccount | undefined, index: number, problem: (what: string) => Error) {
  if (account == null) throw problem(`an entry refers to account ${index}, which is not in the list`);
  const data = await fetch(account.address);
  if (data == null) throw problem(`an entry reads account ${account.address}, which does not exist`);
  return data;
}

/** Build the seeds packed into an address config, in the SPL transfer-hook encoding. */
async function unpackSeeds(
  config: Uint8Array,
  previous: ResolvedAccount[],
  instructionData: Uint8Array,
  fetch: FetchData,
  problem: (what: string) => Error,
): Promise<Uint8Array[]> {
  const seeds: Uint8Array[] = [];
  let i = 0;
  while (i < config.length) {
    const kind = config[i]!;
    if (kind === 0) break;
    if (kind === 1) {
      // A literal: length, then the bytes.
      const length = slice(config, i + 1, 1, "a literal seed", problem)[0]!;
      seeds.push(slice(config, i + 2, length, "a literal seed", problem));
      i += 2 + length;
    } else if (kind === 2) {
      // Bytes of the Execute instruction's data: start, length.
      const [index, length] = slice(config, i + 1, 2, "an instruction-data seed", problem);
      seeds.push(slice(instructionData, index!, length!, "the instruction data", problem));
      i += 3;
    } else if (kind === 3) {
      // The address of an account earlier in the list.
      const index = slice(config, i + 1, 1, "an account-key seed", problem)[0]!;
      const account = previous[index];
      if (account == null) throw problem(`a seed refers to account ${index}, which is not in the list`);
      seeds.push(new Uint8Array(addressEncoder.encode(account.address)));
      i += 2;
    } else if (kind === 4) {
      // Bytes of an earlier account's data: account, start, length.
      const [accountIndex, dataIndex, length] = slice(config, i + 1, 3, "an account-data seed", problem);
      const data = await dataOf(fetch, previous[accountIndex!], accountIndex!, problem);
      seeds.push(slice(data, dataIndex!, length!, `the data of account ${accountIndex}`, problem));
      i += 4;
    } else {
      throw problem(`a seed has unknown type ${kind}`);
    }
  }
  return seeds;
}

async function resolveMeta(
  meta: Meta,
  previous: ResolvedAccount[],
  instructionData: Uint8Array,
  hookProgram: Address,
  fetch: FetchData,
  problem: (what: string) => Error,
): Promise<ResolvedAccount> {
  // The SDK never adds a signer for a hook: an account the hook marks as a signer goes in
  // read-only or writable, and a transaction that would carry a signature for it anyway is refused
  // (assertHookAccountsAreNotSigners).
  const role = meta.isWritable ? AccountRole.WRITABLE : AccountRole.READONLY;
  const { discriminator: kind, addressConfig: config } = meta;
  if (kind === 0) return { address: addressDecoder.decode(config), role };
  if (kind === 2) {
    // An address stored in the instruction data or in an earlier account's data (PubkeyData).
    if (config[0] === 1) {
      return { address: addressDecoder.decode(slice(instructionData, config[1]!, 32, "the instruction data", problem)), role };
    }
    if (config[0] === 2) {
      const data = await dataOf(fetch, previous[config[1]!], config[1]!, problem);
      return { address: addressDecoder.decode(slice(data, config[2]!, 32, `the data of account ${config[1]}`, problem)), role };
    }
    throw problem(`an address stored in data has unknown type ${config[0]}`);
  }
  let programAddress = hookProgram;
  if (kind >= 128) {
    // A PDA of the program at this index of the list.
    const account = previous[kind - 128];
    if (account == null) throw problem(`an entry refers to program ${kind - 128}, which is not in the list`);
    programAddress = account.address;
  } else if (kind !== 1) {
    throw problem(`an entry has unknown type ${kind}`);
  }
  const seeds = await unpackSeeds(config, previous, instructionData, fetch, problem);
  const [address] = await getProgramDerivedAddress({ programAddress, seeds });
  return { address, role };
}

/**
 * The accounts an ExtraAccountMetaList asks for, resolved in order: each entry may refer to the
 * five accounts of the hook's Execute instruction and to the entries before it.
 */
export async function resolveExtraAccounts(input: {
  mint: Address;
  hookProgram: Address;
  metaListData: Uint8Array;
  /** Source, mint, destination, authority and the meta list: the Execute instruction's accounts. */
  executeAccounts: ResolvedAccount[];
  instructionData: Uint8Array;
  fetch: FetchData;
}): Promise<ResolvedAccount[]> {
  const problem = (what: string) => hookError(input.mint, what);
  const resolved = [...input.executeAccounts];
  for (const meta of parseMetaList(input.metaListData, problem)) {
    // An entry marked as a signer is resolved like any other; the transaction must then not carry
    // a signature for it (assertHookAccountsAreNotSigners).
    const account = await resolveMeta(meta, resolved, input.instructionData, input.hookProgram, input.fetch, problem);
    // As the SPL resolver does: an account already in the list, and only read-only there, stays
    // read-only even if the entry asks for it writable.
    const earlier = resolved.filter((a) => a.address === account.address);
    const readOnly = earlier.length > 0 && earlier.every((a) => a.role === AccountRole.READONLY);
    resolved.push(readOnly ? { address: account.address, role: AccountRole.READONLY } : account);
  }
  return resolved.slice(input.executeAccounts.length);
}

export type ResolveTransferHookAccountsInput = {
  rpc: Rpc<SolanaRpcApi>;
  mint: Address;
  sourceToken: Address;
  destinationToken: Address;
  /** Owner of the source account — the transfer authority. */
  owner: Address;
  /** Amount the hook is told about. Confidential transfers always pass u64::MAX. */
  amount?: bigint;
  programAddress?: Address;
};

/**
 * Resolve the accounts a mint's transfer hook needs, in the order Token-2022 expects them appended
 * to a transfer instruction: the resolved extra accounts, then the hook program, then its metadata
 * account. Returns an empty array when the mint has no transfer hook, and throws
 * ACCOUNT_NOT_FOUND when it has one whose accounts cannot be resolved (no extra-account-meta list,
 * or an entry that points at something missing), as the Rust crate does.
 */
export async function resolveTransferHookAccounts(
  input: ResolveTransferHookAccountsInput,
): Promise<ResolvedAccount[]> {
  const hookProgram = await getTransferHookProgram(input.rpc, input.mint);
  if (hookProgram == null) return [];

  const metaListAddress = await findExtraAccountMetaListPda(input.mint, hookProgram);
  const metaListData = await fetchData(input.rpc, metaListAddress);
  if (metaListData == null) {
    throw hookError(input.mint, `hook program ${hookProgram} has no extra-account-meta list at ${metaListAddress}`);
  }

  const amount = input.amount ?? CONFIDENTIAL_TRANSFER_HOOK_AMOUNT;
  const instructionData = new Uint8Array(16);
  instructionData.set(EXECUTE_DISCRIMINATOR, 0);
  new DataView(instructionData.buffer).setBigUint64(8, amount, true);

  const extra = await resolveExtraAccounts({
    mint: input.mint,
    hookProgram,
    metaListData,
    // The hook's Execute instruction's accounts, all read-only there, in the order seed indexes
    // refer to them.
    executeAccounts: [input.sourceToken, input.mint, input.destinationToken, input.owner, metaListAddress].map(
      (address) => ({ address, role: AccountRole.READONLY }),
    ),
    instructionData,
    fetch: (address) => fetchData(input.rpc, address),
  });

  return [
    ...extra,
    { address: hookProgram, role: AccountRole.READONLY },
    { address: metaListAddress, role: AccountRole.READONLY },
  ];
}

export { TOKEN_2022_PROGRAM_ADDRESS };
