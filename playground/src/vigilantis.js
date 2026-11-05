// SPDX-License-Identifier: BUSL-1.1
//
// The Vigilantis instructions the playground sends, encoded with @solana/kit from the Vigilantis IDL.
// `vigilantis-idl.json` is the 1.0.0-rc.2 IDL (sdk/src/idl/vigilantis.json in
// github.com/softseco/vigilantis) without its doc comments; `npm run check` compares the two.
// From Node, use the @softseco/vigilantis package instead.
import { TOKEN_2022_PROGRAM_ADDRESS, getTransferCheckedInstruction } from "@solana-program/token-2022";
import {
  AccountRole,
  address,
  getAddressEncoder,
  getBooleanEncoder,
  getProgramDerivedAddress,
  getU16Encoder,
  getU64Encoder,
} from "@solana/kit";

import idl from "./vigilantis-idl.json";

export const VIGILANTIS_PROGRAM_ADDRESS = address(idl.address);
export const VIGILANTIS_VERSION = idl.metadata.version;

/** The suggested reason codes of @softseco/vigilantis (ENFORCEMENT_REASONS). Vigilantis only records the number. */
export const REASONS = {
  sanctions: 1,
  courtOrder: 2,
  authorityRequest: 3,
  fraud: 4,
  stolenFunds: 5,
  internalReview: 6,
  caseClosed: 7,
};

const addressBytes = getAddressEncoder();
const utf8 = (s) => new TextEncoder().encode(s);

async function pda(...seeds) {
  const [found] = await getProgramDerivedAddress({ programAddress: VIGILANTIS_PROGRAM_ADDRESS, seeds });
  return found;
}

/** The PDAs the playground uses, with the seeds of @softseco/vigilantis (sdk/src/pdas.ts). */
export const pdas = {
  metaList: (mint) => pda(utf8("extra-account-metas"), addressBytes.encode(mint)),
  policy: (mint) => pda(utf8("policy"), addressBytes.encode(mint)),
  block: (mint, wallet) => pda(utf8("block"), addressBytes.encode(mint), addressBytes.encode(wallet)),
  allow: (mint, wallet) => pda(utf8("allow"), addressBytes.encode(mint), addressBytes.encode(wallet)),
  freezeAuthority: (mint) => pda(utf8("freeze-authority"), addressBytes.encode(mint)),
  pauseAuthority: (mint) => pda(utf8("pause-authority"), addressBytes.encode(mint)),
  freezeRecord: (mint, token) => pda(utf8("freeze-record"), addressBytes.encode(mint), addressBytes.encode(token)),
  forfeiture: (mint, token) => pda(utf8("forfeiture"), addressBytes.encode(mint), addressBytes.encode(token)),
};

/**
 * A 32-byte case reference: SHA-256 of `salt` followed by `caseId`, as `caseRef()` in
 * @softseco/vigilantis. The chain stores the hash; only someone with the salt can match it to a case.
 */
export async function caseRef(caseId, salt) {
  const bytes = new Uint8Array([...utf8(salt), ...utf8(caseId)]);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function encodeArg(type, value, name) {
  if (type === "bool") return getBooleanEncoder().encode(value);
  if (type === "u16") return getU16Encoder().encode(value);
  if (type === "u64") return getU64Encoder().encode(BigInt(value));
  if (type?.array?.[0] === "u8" && type.array[1] === 32) {
    if (!(value instanceof Uint8Array) || value.length !== 32) throw new Error(`${name} must be 32 bytes`);
    return value;
  }
  throw new Error(`the playground does not encode ${JSON.stringify(type)} (${name})`);
}

// One instruction from the IDL. `accounts` maps the IDL's account names to addresses, or to signers
// for the accounts the IDL marks as signers. Accounts with a fixed address (system and token
// programs) come from the IDL; an optional account left out is passed as the program's own address,
// which is how Anchor reads "none".
function instruction(name, accounts, args = {}) {
  const ix = idl.instructions.find((i) => i.name === name);
  if (!ix) throw new Error(`Vigilantis ${VIGILANTIS_VERSION} has no instruction ${name}`);
  const metas = ix.accounts.map((a) => {
    const given = accounts[a.name];
    if (given === undefined) {
      if (a.address) return { address: address(a.address), role: AccountRole.READONLY };
      if (a.optional) return { address: VIGILANTIS_PROGRAM_ADDRESS, role: AccountRole.READONLY };
      throw new Error(`${name}: the ${a.name} account is missing`);
    }
    if (a.signer) {
      return { address: given.address, role: a.writable ? AccountRole.WRITABLE_SIGNER : AccountRole.READONLY_SIGNER, signer: given };
    }
    return { address: given, role: a.writable ? AccountRole.WRITABLE : AccountRole.READONLY };
  });
  const parts = [Uint8Array.from(ix.discriminator), ...ix.args.map((a) => encodeArg(a.type, args[a.name], a.name))];
  const data = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  parts.reduce((offset, p) => (data.set(p, offset), offset + p.length), 0);
  return { programAddress: VIGILANTIS_PROGRAM_ADDRESS, accounts: metas, data };
}

/** The accounts Token-2022 passes to the hook on every transfer. */
export async function initializeExtraAccountMetaList({ payer, mint }) {
  return instruction("initialize_extra_account_meta_list", { payer, mint, extra_account_meta_list: await pdas.metaList(mint) });
}

/** The mint's policy. `authority` must be the mint authority and becomes the policy's admin. */
export async function initializePolicy({ authority, mint, allowlist, blocklist, maxTransferAmount, allowConfidential }) {
  return instruction(
    "initialize_policy",
    { authority, mint, policy_config: await pdas.policy(mint) },
    {
      allowlist_enabled: allowlist,
      blocklist_enabled: blocklist,
      max_transfer_amount: maxTransferAmount,
      allow_confidential: allowConfidential,
    },
  );
}

/** Block a wallet, with the reason recorded on-chain: it can neither send nor receive this token. */
export async function blockWallet({ authority, mint, wallet, reasonCode, caseRef: ref }) {
  return instruction(
    "block_wallet",
    { authority, mint, wallet, policy_config: await pdas.policy(mint), block_entry: await pdas.block(mint, wallet) },
    { reason_code: reasonCode, case_ref: ref },
  );
}

async function freezeAccounts(mint, tokenAccount, authority) {
  return {
    authority,
    mint,
    token_account: tokenAccount,
    policy_config: await pdas.policy(mint),
    freeze_authority: await pdas.freezeAuthority(mint),
    freeze_record: await pdas.freezeRecord(mint, tokenAccount),
    // Since 1.0.0-rc.2: a thaw is refused while this record exists. The playground never forfeits.
    forfeiture_record: await pdas.forfeiture(mint, tokenAccount),
  };
}

/** Freeze a token account through the freeze authority Vigilantis holds for the mint. */
export async function freezeTokenAccount({ authority, mint, tokenAccount, reasonCode, caseRef: ref }) {
  return instruction("freeze_token_account", await freezeAccounts(mint, tokenAccount, authority), { reason_code: reasonCode, case_ref: ref });
}

/** Thaw a token account Vigilantis froze. */
export async function thawTokenAccount({ authority, mint, tokenAccount, reasonCode, caseRef: ref }) {
  return instruction("thaw_token_account", await freezeAccounts(mint, tokenAccount, authority), { reason_code: reasonCode, case_ref: ref });
}

async function pauseAccounts(mint, authority) {
  return { authority, mint, policy_config: await pdas.policy(mint), pause_authority: await pdas.pauseAuthority(mint) };
}

/** Pause every transfer of a Pausable mint whose pause authority is Vigilantis. */
export async function pause({ authority, mint, reasonCode, caseRef: ref }) {
  return instruction("pause", await pauseAccounts(mint, authority), { reason_code: reasonCode, case_ref: ref });
}

/** Resume transfers. */
export async function resume({ authority, mint, reasonCode, caseRef: ref }) {
  return instruction("resume", await pauseAccounts(mint, authority), { reason_code: reasonCode, case_ref: ref });
}

/**
 * A public Token-2022 `TransferChecked` of a mint whose hook is Vigilantis, with the accounts the
 * hook reads appended in the order of Vigilantis's meta list (policy, sender's, recipient's and
 * authority's block entries, recipient's allow entry), then the hook program and the meta list, as
 * Token-2022 expects them.
 */
export async function transferChecked({ mint, source, destination, authority, sourceOwner, destinationOwner, amount, decimals }) {
  const ix = getTransferCheckedInstruction(
    { source, mint, destination, authority, amount, decimals },
    { programAddress: TOKEN_2022_PROGRAM_ADDRESS },
  );
  const extra = [
    await pdas.policy(mint),
    await pdas.block(mint, sourceOwner),
    await pdas.block(mint, destinationOwner),
    await pdas.allow(mint, destinationOwner),
    await pdas.block(mint, authority.address),
    VIGILANTIS_PROGRAM_ADDRESS,
    await pdas.metaList(mint),
  ];
  return { ...ix, accounts: [...ix.accounts, ...extra.map((a) => ({ address: a, role: AccountRole.READONLY }))] };
}

/** The name and message of a Vigilantis error code (6000 and up), or null. */
export function vigilantisError(code) {
  const e = idl.errors.find((x) => x.code === code);
  return e ? { name: e.name, message: e.msg } : null;
}
