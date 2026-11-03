// SPDX-License-Identifier: BUSL-1.1
//
// Transfer-hook accounts. The unit tests resolve hand-made extra-account-meta lists, one entry
// type at a time, against what the SPL interface (spl-tlv-account-resolution) resolves them to.
// The integration test runs confidential transfers through Sentinel, a real hook, on a local
// validator started with SENTINEL_SO (see scripts/start-test-validator.sh).
import {
  AccountRole,
  address,
  generateKeyPairSigner,
  getAddressEncoder,
  getProgramDerivedAddress,
  type AccountMeta,
  type AccountSignerMeta,
  type Address,
  type Instruction,
} from "@solana/kit";
import { expect } from "chai";

import { TOKEN_2022_PROGRAM_ADDRESS, extension, findAssociatedTokenPda } from "@solana-program/token-2022";

import { applyPendingBalance } from "../src/applyPendingBalance";
import { configureAccount } from "../src/configureAccount";
import { decryptBalance } from "../src/decryptBalance";
import { deposit } from "../src/deposit";
import { isConfidentialTransfersError } from "../src/errors";
import {
  assertHookAccountsAreNotSigners,
  findExtraAccountMetaListPda,
  resolveExtraAccounts,
  resolveTransferHookAccounts,
} from "../src/internal/transferHook";
import { transfer } from "../src/transfer";
import { createConfidentialMint, fundedSigner, mintPublicTokens, rpc, rpcSubscriptions, sendInstructions } from "./_helpers";
import { accountsRpc, mintBytes, rejection, tokenAccountBytes, walletLike } from "./_offline";

const EXECUTE = [105, 37, 101, 197, 75, 251, 102, 26];
const encode = (a: Address) => new Uint8Array(getAddressEncoder().encode(a));
const u32 = (n: number) => new Uint8Array(new Uint32Array([n]).buffer);

/** One 35-byte entry: type, 32-byte address config, is_signer, is_writable. */
function entry(kind: number, config: number[] | Uint8Array, flags: { signer?: boolean; writable?: boolean } = {}) {
  const bytes = new Uint8Array(35);
  bytes[0] = kind;
  bytes.set(config, 1);
  bytes[33] = flags.signer ? 1 : 0;
  bytes[34] = flags.writable ? 1 : 0;
  return bytes;
}

/** A TLV account with the Execute entry, after an optional entry of another type. */
function metaList(entries: Uint8Array[], options: { otherFirst?: boolean; claim?: number } = {}) {
  const parts: number[] = [];
  if (options.otherFirst) parts.push(...[1, 2, 3, 4, 5, 6, 7, 8], ...u32(3), 9, 9, 9);
  const value = [...u32(options.claim ?? entries.length), ...entries.flatMap((e) => [...e])];
  parts.push(...EXECUTE, ...u32(value.length), ...value);
  return new Uint8Array(parts);
}

describe("transfer-hook accounts", () => {
  let accounts: { source: Address; mint: Address; destination: Address; owner: Address; list: Address; hook: Address };
  const instructionData = new Uint8Array([...EXECUTE, 255, 255, 255, 255, 255, 255, 255, 255]);
  const store = new Map<Address, Uint8Array>();
  const resolve = (data: Uint8Array) =>
    resolveExtraAccounts({
      mint: accounts.mint,
      hookProgram: accounts.hook,
      metaListData: data,
      executeAccounts: [accounts.source, accounts.mint, accounts.destination, accounts.owner, accounts.list].map((address) => ({
        address,
        role: AccountRole.READONLY,
      })),
      instructionData,
      fetch: async (a) => store.get(a) ?? null,
    });
  const refused = async (data: Uint8Array) => {
    try {
      await resolve(data);
    } catch (e) {
      return isConfidentialTransfersError(e, "ACCOUNT_NOT_FOUND") ? e.message : `wrong error: ${String(e)}`;
    }
    return "resolved";
  };

  before(async () => {
    const [source, mint, destination, owner, list, hook] = await Promise.all(
      Array.from({ length: 6 }, async () => (await generateKeyPairSigner()).address),
    );
    accounts = { source, mint, destination, owner, list, hook };
  });

  it("resolves a literal address, never as a signer, and writable only where the SPL resolver allows", async () => {
    const literal = (await generateKeyPairSigner()).address;
    const [resolved, mint] = await resolve(
      metaList([entry(0, encode(literal), { signer: true, writable: true }), entry(0, encode(accounts.mint), { writable: true })]),
    );
    expect(resolved).to.deep.equal({ address: literal, role: AccountRole.WRITABLE });
    // The mint is read-only in the Execute instruction, so it stays read-only, as in the SPL resolver.
    expect(mint).to.deep.equal({ address: accounts.mint, role: AccountRole.READONLY });
  });

  it("resolves a PDA of the hook program from a literal and an account key", async () => {
    const config = [1, 5, ...new TextEncoder().encode("block"), 3, 0];
    const [expected] = await getProgramDerivedAddress({
      programAddress: accounts.hook,
      seeds: [new TextEncoder().encode("block"), encode(accounts.source)],
    });
    expect((await resolve(metaList([entry(1, config)])))[0]!.address).to.equal(expected);
  });

  it("resolves a PDA of another program in the list, with seeds from instruction and account data", async () => {
    const other = (await generateKeyPairSigner()).address;
    const destinationData = new Uint8Array(80).map((_, i) => i);
    store.set(accounts.destination, destinationData);
    // Entry 5: the other program. Entry 6: its PDA from 8 bytes of instruction data and 4 bytes
    // of the destination's data (offset 40).
    const pda = entry(128 + 5, [2, 8, 8, 4, 2, 40, 4]);
    const [expected] = await getProgramDerivedAddress({
      programAddress: other,
      seeds: [instructionData.subarray(8, 16), destinationData.subarray(40, 44)],
    });
    const resolved = await resolve(metaList([entry(0, encode(other)), pda], { otherFirst: true }));
    expect(resolved[1]!.address).to.equal(expected);
  });

  it("resolves an address stored in an account's data (PubkeyData)", async () => {
    const stored = (await generateKeyPairSigner()).address;
    store.set(accounts.destination, new Uint8Array([...new Uint8Array(32), ...encode(stored)]));
    const [resolved] = await resolve(metaList([entry(2, [2, 2, 32])]));
    expect(resolved!.address).to.equal(stored);
  });

  it("refuses, before signing, entries that do not resolve", async () => {
    store.set(accounts.destination, new Uint8Array(10));
    expect(await refused(metaList([entry(2, [1, 0])]))).to.match(/instruction data is too short/);
    expect(await refused(metaList([entry(2, [2, 2, 0])]))).to.match(/data of account 2 is too short/);
    expect(await refused(metaList([entry(1, [4, 2, 0, 32])]))).to.match(/data of account 2 is too short/);
    expect(await refused(metaList([entry(1, [4, 3, 0, 32])]))).to.match(/does not exist/);
    expect(await refused(metaList([entry(1, [3, 9])]))).to.match(/account 9, which is not in the list/);
    expect(await refused(metaList([entry(7, [])]))).to.match(/unknown type 7/);
    expect(await refused(metaList([entry(0, encode(accounts.owner))], { claim: 2 }))).to.match(/claims 2 entries/);
    expect(await refused(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, ...u32(0)]))).to.match(/no entry for the Execute instruction/);
  });

  it("refuses a list that resolves to a signer of the transaction, such as the payer", async () => {
    const payer = (await generateKeyPairSigner()).address;
    const signers = [payer, accounts.owner];
    // A literal entry naming the payer, marked as a signer: the hook would get the payer's signature.
    const resolved = await resolve(metaList([entry(0, encode(payer), { signer: true, writable: true })]));
    let error: unknown;
    try {
      assertHookAccountsAreNotSigners(resolved, signers, "transfer");
    } catch (e) {
      error = e;
    }
    expect(isConfidentialTransfersError(error, "INVALID_INPUT")).to.equal(true);
    expect((error as Error).message).to.contain(payer);
    // The owner too, and an address stored in the source account's data is no way around it.
    store.set(accounts.source, new Uint8Array([...new Uint8Array(32), ...encode(accounts.owner)]));
    const owner = await resolve(metaList([entry(2, [2, 0, 32])]));
    expect(() => assertHookAccountsAreNotSigners(owner, signers, "transfer")).to.throw(/also signs this transaction/);
    // PDAs and other accounts are fine.
    const pda = await resolve(metaList([entry(1, [1, 5, ...new TextEncoder().encode("block"), 3, 0])]));
    expect(() => assertHookAccountsAreNotSigners(pda, signers, "transfer")).not.to.throw();
  });

  it("makes transfer() refuse such a hook before the wallet is asked for anything", async () => {
    const [payerKey, ownerKey, recipient, mintKey, hook] = await Promise.all(Array.from({ length: 5 }, () => generateKeyPairSigner()));
    const { signer: payer, counts: payerCounts } = walletLike(payerKey);
    const { signer: owner, counts: ownerCounts } = walletLike(ownerKey);
    const mint = mintKey.address;
    const ata = async (o: Address) => (await findAssociatedTokenPda({ owner: o, mint, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS }))[0];
    const metaListAddress = await findExtraAccountMetaListPda(mint, hook.address);
    const chain = accountsRpc(
      new Map([
        [mint, { data: mintBytes([extension("TransferHook", { authority: hook.address, programId: hook.address })]) }],
        [await ata(owner.address), { data: tokenAccountBytes(mint, owner.address) }],
        [await ata(recipient.address), { data: tokenAccountBytes(mint, recipient.address) }],
        [metaListAddress, { data: metaList([entry(0, encode(payer.address), { signer: true, writable: true })]), owner: hook.address }],
      ]),
    );
    const error = await rejection(
      transfer({ rpc: chain, rpcSubscriptions: {} as never, payer, owner, mint, destinationOwner: recipient.address, amount: 1n }),
    );
    // INVALID_INPUT, not CANNOT_SIGN_MESSAGES: refused before the owner's keys were asked for.
    expect(error.code).to.equal("INVALID_INPUT");
    expect(error.message).to.contain("transfer hook asks for");
    expect(payerCounts.requests + ownerCounts.requests).to.equal(0);
  });
});

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;
const SENTINEL = address("5fH1jj6XeZC96jPCxKiSb2onAXcs7f4rMeqMmSsP6puD");
const SYSTEM = address("11111111111111111111111111111111");

/** Sentinel's `initialize_policy` or `update_policy`: lists off, a limit, the confidential opt-in. */
function policyData(discriminator: number[], allowConfidential: boolean) {
  return new Uint8Array([...discriminator, 0, 0, ...new Uint8Array(new BigUint64Array([1_000_000n]).buffer), allowConfidential ? 1 : 0]);
}

describeOnChain("transfer hook (integration)", function () {
  this.timeout(240000);

  before(async function () {
    try {
      await rpc.getVersion().send();
      const program = await rpc.getAccountInfo(SENTINEL, { encoding: "base64" }).send();
      if (program.value == null) this.skip(); // validator started without SENTINEL_SO
    } catch {
      this.skip();
    }
  });

  it("refuses a hook mint whose extra-account-meta list was never created", async () => {
    const payer = await fundedSigner();
    const { mint } = await createConfidentialMint(payer, 2, undefined, SENTINEL);
    const [source, destination] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
    let error: unknown;
    try {
      await resolveTransferHookAccounts({ rpc, mint, sourceToken: source.address, destinationToken: destination.address, owner: payer.address });
    } catch (e) {
      error = e;
    }
    expect(isConfidentialTransfersError(error, "ACCOUNT_NOT_FOUND")).to.equal(true);
    expect(String((error as Error).message)).to.match(/has no extra-account-meta list/);
  });

  it("resolves Sentinel's accounts, and cleans up when the hook refuses a transfer", async () => {
    const payer = await fundedSigner();
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer, 2, undefined, SENTINEL);
    const [policy] = await getProgramDerivedAddress({ programAddress: SENTINEL, seeds: [new TextEncoder().encode("policy"), encode(mint)] });
    const [metas] = await getProgramDerivedAddress({ programAddress: SENTINEL, seeds: [new TextEncoder().encode("extra-account-metas"), encode(mint)] });
    const sentinel = (data: Uint8Array, accounts: Array<AccountMeta | AccountSignerMeta>): Instruction => ({ programAddress: SENTINEL, accounts, data });
    const authority = { address: mintAuthority.address, role: AccountRole.WRITABLE_SIGNER, signer: mintAuthority } as const;
    await sendInstructions(mintAuthority, [
      sentinel(policyData([9, 186, 86, 225, 129, 162, 231, 56], false), [
        authority,
        { address: mint, role: AccountRole.READONLY },
        { address: policy, role: AccountRole.WRITABLE },
        { address: SYSTEM, role: AccountRole.READONLY },
      ]),
      sentinel(new Uint8Array([92, 197, 174, 197, 41, 124, 19, 3]), [
        authority,
        { address: metas, role: AccountRole.WRITABLE },
        { address: mint, role: AccountRole.READONLY },
        { address: SYSTEM, role: AccountRole.READONLY },
      ]),
    ]);

    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    const { token: bobToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    await mintPublicTokens({ payer, mint, token: aliceToken, mintAuthority, amount: 500n });
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 500n, decimals });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });

    const hookAccounts = await resolveTransferHookAccounts({ rpc, mint, sourceToken: aliceToken, destinationToken: bobToken, owner: alice.address });
    expect(hookAccounts.slice(-2).map((a) => a.address)).to.deep.equal([SENTINEL, metas]);
    expect(hookAccounts.map((a) => a.address)).to.include(policy);

    // Confidential transfers are off in the policy, so the hook refuses. In one transaction the
    // refusal comes in its simulation, before anything is signed or created.
    const refusal = async (singleTransaction: boolean) => {
      try {
        await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 200n, singleTransaction });
      } catch (e) {
        return e;
      }
      throw new Error("the hook did not refuse");
    };
    const single = await refusal(true);
    expect(isConfidentialTransfersError(single, "TRANSACTION_FAILED")).to.equal(true);
    expect(isConfidentialTransfersError(single) && single.proofAccounts).to.equal(undefined);
    // With proof accounts, the refusal comes at the transfer step, and the proof accounts go.
    const multiple = await refusal(false);
    expect(isConfidentialTransfersError(multiple, "TRANSACTION_FAILED")).to.equal(true);
    expect(isConfidentialTransfersError(multiple) && multiple.proofAccounts?.leftOpen).to.deep.equal([]);

    await sendInstructions(mintAuthority, [
      sentinel(policyData([212, 245, 246, 7, 163, 151, 18, 57], true), [
        { address: mintAuthority.address, role: AccountRole.READONLY_SIGNER, signer: mintAuthority },
        { address: mint, role: AccountRole.READONLY },
        { address: policy, role: AccountRole.WRITABLE },
      ]),
    ]);
    await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 200n });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    expect(await decryptBalance({ rpc, owner: bob, mint })).to.equal(200n);
  });
});
