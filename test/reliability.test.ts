// SPDX-License-Identifier: BUSL-1.1
//
// Integration tests for what 3.2 adds: one signing request per signer for a whole transfer,
// cleanup when a step fails halfway, recovering proof accounts left by a process that stopped,
// priority fees, and the checks that stop a doomed transfer before anything is signed.
// Require a CT-capable validator:
//   TOKEN_2022_SO=test/fixtures/spl_token_2022.so npm run validator
//   CT_LOCAL_PROGRAM=1 npm test
import { getTransferSolInstruction } from "@solana-program/system";
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS } from "@solana-program/zk-elgamal-proof";
import {
  address,
  lamports,
  sequentialInstructionPlan,
  type Address,
  type Instruction,
  type KeyPairSigner,
  type Signature,
  type TransactionModifyingSigner,
} from "@solana/kit";
import { TOKEN_2022_PROGRAM_ADDRESS, fetchToken, findAssociatedTokenPda } from "@solana-program/token-2022";
import { expect } from "chai";

import {
  applyPendingBalance,
  configureAccount,
  decryptBalance,
  deposit,
  deriveConfidentialKeys,
  isConfidentialTransfersError,
  recoverProofAccounts,
  transfer,
  withdraw,
  type ConfidentialTransfersError,
} from "../src/index";
import { getConfidentialTransferProofFlow, type ProofFlow } from "../src/internal/confidentialTransferProof";
import { executeProofFlow, sendSingleTransaction } from "../src/internal/send";
import { createConfidentialMint, fundedSigner, mintPublicTokens, rpc, rpcSubscriptions } from "./_helpers";

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

/**
 * A keypair behind kit's TransactionModifyingSigner interface (what a browser wallet gives). The
 * counts live outside the signer, because kit freezes signer objects.
 */
function walletLike(keypair: KeyPairSigner) {
  const counts = { requests: 0, transactions: 0 };
  const signer: TransactionModifyingSigner = {
    address: keypair.address,
    async modifyAndSignTransactions(txs) {
      counts.requests += 1;
      counts.transactions += txs.length;
      const dictionaries = await keypair.signTransactions(txs as never);
      return txs.map((tx, i) =>
        Object.freeze({ ...tx, signatures: Object.freeze({ ...tx.signatures, ...dictionaries[i] }) }),
      ) as never;
    },
  };
  return { signer, counts };
}

async function rejection(promise: Promise<unknown>): Promise<ConfidentialTransfersError> {
  try {
    await promise;
  } catch (e) {
    if (isConfidentialTransfersError(e)) return e;
    throw e;
  }
  throw new Error("expected the call to reject");
}

async function existing(addresses: readonly Address[]): Promise<Address[]> {
  const { value } = await rpc.getMultipleAccounts([...addresses], { encoding: "base64" }).send();
  return addresses.filter((_, i) => value[i] != null);
}

/** Alice with `amount` in her confidential available balance, and Bob configured to receive. */
async function aliceAndBob(amount = 1000n, bobMaxCredits?: number) {
  const payer = await fundedSigner(5n);
  const alice = await fundedSigner();
  const bob = await fundedSigner();
  const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
  const { token } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
  await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint, maximumPendingBalanceCreditCounter: bobMaxCredits });
  await mintPublicTokens({ payer, mint, token, mintAuthority, amount });
  await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount, decimals });
  await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });
  return { payer, alice, bob, mint, decimals, aliceToken: token };
}

/** The proof flow of a 10-unit transfer from Alice to Bob, built but not sent. */
async function transferFlow(payer: KeyPairSigner, alice: KeyPairSigner, bob: KeyPairSigner, mint: Address) {
  const keys = await deriveConfidentialKeys({ signer: alice });
  const ata = async (owner: Address) =>
    (await findAssociatedTokenPda({ owner, mint, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS }))[0];
  const [aliceToken, bobToken] = await Promise.all([ata(alice.address), ata(bob.address)]);
  const [source, dest] = await Promise.all([fetchToken(rpc, aliceToken), fetchToken(rpc, bobToken)]);
  return getConfidentialTransferProofFlow({
    payer,
    rpc,
    sourceToken: aliceToken,
    mint,
    destinationToken: bobToken,
    sourceTokenAccount: source.data,
    destinationTokenAccount: dest.data,
    authority: alice,
    amount: 10n,
    sourceElgamalKeypair: keys.elgamalKeypair,
    aesKey: keys.aesKey,
  });
}

describeOnChain("reliability (integration)", function () {
  this.timeout(240000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("asks a wallet once for a whole transfer and once for a whole withdraw", async () => {
    const { alice, bob, mint, decimals } = await aliceAndBob();
    const { signer: wallet, counts } = walletLike(alice); // Alice pays and signs, as in a browser
    const keys = await deriveConfidentialKeys({ signer: alice }); // a web app does this once

    // One transaction each, the proofs inside.
    const t = await transfer({ rpc, rpcSubscriptions, payer: wallet, owner: wallet, mint, destinationOwner: bob.address, amount: 300n, keys });
    expect(counts.requests).to.equal(1);
    expect(t.signatures.length).to.equal(1);
    const w = await withdraw({ rpc, rpcSubscriptions, payer: wallet, owner: wallet, mint, amount: 200n, decimals, keys });
    expect(counts.requests).to.equal(2);
    expect(w.signatures.length).to.equal(1);
    expect(counts.transactions).to.equal(2);

    // With proof accounts: several transactions, still one request each.
    const t2 = await transfer({ rpc, rpcSubscriptions, payer: wallet, owner: wallet, mint, destinationOwner: bob.address, amount: 100n, keys, singleTransaction: false });
    expect(counts.requests).to.equal(3);
    expect(t2.signatures.length).to.be.greaterThan(1);
    const w2 = await withdraw({ rpc, rpcSubscriptions, payer: wallet, owner: wallet, mint, amount: 100n, decimals, keys, singleTransaction: false });
    expect(counts.requests).to.equal(4);
    expect(w2.signatures.length).to.be.greaterThan(1);
    expect(counts.transactions).to.equal(2 + t2.signatures.length + w2.signatures.length);

    expect(await decryptBalance({ rpc, owner: alice, mint })).to.equal(300n);
    expect([...t.proofAccountsLeftOpen, ...t2.proofAccountsLeftOpen, ...w2.proofAccountsLeftOpen]).to.deep.equal([]);
  });

  it("falls back to proof accounts, before signing anything, when one transaction would be too large", async () => {
    const { payer } = await aliceAndBob();
    const { signer: wallet, counts } = walletLike(payer);
    const tooLarge: Instruction = { programAddress: payer.address, accounts: [], data: new Uint8Array(4100) };
    const sent = await sendSingleTransaction({ rpc, rpcSubscriptions, payer: wallet, operation: "test" }, [tooLarge]);
    expect(sent).to.equal(null);
    expect(counts.requests).to.equal(0);
  });

  it("closes the proof accounts and names the step when the transfer step fails", async () => {
    const { payer, alice, bob, mint } = await aliceAndBob();
    const flow = await transferFlow(payer, alice, bob, mint);
    // Replace the transfer with an instruction the chain refuses (more lamports than exist).
    const failing: ProofFlow = {
      ...flow,
      action: getTransferSolInstruction({ source: payer, destination: bob.address, amount: lamports(10n ** 18n) }),
    };
    const before = await rpc.getBalance(payer.address).send();
    const err = await rejection(
      executeProofFlow({ rpc, rpcSubscriptions, payer, operation: "transfer" }, failing, "transfer"),
    );
    expect(err.code).to.equal("TRANSACTION_FAILED");
    expect(err.step).to.equal("transfer");
    expect(err.logs?.length).to.be.greaterThan(0);
    expect(err.proofAccounts?.closed).to.have.members(flow.proofAccounts);
    expect(err.proofAccounts?.leftOpen).to.deep.equal([]);
    expect(await existing(flow.proofAccounts)).to.deep.equal([]);
    // The rent came back: the payer is out only the transaction fees.
    const after = await rpc.getBalance(payer.address).send();
    expect(Number(before.value - after.value)).to.be.lessThan(100_000);
  });

  it("closes what it created when a step fails while setting up the proofs", async () => {
    const { payer, alice, bob, mint } = await aliceAndBob();
    const flow = await transferFlow(payer, alice, bob, mint);
    // After the proofs, a step the chain refuses: a System instruction with 900 bytes of nonsense,
    // too large to share a transaction with the transfer, so it runs on its own between the two.
    const failing: ProofFlow = {
      ...flow,
      setup: sequentialInstructionPlan([
        flow.setup,
        { programAddress: address("11111111111111111111111111111111"), accounts: [], data: new Uint8Array(900).fill(7) },
      ]),
    };
    const err = await rejection(executeProofFlow({ rpc, rpcSubscriptions, payer, operation: "transfer" }, failing, "transfer"));
    expect(err.step).to.equal("proofs");
    expect(err.signatures?.length).to.be.greaterThan(0); // the proof transactions landed
    expect(err.proofAccounts?.closed).to.have.members(flow.proofAccounts);
    expect(err.proofAccounts?.leftOpen).to.deep.equal([]);
    expect(await existing(flow.proofAccounts)).to.deep.equal([]);
  });

  it("recoverProofAccounts closes proof accounts a stopped process left behind", async () => {
    const { payer, alice, bob, mint } = await aliceAndBob();
    const flow = await transferFlow(payer, alice, bob, mint);
    // Only the proof setup, as if the process had stopped right after it.
    await executeProofFlow(
      { rpc, rpcSubscriptions, payer, operation: "test" },
      { proofAccounts: [], setup: flow.setup, cleanup: [], action: getTransferSolInstruction({ source: payer, destination: payer.address, amount: lamports(0n) }) },
      "test",
    );
    expect(await existing(flow.proofAccounts)).to.have.members(flow.proofAccounts);

    const recovered = await recoverProofAccounts({ rpc, rpcSubscriptions, authority: payer });
    expect(recovered.closed).to.have.members(flow.proofAccounts);
    expect(recovered.leftOpen).to.deep.equal([]);
    expect(recovered.lamports > 0n).to.equal(true);
    expect(await existing(flow.proofAccounts)).to.deep.equal([]);
    // Nothing left: a second run finds nothing.
    expect((await recoverProofAccounts({ rpc, rpcSubscriptions, authority: payer })).closed).to.deep.equal([]);
  });

  it("adds a priority fee to every transaction that has room for one", async () => {
    const { payer, alice, bob, mint } = await aliceAndBob();
    const priorityFees = async (signatures: readonly Signature[]) =>
      Promise.all(
        signatures.map(async (s) => {
          const tx = await rpc.getTransaction(s, { commitment: "confirmed", maxSupportedTransactionVersion: 1, encoding: "json" }).send();
          const signers = (tx as unknown as { transaction: { signatures: string[] } }).transaction.signatures.length;
          return tx!.meta!.fee - BigInt(signers) * 5000n; // the part above the base fee
        }),
      );

    // One transaction: the fee is paid on its estimated compute units.
    const single = await transfer({
      rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 100n,
      computeUnitPrice: 50_000n,
    });
    const [fee] = await priorityFees(single.signatures);
    expect(single.signatures.length).to.equal(1);
    expect(fee > 0n).to.equal(true);

    // With proof accounts, the range-proof verification is too large to take the extra instruction;
    // all others pay it.
    const { signatures } = await transfer({
      rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 100n,
      computeUnitPrice: 50_000n, singleTransaction: false,
    });
    const prioritized = (await priorityFees(signatures)).filter((f) => f > 0n).length;
    expect(prioritized).to.equal(signatures.length - 1);
    expect(await decryptBalance({ rpc, owner: alice, mint })).to.equal(800n);
  });

  it("stops before signing anything when the recipient's pending balance is full", async () => {
    const { payer, alice, bob, mint } = await aliceAndBob(1000n, 1);
    await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 1n });
    const { signer: wallet, counts } = walletLike(alice);
    const keys = await deriveConfidentialKeys({ signer: alice });
    const err = await rejection(
      transfer({ rpc, rpcSubscriptions, payer: wallet, owner: wallet, mint, destinationOwner: bob.address, amount: 1n, keys }),
    );
    expect(err.code).to.equal("PENDING_BALANCE_LIMIT");
    expect(err.message).to.contain("applyPendingBalance");
    expect(counts.requests).to.equal(0);

    // Once Bob applies, the next transfer goes through.
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 1n });
  });

  it("names the missing recipient account and the short public balance", async () => {
    const { payer, alice, mint, decimals } = await aliceAndBob(100n);
    const stranger = await fundedSigner();
    const missing = await rejection(
      transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: stranger.address, amount: 1n }),
    );
    expect(missing.code).to.equal("ACCOUNT_NOT_FOUND");
    expect(missing.message).to.contain("recipient");

    const short = await rejection(deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 1n, decimals }));
    expect(short.code).to.equal("INSUFFICIENT_FUNDS"); // all 100 were deposited already
  });

  it("leaves no proof accounts behind after a normal transfer and withdraw", async () => {
    const { payer, alice, bob, mint, decimals } = await aliceAndBob();
    await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 10n });
    await withdraw({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 10n, decimals });
    const left = await rpc
      .getProgramAccounts(ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS, {
        encoding: "base64",
        dataSlice: { offset: 0, length: 0 },
        filters: [{ memcmp: { offset: 0n, bytes: payer.address as never, encoding: "base58" } }],
      })
      .send();
    expect(left).to.have.length(0);
  });
});
