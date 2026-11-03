// SPDX-License-Identifier: BUSL-1.1
//
// Validator-free tests for the sending layer and the typed errors: signing several transactions
// in one request per signer, retrying only what is safe to retry, and the input checks that fail
// before anything touches the network.
import { getTransferSolInstruction } from "@solana-program/system";
import {
  AccountRole,
  SOLANA_ERROR__BLOCK_HEIGHT_EXCEEDED,
  SOLANA_ERROR__JSON_RPC__INVALID_PARAMS,
  SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR,
  SolanaError,
  address,
  appendTransactionMessageInstructions,
  createTransactionMessage,
  generateKeyPairSigner,
  isFullySignedTransaction,
  lamports,
  pipe,
  sequentialInstructionPlan,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Blockhash,
  type Instruction,
  type KeyPairSigner,
  type Signature,
  type TransactionModifyingSigner,
} from "@solana/kit";
import { expect } from "chai";

import { ConfidentialTransfersError, configureAccount, deposit, isConfidentialTransfersError, transfer } from "../src/index";
import type { ProofFlow } from "../src/internal/confidentialTransferProof";
import {
  closeProofAccounts,
  executeProofFlow,
  outcomeAfterExpiry,
  outcomeOfSentTransaction,
  refusedBeforeForwarding,
  sendInstructions,
  signTransactionMessagesTogether,
  withRetries,
} from "../src/internal/send";
import { accountsOf, fakeNetwork, proofAccountsExist, walletLike as countingWallet, type NetworkScript } from "./_offline";

const lifetime = { blockhash: "11111111111111111111111111111111" as Blockhash, lastValidBlockHeight: 100n };

function walletLike(keypair: KeyPairSigner) {
  const counts = { requests: 0, transactions: 0 };
  const signer: TransactionModifyingSigner = {
    address: keypair.address,
    async modifyAndSignTransactions(txs) {
      counts.requests += 1;
      counts.transactions += txs.length;
      const dictionaries = await keypair.signTransactions(txs as never);
      return txs.map((tx, i) => Object.freeze({ ...tx, signatures: { ...tx.signatures, ...dictionaries[i] } })) as never;
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

describe("signing several transactions together", () => {
  it("asks a wallet once for every transaction it signs, and still lets keypairs co-sign", async () => {
    const [walletKey, other, extra] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner(), generateKeyPairSigner()]);
    const { signer: wallet, counts } = walletLike(walletKey);
    const message = (cosigner?: KeyPairSigner) =>
      pipe(
        createTransactionMessage({ version: 0 }),
        (tx) => setTransactionMessageFeePayerSigner(wallet, tx),
        (tx) => setTransactionMessageLifetimeUsingBlockhash(lifetime, tx),
        (tx) =>
          appendTransactionMessageInstructions(
            [getTransferSolInstruction({ source: cosigner ?? wallet, destination: other.address, amount: lamports(1n) })],
            tx,
          ),
      );
    const transactions = await signTransactionMessagesTogether([message(), message(extra), message()], lifetime);
    expect(counts.requests).to.equal(1);
    expect(counts.transactions).to.equal(3);
    expect(transactions.every((tx) => isFullySignedTransaction(tx))).to.equal(true);
    expect(transactions.every((tx) => tx.lifetimeConstraint.blockhash === lifetime.blockhash)).to.equal(true);
  });
});

describe("retries", () => {
  it("runs again after an expired transaction, up to the limit", async () => {
    let calls = 0;
    const result = await withRetries(2, async () => {
      calls += 1;
      if (calls < 3) throw new ConfidentialTransfersError("TRANSACTION_EXPIRED", "expired");
      return "ok";
    });
    expect(result).to.equal("ok");
    expect(calls).to.equal(3);
  });

  it("does not retry by default, and never retries a failed transaction", async () => {
    let calls = 0;
    const expired = await rejection(
      withRetries(undefined, async () => {
        calls += 1;
        throw new ConfidentialTransfersError("TRANSACTION_EXPIRED", "expired");
      }),
    );
    expect(expired.retryable).to.equal(true);
    expect(calls).to.equal(1);

    calls = 0;
    const failed = await rejection(
      withRetries(5, async () => {
        calls += 1;
        throw new ConfidentialTransfersError("TRANSACTION_FAILED", "refused");
      }),
    );
    expect(failed.retryable).to.equal(false);
    expect(calls).to.equal(1);
  });
});

describe("a blockhash that expired before a confirmation arrived", () => {
  const signature = "1111111111111111111111111111111111111111111111111111111111111111" as Signature;
  // The blockhash is valid up to block height 100; the RPC reports height 101 at slot 500, and
  // answers status reads at slot 600 unless told otherwise.
  const rpcAnswering = (answers: Array<unknown | Error>, statusSlots: bigint[] = [600n]) => {
    let call = 0;
    return {
      getEpochInfo: () => ({ send: async () => ({ blockHeight: 101n, absoluteSlot: 500n }) }),
      getSignatureStatuses: () => ({
        send: async () => {
          const n = call++;
          const answer = answers[Math.min(n, answers.length - 1)];
          if (answer instanceof Error) throw answer;
          return { context: { slot: statusSlots[Math.min(n, statusSlots.length - 1)] }, value: [answer] };
        },
      }),
    } as never;
  };
  const outcome = (rpc: never) => outcomeAfterExpiry(rpc, signature, 100n, 0);

  it("is expired only when the RPC has no record of the transaction", async () => {
    expect(await outcome(rpcAnswering([null]))).to.equal("not-found");
  });

  it("does not take \"not found\" from a node behind the one that saw the expiry", async () => {
    // Behind a load balancer: the status node lags the expiry slot, then catches up and finds it.
    const landedLate = rpcAnswering([null, null, { err: null, confirmationStatus: "confirmed" }], [450n, 480n, 600n]);
    expect(await outcome(landedLate)).to.equal("landed");
    expect(await outcome(rpcAnswering([null], [450n]))).to.equal("unknown");
  });

  it("does not call an error on a transaction that is only processed final", async () => {
    const forkDropped = rpcAnswering([{ err: { InstructionError: [0, "Custom"] }, confirmationStatus: "processed" }, { err: null, confirmationStatus: "confirmed" }]);
    expect(await outcome(forkDropped)).to.equal("landed");
  });

  it("is a success when the transaction landed after all, so a retry does not send it twice", async () => {
    expect(await outcome(rpcAnswering([{ err: null, confirmationStatus: "confirmed" }]))).to.equal("landed");
    expect(
      await outcome(rpcAnswering([{ err: null, confirmationStatus: "processed" }, { err: null, confirmationStatus: "finalized" }])),
    ).to.equal("landed");
  });

  it("is a failure when the transaction landed with an error", async () => {
    expect(await outcome(rpcAnswering([{ err: { InstructionError: [0, "Custom"] }, confirmationStatus: "confirmed" }]))).to.equal("failed");
  });

  it("is unknown, and not retried, when the status cannot be read or stays processed", async () => {
    expect(await outcome(rpcAnswering([new Error("rate limited")]))).to.equal("unknown");
    expect(await outcome(rpcAnswering([{ err: null, confirmationStatus: "processed" }]))).to.equal("unknown");
  });
});

describe("input checks before the network", () => {
  const offline = { rpc: {} as never, rpcSubscriptions: {} as never };

  it("deposit refuses zero and more than 2^48 - 1", async () => {
    const owner = await generateKeyPairSigner();
    const mint = (await generateKeyPairSigner()).address;
    const zero = await rejection(deposit({ ...offline, payer: owner, owner, mint, amount: 0n, decimals: 2 }));
    expect(zero.code).to.equal("INVALID_INPUT");
    const big = await rejection(deposit({ ...offline, payer: owner, owner, mint, amount: 1n << 48n, decimals: 2 }));
    expect(big.code).to.equal("AMOUNT_TOO_LARGE");
    expect(big.operation).to.equal("deposit");
  });

  it("transfer refuses zero and a missing destination", async () => {
    const owner = await generateKeyPairSigner();
    const mint = (await generateKeyPairSigner()).address;
    expect((await rejection(transfer({ ...offline, payer: owner, owner, mint, destinationOwner: owner.address, amount: 0n }))).code).to.equal(
      "INVALID_INPUT",
    );
    expect((await rejection(transfer({ ...offline, payer: owner, owner, mint, amount: 1n }))).code).to.equal("INVALID_INPUT");
  });

  it("configureAccount refuses a pending-credit cap outside 1 to 2^16, before asking for keys", async () => {
    const owner = await generateKeyPairSigner();
    const mint = (await generateKeyPairSigner()).address;
    for (const cap of [65537, (1n << 16n) + 1n, 0, 1.5]) {
      const error = await rejection(configureAccount({ ...offline, payer: owner, owner, mint, maximumPendingBalanceCreditCounter: cap }));
      expect(error.code, String(cap)).to.equal("INVALID_INPUT");
      expect(error.message).to.contain("65536");
    }
  });

  it("errors are real Errors with a name, a code and the operation", () => {
    const error = new ConfidentialTransfersError("PENDING_BALANCE_LIMIT", "full", { operation: "transfer" });
    expect(error).to.be.instanceOf(Error);
    expect(error.name).to.equal("ConfidentialTransfersError");
    expect(isConfidentialTransfersError(error, "PENDING_BALANCE_LIMIT")).to.equal(true);
    expect(isConfidentialTransfersError(error, "INSUFFICIENT_FUNDS")).to.equal(false);
    expect(isConfidentialTransfersError(new Error("x"))).to.equal(false);
  });
});

describe("a transaction sent but not seen confirmed", () => {
  const polling = { intervalMs: 0, timeoutMs: 2000 };
  const lostConfirmation = () => new Error("websocket closed");
  const unreadable = (): never => {
    throw new Error("rate limited");
  };

  async function sendOne(script: NetworkScript, outcomePolling = polling) {
    const payer = await generateKeyPairSigner();
    const network = fakeNetwork(script);
    const ctx = { ...network, payer, operation: "deposit", outcomePolling };
    const instruction = getTransferSolInstruction({ source: payer, destination: payer.address, amount: lamports(1n) });
    return { network, run: () => sendInstructions(ctx, [instruction]) };
  }

  it("is reported as landed when its status shows it confirmed, though its confirmation was lost", async () => {
    const { network, run } = await sendOne({ confirm: lostConfirmation, status: () => ({ err: null, confirmationStatus: "confirmed" }) });
    expect(await run()).to.be.a("string");
    expect(network.calls.sent).to.have.length(1);
  });

  it("is reported as landed when the send failed with a 5xx but the transaction got through", async () => {
    const { network, run } = await sendOne({
      send: () => {
        throw new SolanaError(SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR, { headers: new Headers(), message: "Bad Gateway", statusCode: 502 });
      },
      status: () => ({ err: null, confirmationStatus: "finalized" }),
    });
    expect(await run()).to.be.a("string");
    expect(network.calls.subscriptions).to.equal(0);
  });

  it("is expired, and retryable, only once its blockhash expired with no trace of it", async () => {
    const { network, run } = await sendOne({ confirm: lostConfirmation, status: () => null, blockHeight: (n) => (n < 3 ? 99n : 101n) });
    const error = await rejection(run());
    expect(error.code).to.equal("TRANSACTION_EXPIRED");
    expect(error.retryable).to.equal(true);
    expect(error.signature).to.be.a("string");
    expect(network.calls.blockHeightReads).to.be.at.least(3); // it waited for the expiry
  });

  it("is a failure, with its logs, when it landed with an error", async () => {
    const { run } = await sendOne({
      confirm: lostConfirmation,
      status: () => ({ err: { InstructionError: [0, "Custom"] }, confirmationStatus: "confirmed" }),
    });
    const error = await rejection(run());
    expect(error.code).to.equal("TRANSACTION_FAILED");
    expect(error.logs).to.deep.equal(["Program log: failed on chain"]);
  });

  it("is reported distinctly, never retried, when its status cannot be read", async () => {
    const { network, run } = await sendOne(
      { send: () => { throw new TypeError("fetch failed"); }, status: unreadable, blockHeight: unreadable },
      { intervalMs: 0, timeoutMs: 0 },
    );
    let attempts = 0;
    const error = await rejection(withRetries(3, () => ((attempts += 1), run())));
    expect(error.code).to.equal("TRANSACTION_OUTCOME_UNKNOWN");
    expect(error.retryable).to.equal(false);
    expect(error.signature).to.be.a("string");
    expect(error.message).to.contain(error.signature!);
    expect(attempts).to.equal(1);
    expect(network.calls.sent).to.have.length(1);
  });

  it("is a failure at once when the node refuses the send", async () => {
    for (const refusal of [
      new SolanaError(SOLANA_ERROR__JSON_RPC__INVALID_PARAMS, { __serverMessage: "invalid transaction" }),
      new SolanaError(SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR, { headers: new Headers(), message: "Too Many Requests", statusCode: 429 }),
    ]) {
      const { network, run } = await sendOne({ send: () => { throw refusal; } });
      const error = await rejection(run());
      expect(error.code).to.equal("TRANSACTION_FAILED");
      expect(network.calls.statusReads).to.equal(0);
    }
  });

  it("tells a refusal from an error that may come after the node took the transaction", () => {
    const http = (statusCode: number) => new SolanaError(SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR, { headers: new Headers(), message: "", statusCode });
    expect(refusedBeforeForwarding(http(429))).to.equal(true);
    expect(refusedBeforeForwarding(new SolanaError(SOLANA_ERROR__JSON_RPC__INVALID_PARAMS, { __serverMessage: "" }))).to.equal(true);
    expect(refusedBeforeForwarding(http(503))).to.equal(false);
    expect(refusedBeforeForwarding(new TypeError("fetch failed"))).to.equal(false);
    expect(refusedBeforeForwarding(new SolanaError(SOLANA_ERROR__BLOCK_HEIGHT_EXCEEDED, { currentBlockHeight: 1n, lastValidBlockHeight: 0n }))).to.equal(false);
  });

  it("waits for the blockhash to expire before calling a transaction that is not found expired", async () => {
    const signature = "1111111111111111111111111111111111111111111111111111111111111111" as Signature;
    const heights = [90n, 100n, 101n, 101n];
    const rpc = {
      getSignatureStatuses: () => ({ send: async () => ({ context: { slot: 1000n }, value: [null] }) }),
      getEpochInfo: () => ({ send: async () => { const h = heights.shift()!; return { blockHeight: h, absoluteSlot: h }; } }),
    } as never;
    expect(await outcomeOfSentTransaction(rpc, signature, 100n, { intervalMs: 0 })).to.equal("not-found");
    expect(heights).to.deep.equal([]);
  });
});

describe("a transfer or withdraw whose own outcome is unknown", () => {
  const SYSTEM = address("11111111111111111111111111111111");
  // Each needs a transaction of its own, as the proofs do.
  const big = (fill: number): Instruction => ({ programAddress: SYSTEM, accounts: [], data: new Uint8Array(900).fill(fill) });

  async function flow() {
    const proofAccounts = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]).then((s) => s.map((k) => k.address));
    return { proofAccounts, setup: sequentialInstructionPlan([big(1)]), action: big(2), cleanup: [big(3)] } as ProofFlow;
  }

  it("leaves its proof accounts open and names the transaction to look up", async () => {
    const payer = await generateKeyPairSigner();
    const network = fakeNetwork({
      confirm: (n) => (n === 2 ? new Error("websocket closed") : "confirmed"),
      status: () => {
        throw new Error("rate limited");
      },
      accounts: proofAccountsExist,
    });
    const f = await flow();
    const ctx = { ...network, payer, operation: "transfer", outcomePolling: { intervalMs: 0, timeoutMs: 0 } };
    const error = await rejection(executeProofFlow(ctx, f, "transfer"));
    expect(error.code).to.equal("TRANSACTION_OUTCOME_UNKNOWN");
    expect(error.step).to.equal("transfer");
    expect(error.signatures).to.have.length(1); // the proofs landed
    expect(error.signature).to.be.a("string");
    expect(error.proofAccounts).to.deep.equal({ closed: [], leftOpen: f.proofAccounts });
    expect(network.calls.lookups).to.deep.equal([]); // no attempt to close them
    expect(network.calls.sent).to.have.length(2);
  });

  it("is a failure when only a proof step's outcome is unknown: the transfer itself was not sent", async () => {
    const payer = await generateKeyPairSigner();
    const network = fakeNetwork({
      confirm: () => new Error("websocket closed"),
      status: () => {
        throw new Error("rate limited");
      },
    });
    const ctx = { ...network, payer, operation: "transfer", outcomePolling: { intervalMs: 0, timeoutMs: 0 } };
    const error = await rejection(executeProofFlow(ctx, await flow(), "transfer"));
    expect(error.code).to.equal("TRANSACTION_FAILED");
    expect(error.step).to.equal("proofs");
    expect(error.message).to.contain("The transfer itself was not sent");
    expect(network.calls.lookups).to.deep.equal([2]); // the proof accounts were looked for, to close them
  });
});

describe("transfer-hook accounts that sign", () => {
  it("refuses, before signing, a hook account that is the payer", async () => {
    const [payerKey, owner] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
    const { signer: payer, counts } = countingWallet(payerKey);
    const action: Instruction = {
      programAddress: address("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
      accounts: [
        { address: owner.address, role: AccountRole.READONLY_SIGNER, signer: owner } as never,
        { address: payer.address, role: AccountRole.WRITABLE },
      ],
      data: new Uint8Array([27, 7]),
    };
    const flow: ProofFlow = { proofAccounts: [], setup: sequentialInstructionPlan([]), action, cleanup: [], transferHookAccounts: [payer.address] };
    // No RPC: the refusal has to come before the blockhash is even fetched.
    const error = await rejection(executeProofFlow({ rpc: {} as never, rpcSubscriptions: {} as never, payer, operation: "transfer" }, flow, "transfer"));
    expect(error.code).to.equal("INVALID_INPUT");
    expect(error.message).to.contain(payer.address);
    expect(counts.requests).to.equal(0);
  });

  it("refuses a hook account that signs the same transaction as a proof account", async () => {
    const [payer, proofAccount] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
    const SYSTEM = address("11111111111111111111111111111111");
    const create: Instruction = {
      programAddress: SYSTEM,
      accounts: [{ address: proofAccount.address, role: AccountRole.WRITABLE_SIGNER, signer: proofAccount } as never],
      data: new Uint8Array([1]),
    };
    const action: Instruction = { programAddress: SYSTEM, accounts: [{ address: proofAccount.address, role: AccountRole.READONLY }], data: new Uint8Array([2]) };
    const flow: ProofFlow = {
      proofAccounts: [proofAccount.address],
      setup: sequentialInstructionPlan([create]), // small enough to share the action's transaction
      action,
      cleanup: [],
      transferHookAccounts: [proofAccount.address],
    };
    const error = await rejection(executeProofFlow({ rpc: {} as never, rpcSubscriptions: {} as never, payer, operation: "transfer" }, flow, "transfer"));
    expect(error.code).to.equal("INVALID_INPUT");
  });
});

describe("closing proof accounts", () => {
  it("looks up more than 100 at a time in chunks, and retries a failed batch one account at a time", async () => {
    const payer = await generateKeyPairSigner();
    const addresses: Address[] = [];
    for (let i = 0; i < 205; i++) addresses.push((await generateKeyPairSigner()).address);
    const stuck = addresses[3]; // in the first batch of eight; its close is refused
    const network = fakeNetwork({
      accounts: proofAccountsExist,
      simulate: (wire) => (accountsOf(wire).includes(stuck) ? { InstructionError: [0, "InvalidAccountOwner"] } : undefined),
    });
    const result = await closeProofAccounts({ ...network, payer, operation: "recoverProofAccounts" }, addresses);
    expect(network.calls.lookups).to.deep.equal([100, 100, 5]);
    expect(result.leftOpen).to.deep.equal([stuck]);
    expect(result.closed).to.have.length(204);
    expect(result.closed).to.have.members(addresses.filter((a) => a !== stuck));
  });
});

describe("auditor report CSV", () => {
  it("writes one row per entry, formats amounts and quotes what needs quoting", async () => {
    const { confidentialActivityToCsv } = await import("../src/index");
    const a = (await generateKeyPairSigner()).address;
    const b = (await generateKeyPairSigner()).address;
    const csv = confidentialActivityToCsv(
      [
        { signature: "sig1" as never, slot: 5n, blockTime: new Date("2026-10-12T10:00:00Z"), kind: "transfer", fromToken: a, fromOwner: a, toToken: b, toOwner: b, amount: 12345n, decrypted: true },
        { signature: "sig2" as never, slot: 6n, blockTime: null, kind: "transfer", fromToken: a, fromOwner: null, toToken: b, toOwner: null, amount: null, decrypted: false, note: 'not encrypted, to "this" key' },
        { signature: "sig3" as never, slot: 7n, blockTime: null, kind: "deposit", fromToken: a, fromOwner: a, toToken: a, toOwner: a, amount: 5n, decrypted: false },
      ],
      { decimals: 2 },
    );
    const lines = csv.split("\r\n");
    expect(lines[1]).to.equal(`2026-10-12T10:00:00.000Z,5,sig1,transfer,${a},${a},${b},${b},12345,123.45,yes,`);
    expect(lines[2]).to.equal(`,6,sig2,transfer,,${a},,${b},,,no,"not encrypted, to ""this"" key"`);
    expect(lines[3]).to.contain(",5,0.05,no,");
    expect(lines[4]).to.equal("");
  });
});
