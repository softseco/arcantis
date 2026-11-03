// SPDX-License-Identifier: BUSL-1.1
//
// Sending transactions: one for configure, deposit and apply; one for transfer and withdraw, with
// their proofs inside (a v1 transaction, up to 4,096 bytes), or several when that does not fit or
// the caller asks for it.
//
// For a multi-transaction operation every transaction is planned and signed up front, in one call
// per signer, so a browser wallet asks once ("approve 5 transactions") instead of once per
// transaction. They are then sent in order, each simulated first so a failure comes with its
// program logs. If a step fails before the transfer or withdraw itself lands, the proof accounts
// created so far are closed again, which returns their rent to the payer.
//
// A transaction that was sent (or may have reached a node) but was not seen confirmed is never
// assumed to have failed: its status decides, and while its blockhash is valid it can still land.
import {
  SOLANA_ERROR__BLOCK_HEIGHT_EXCEEDED,
  SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR,
  appendTransactionMessageInstructions,
  assertIsFullySignedTransaction,
  compileTransaction,
  createTransactionMessage,
  createTransactionPlanner,
  flattenTransactionPlan,
  getBase64EncodedWireTransaction,
  getCompiledTransactionMessageDecoder,
  getSignatureFromTransaction,
  getSignersFromTransactionMessage,
  isSignerRole,
  isSolanaError,
  isTransactionMessageWithinSizeLimit,
  isTransactionModifyingSigner,
  isTransactionPartialSigner,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageComputeUnitLimit,
  setTransactionMessageComputeUnitPrice,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  setTransactionMessageLoadedAccountsDataSizeLimit,
  setTransactionMessagePriorityFeeLamports,
  type Address,
  type Instruction,
  type Rpc,
  type RpcSubscriptions,
  type Signature,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
  type Transaction,
  type TransactionSigner,
} from "@solana/kit";
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS, closeContextStateProof } from "@solana-program/zk-elgamal-proof";

import { ConfidentialTransfersError, isConfidentialTransfersError } from "../errors";
import { proofFlowToPlan, type ProofFlow } from "./confidentialTransferProof";
import { assertHookAccountsAreNotSigners } from "./transferHook";

/** Options every sending function accepts. */
export type SendOptions = {
  /**
   * Priority fee, in micro-lamports per compute unit. A one-transaction transfer or withdraw pays
   * it on its estimated compute units. With proof accounts it is added to each transaction that
   * has room for it; the range-proof transaction of a transfer is too full and goes without.
   */
  computeUnitPrice?: bigint | number;
  /**
   * How many times to run the whole operation again when a transaction expires before it is
   * confirmed (`TRANSACTION_EXPIRED`). Each retry builds and signs new transactions, so a wallet
   * asks again. Default 0.
   */
  retries?: number;
};

export type SendContext = {
  rpc: Rpc<SolanaRpcApi>;
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
  payer: TransactionSigner;
  /** The SDK function, for error messages. */
  operation: string;
  computeUnitPrice?: bigint | number;
  /** How often, and how long, to poll a transaction's status when its outcome has to be found out. */
  outcomePolling?: OutcomePolling;
};

export type OutcomePolling = {
  /** Between two reads of the status. Default 2 seconds. */
  intervalMs?: number;
  /** Give up, with "unknown", after this long without an answer. Default 3 minutes. */
  timeoutMs?: number;
};

/** What became of a transaction that was not seen confirmed. */
export type Outcome = "landed" | "failed" | "not-found" | "unknown";

type Message = Parameters<typeof compileTransaction>[0];
type BlockhashLifetime = { blockhash: Parameters<typeof setTransactionMessageLifetimeUsingBlockhash>[0]["blockhash"]; lastValidBlockHeight: bigint };
type SendableTransaction = Transaction & { lifetimeConstraint: BlockhashLifetime };

const bigintReplacer = (_key: string, value: unknown) => (typeof value === "bigint" ? value.toString() : value);

function withPriorityFee<T extends Message>(message: T, price: bigint | number | undefined): T {
  if (price === undefined || BigInt(price) === 0n) return message;
  const priced = setTransactionMessageComputeUnitPrice(BigInt(price), message as never) as unknown as T;
  return isTransactionMessageWithinSizeLimit(priced as never) ? priced : message;
}

/**
 * Sign several transaction messages with their signers, asking each signer once for all the
 * transactions it has to sign. Follows kit's rules for which signer interface is used: modifying
 * signers (wallets) first, then partial signers (keypairs), so a wallet that changes a
 * transaction does so before anyone else signs it.
 */
export async function signTransactionMessagesTogether(
  messages: readonly Message[],
  lifetime: BlockhashLifetime,
): Promise<SendableTransaction[]> {
  let transactions: Transaction[] = messages.map((m) => compileTransaction(m));
  const signersByTx = messages.map((m) => getSignersFromTransactionMessage(m as never) as TransactionSigner[]);

  const unique = new Map<Address, TransactionSigner>();
  for (const signers of signersByTx) for (const s of signers) if (!unique.has(s.address)) unique.set(s.address, s);
  const candidates = [...unique.values()].filter((s) => isTransactionModifyingSigner(s) || isTransactionPartialSigner(s));
  const modifying = candidates.filter(isTransactionModifyingSigner);
  const modifyingOnly = modifying.filter((s) => !isTransactionPartialSigner(s));
  const modifyingSigners = modifyingOnly.length > 0 ? modifyingOnly : modifying.slice(0, 1);
  const chosen = new Set<TransactionSigner>(modifyingSigners);
  const partialSigners = candidates.filter((s) => isTransactionPartialSigner(s) && !chosen.has(s));

  const needs = (signer: TransactionSigner) =>
    transactions.map((_, i) => i).filter((i) => signersByTx[i].some((s) => s.address === signer.address));

  for (const signer of modifyingSigners) {
    if (!isTransactionModifyingSigner(signer)) continue;
    const indexes = needs(signer);
    if (indexes.length === 0) continue;
    const signed = await signer.modifyAndSignTransactions(indexes.map((i) => transactions[i]) as never);
    indexes.forEach((txIndex, k) => (transactions[txIndex] = signed[k] as Transaction));
  }
  await Promise.all(
    partialSigners.map(async (signer) => {
      if (!isTransactionPartialSigner(signer)) return;
      const indexes = needs(signer);
      if (indexes.length === 0) return;
      const dictionaries = await signer.signTransactions(indexes.map((i) => transactions[i]) as never);
      indexes.forEach((txIndex, k) => {
        const tx = transactions[txIndex];
        transactions[txIndex] = Object.freeze({ ...tx, signatures: Object.freeze({ ...tx.signatures, ...dictionaries[k] }) });
      });
    }),
  );
  return transactions.map((tx) => {
    assertIsFullySignedTransaction(tx);
    // A wallet that modifies a transaction may drop the lifetime kit uses to wait for it.
    const withLifetime = ("lifetimeConstraint" in tx ? tx : { ...tx, lifetimeConstraint: lifetime }) as SendableTransaction;
    // It may also have put in a newer blockhash and kept the old lifetime. Expiry is then measured
    // against the wrong block height, so "it did not land" can never be concluded for it.
    const signed = getCompiledTransactionMessageDecoder().decode(tx.messageBytes).lifetimeToken;
    if (signed !== withLifetime.lifetimeConstraint.blockhash) lifetimeNotKnown.add(withLifetime);
    return withLifetime;
  });
}

/** Signed transactions whose blockhash is not the one their lifetime names (see above). */
const lifetimeNotKnown = new WeakSet<object>();

async function logsOf(ctx: SendContext, signature: Signature): Promise<string[] | undefined> {
  try {
    const tx = await ctx.rpc
      .getTransaction(signature, { commitment: "confirmed", maxSupportedTransactionVersion: 1, encoding: "json" })
      .send();
    return tx?.meta?.logMessages ? [...tx.meta.logMessages] : undefined;
  } catch {
    return undefined;
  }
}

const messageOf = (e: unknown) => (e instanceof Error ? e.message : String(e));
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Simulate, send, and wait for confirmation. Throws ConfidentialTransfersError.
 *
 * Sending and confirming are two stages, because an error means something different in each. A
 * node that answers the send with a refusal did not pass the transaction on: it failed. Any other
 * error (a 5xx, a timeout, a lost connection, a confirmation that never came) may come after the
 * transaction reached a node, so it may still land, or have landed: its status decides (`settle`).
 */
async function simulateAndSend(ctx: SendContext, tx: SendableTransaction, step: string, simulated = false): Promise<Signature> {
  if (!simulated) await simulate(ctx, getBase64EncodedWireTransaction(tx), step);
  const signature = getSignatureFromTransaction(tx);
  try {
    // What kit's sendAndConfirmTransaction sends, with the same settings.
    await ctx.rpc
      .sendTransaction(getBase64EncodedWireTransaction(tx), {
        encoding: "base64",
        skipPreflight: true,
        preflightCommitment: "confirmed",
      })
      .send();
  } catch (e) {
    if (refusedBeforeForwarding(e)) {
      throw new ConfidentialTransfersError(
        "TRANSACTION_FAILED",
        `${ctx.operation}: the RPC node refused transaction ${signature}: ${messageOf(e)}`,
        { operation: ctx.operation, step, signature, cause: e },
      );
    }
    return settle(ctx, tx, step, e, "send");
  }
  try {
    await confirmationOf(ctx, signature)(tx as never, { commitment: "confirmed" });
  } catch (e) {
    // At BLOCK_HEIGHT_EXCEEDED the blockhash has expired: usually the transaction never landed, but
    // a confirmation the RPC failed to deliver looks the same, and calling a transaction that
    // landed "expired" would let a retry send a transfer twice.
    return settle(ctx, tx, step, e, isSolanaError(e, SOLANA_ERROR__BLOCK_HEIGHT_EXCEEDED) ? "expired" : "confirm");
  }
  return signature;
}

type Simulation = { unitsConsumed?: bigint; loadedAccountsDataSize?: number };

/** Simulate a transaction (its signatures are not checked); throw with the program logs if it fails. */
async function simulate(ctx: SendContext, wire: ReturnType<typeof getBase64EncodedWireTransaction>, step: string): Promise<Simulation> {
  const simulation = await ctx.rpc
    .simulateTransaction(wire, { encoding: "base64", replaceRecentBlockhash: true, sigVerify: false })
    .send();
  if (simulation.value.err) {
    const logs = simulation.value.logs ?? [];
    throw new ConfidentialTransfersError(
      "TRANSACTION_FAILED",
      `${ctx.operation} ${step === ctx.operation ? "transaction" : `step "${step}"`} failed simulation: ` +
        JSON.stringify(simulation.value.err, bigintReplacer) +
        "\n--- program logs ---\n" +
        logs.join("\n"),
      { operation: ctx.operation, step, logs },
    );
  }
  return simulation.value as Simulation;
}

/**
 * kit's confirmation of a transaction already sent: its signature subscription raced against the
 * expiry of its blockhash. kit offers it only together with the sending, so it gets an RPC whose
 * `sendTransaction` returns the signature without sending anything: nothing is sent twice.
 */
function confirmationOf(ctx: SendContext, signature: Signature) {
  const rpc = {
    getEpochInfo: (...args: Parameters<SendContext["rpc"]["getEpochInfo"]>) => ctx.rpc.getEpochInfo(...args),
    getSignatureStatuses: (...args: Parameters<SendContext["rpc"]["getSignatureStatuses"]>) =>
      ctx.rpc.getSignatureStatuses(...args),
    sendTransaction: () => ({ send: async () => signature }),
  };
  return sendAndConfirmTransactionFactory({ rpc: rpc as never, rpcSubscriptions: ctx.rpcSubscriptions });
}

/**
 * True when the RPC node turned the send down, so the transaction was not passed on: an HTTP
 * status below 500 (rate limited, too large), or a JSON-RPC error, which a node answers only
 * before forwarding a transaction (malformed, bad signature, node unhealthy). kit keeps JSON-RPC
 * error codes, which are negative, as its own codes. A 5xx, a timeout or a lost connection can
 * come after the node took the transaction, so they do not count.
 */
export function refusedBeforeForwarding(e: unknown): boolean {
  if (isSolanaError(e, SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR)) return e.context.statusCode < 500;
  return isSolanaError(e) && e.context.__code < 0;
}

/**
 * A transaction that was sent, or may have reached a node, but was not seen confirmed: find out
 * from its status what became of it. Returns its signature if it landed; otherwise throws
 * TRANSACTION_FAILED (it landed with an error), TRANSACTION_EXPIRED (it did not land and, its
 * blockhash expired, never will: the only outcome a retry may follow) or
 * TRANSACTION_OUTCOME_UNKNOWN (its status could not be read).
 */
async function settle(
  ctx: SendContext,
  tx: SendableTransaction,
  step: string,
  cause: unknown,
  stage: "send" | "confirm" | "expired",
): Promise<Signature> {
  const signature = getSignatureFromTransaction(tx);
  const { lastValidBlockHeight } = tx.lifetimeConstraint;
  let outcome =
    stage === "expired"
      ? await outcomeAfterExpiry(ctx.rpc, signature, lastValidBlockHeight, ctx.outcomePolling?.intervalMs)
      : await outcomeOfSentTransaction(ctx.rpc, signature, lastValidBlockHeight, ctx.outcomePolling);
  // Its real blockhash may still be valid: it can still land.
  if (outcome === "not-found" && lifetimeNotKnown.has(tx)) outcome = "unknown";
  if (outcome === "landed") return signature;
  const details = { operation: ctx.operation, step, signature, cause };
  if (outcome === "failed") {
    throw new ConfidentialTransfersError(
      "TRANSACTION_FAILED",
      `${ctx.operation}: transaction ${signature} failed` + (stage === "confirm" ? `: ${messageOf(cause)}` : ""),
      { ...details, logs: await logsOf(ctx, signature) },
    );
  }
  const what =
    stage === "send"
      ? `transaction ${signature} may not have reached the RPC node (${messageOf(cause)})`
      : stage === "confirm"
        ? `no confirmation of transaction ${signature} arrived (${messageOf(cause)})`
        : `transaction ${signature} was not confirmed before its blockhash expired`;
  if (outcome === "not-found") {
    throw new ConfidentialTransfersError(
      "TRANSACTION_EXPIRED",
      `${ctx.operation}: ${what}. ${stage === "expired" ? "" : "Its blockhash has expired since. "}It did not land; it is ` +
        "safe to run again" + (stage === "expired" ? " (the network may be busy; a priority fee helps)." : "."),
      details,
    );
  }
  throw new ConfidentialTransfersError(
    "TRANSACTION_OUTCOME_UNKNOWN",
    `${ctx.operation}: ${what}, and its status could not be read. It may have landed: look it up on an explorer ` +
      "before running the operation again.",
    details,
  );
}

type StatusRpc = Pick<Rpc<SolanaRpcApi>, "getSignatureStatuses" | "getEpochInfo">;

/**
 * What became of a transaction whose blockhash has expired, or is about to: "landed" (confirmed
 * without an error), "failed" (confirmed with an error), "not-found" (it did not land, and with
 * its blockhash expired it never will) or "unknown" (the status could not be read, or the
 * transaction is still only processed, after a few more tries).
 *
 * "Not found" is trusted only from a status answer at or after the slot at which the RPC saw the
 * block height pass `lastValidBlockHeight`. Behind a load balancer the status may come from a
 * node a few slots behind the one that reported the expiry, without the last blocks, where a
 * transaction that landed in them is not found yet. An error on a transaction that is only
 * processed is not final either: its fork may be dropped and the transaction land elsewhere.
 */
export async function outcomeAfterExpiry(
  rpc: StatusRpc,
  signature: Signature,
  lastValidBlockHeight: bigint,
  pollMs = 1000,
): Promise<Outcome> {
  let expiredAtSlot: bigint | undefined;
  for (let attempt = 0; attempt < 8; attempt++) {
    if (attempt > 0) await sleep(pollMs);
    let status;
    let slot: bigint;
    try {
      if (expiredAtSlot === undefined) {
        const info = await rpc.getEpochInfo({ commitment: "confirmed" }).send();
        if (info.blockHeight > lastValidBlockHeight) expiredAtSlot = info.absoluteSlot;
      }
      ({ context: { slot }, value: [status] } = await rpc
        .getSignatureStatuses([signature], { searchTransactionHistory: true })
        .send());
    } catch {
      continue;
    }
    if (status != null && status.confirmationStatus !== "processed") return status.err ? "failed" : "landed";
    if (status == null && expiredAtSlot !== undefined && slot >= expiredAtSlot) return "not-found";
  }
  return "unknown";
}

/**
 * What became of a transaction that may have reached a node while its blockhash was still valid,
 * so that it may still land. Its status is read until it shows the transaction confirmed or
 * failed, or until the blockhash has expired, after which it is read as in
 * {@link outcomeAfterExpiry}. "unknown" when that takes longer than `timeoutMs`, for example
 * because the RPC does not answer.
 */
export async function outcomeOfSentTransaction(
  rpc: StatusRpc,
  signature: Signature,
  lastValidBlockHeight: bigint,
  { intervalMs = 2000, timeoutMs = 180_000 }: OutcomePolling = {},
): Promise<Outcome> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const [{ value: [status] }, { blockHeight }] = await Promise.all([
        rpc.getSignatureStatuses([signature], { searchTransactionHistory: true }).send(),
        rpc.getEpochInfo({ commitment: "confirmed" }).send(),
      ]);
      if (status != null && status.confirmationStatus !== "processed") return status.err ? "failed" : "landed";
      if (blockHeight > lastValidBlockHeight) return outcomeAfterExpiry(rpc, signature, lastValidBlockHeight, intervalMs);
    } catch {
      // No answer this time; ask again until the deadline.
    }
    if (Date.now() >= deadline) return "unknown";
    await sleep(intervalMs);
  }
}

async function latestLifetime(ctx: SendContext): Promise<BlockhashLifetime> {
  const { value } = await ctx.rpc.getLatestBlockhash({ commitment: "confirmed" }).send();
  return value;
}

/** One transaction: build, sign, simulate, send, confirm. */
export async function sendInstructions(ctx: SendContext, instructions: Instruction[]): Promise<Signature> {
  const lifetime = await latestLifetime(ctx);
  const message = withPriorityFee(
    pipe(
      createTransactionMessage({ version: 0 }),
      (tx) => setTransactionMessageFeePayerSigner(ctx.payer, tx),
      (tx) => setTransactionMessageLifetimeUsingBlockhash(lifetime, tx),
      (tx) => appendTransactionMessageInstructions(instructions, tx),
    ),
    ctx.computeUnitPrice,
  );
  const [tx] = await signTransactionMessagesTogether([message], lifetime);
  return simulateAndSend(ctx, tx, ctx.operation);
}

/** The most compute units and loaded account data a transaction may ask for. */
const MAX_COMPUTE_UNITS = 1_400_000;
const MAX_LOADED_ACCOUNTS_DATA_SIZE = 64 * 1024 * 1024;

/**
 * A transfer or withdraw in one v1 transaction, its proofs inside: estimate its compute units and
 * loaded account data by simulating it, sign it, send it, confirm it. Returns null, before anything
 * is signed, when it does not fit in one transaction (over 4,096 bytes or 64 accounts, e.g. with a
 * transfer hook that asks for many accounts); the caller then uses proof accounts.
 */
export async function sendSingleTransaction(
  ctx: SendContext,
  instructions: Instruction[],
  transferHookAccounts?: Address[],
): Promise<ProofFlowResult | null> {
  const lifetime = await latestLifetime(ctx);
  const draft = pipe(
    createTransactionMessage({ version: 1 }),
    (tx) => setTransactionMessageFeePayerSigner(ctx.payer, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(lifetime, tx),
    (tx) => appendTransactionMessageInstructions(instructions, tx),
    (tx) => setTransactionMessageComputeUnitLimit(MAX_COMPUTE_UNITS, tx),
    (tx) => setTransactionMessageLoadedAccountsDataSizeLimit(MAX_LOADED_ACCOUNTS_DATA_SIZE, tx),
  );
  let compiled;
  try {
    compiled = compileTransaction(draft);
  } catch {
    return null; // more accounts than a v1 transaction holds
  }
  if (!isTransactionMessageWithinSizeLimit(draft)) return null;
  if (transferHookAccounts && transferHookAccounts.length > 0) {
    assertHookAccountsAreNotSigners(transferHookAccounts, signerAddresses(draft as unknown as Message), ctx.operation);
  }

  // The estimate leaves room for the account state to change a little before the transaction runs.
  const estimate = await simulate(ctx, getBase64EncodedWireTransaction(compiled), ctx.operation);
  const units = Math.min(MAX_COMPUTE_UNITS, Math.ceil(Number(estimate.unitsConsumed ?? MAX_COMPUTE_UNITS) * 1.2));
  const loaded = estimate.loadedAccountsDataSize
    ? Math.min(MAX_LOADED_ACCOUNTS_DATA_SIZE, Math.ceil(estimate.loadedAccountsDataSize * 1.1))
    : MAX_LOADED_ACCOUNTS_DATA_SIZE;
  const price = ctx.computeUnitPrice === undefined ? 0n : BigInt(ctx.computeUnitPrice);
  const message = pipe(
    draft,
    (tx) => setTransactionMessageComputeUnitLimit(units, tx),
    (tx) => setTransactionMessageLoadedAccountsDataSizeLimit(loaded, tx),
    (tx) => (price > 0n ? setTransactionMessagePriorityFeeLamports((price * BigInt(units) + 999_999n) / 1_000_000n, tx) : tx),
  );
  if (!isTransactionMessageWithinSizeLimit(message)) return null;

  const [tx] = await signTransactionMessagesTogether([message as unknown as Message], lifetime);
  const signature = await simulateAndSend(ctx, tx, ctx.operation, true);
  return { signatures: [signature], proofAccountsLeftOpen: [] };
}

export type ProofFlowResult = {
  signatures: Signature[];
  /** Proof accounts still open after the operation succeeded (normally none). */
  proofAccountsLeftOpen: Address[];
};

/**
 * A transfer or withdraw: plan every transaction, sign them all together, send them in order.
 * `actionStep` names the main step in errors ("transfer", "withdraw"). When a step fails, the proof
 * accounts are closed, except when the outcome of the main step itself is unknown.
 */
export async function executeProofFlow(ctx: SendContext, flow: ProofFlow, actionStep: string): Promise<ProofFlowResult> {
  const planner = createTransactionPlanner({
    createTransactionMessage: () =>
      pipe(createTransactionMessage({ version: 0 }), (tx) => setTransactionMessageFeePayerSigner(ctx.payer, tx)),
  });
  const plan = await planner(proofFlowToPlan(flow));
  const planned = flattenTransactionPlan(plan).map((single) => single.message as Message);
  const actionIndex = planned.findIndex((m) => m.instructions.includes(flow.action));
  if (actionIndex !== -1 && flow.transferHookAccounts && flow.transferHookAccounts.length > 0) {
    // Whatever the planner put in the transfer's transaction (proof accounts too), no account the
    // hook asked for may sign it. Checked before anything is signed.
    assertHookAccountsAreNotSigners(flow.transferHookAccounts, signerAddresses(planned[actionIndex]), ctx.operation);
  }

  const lifetime = await latestLifetime(ctx);
  const messages = planned.map((m) =>
    withPriorityFee(setTransactionMessageLifetimeUsingBlockhash(lifetime, m as never) as Message, ctx.computeUnitPrice),
  );
  const transactions = await signTransactionMessagesTogether(messages, lifetime);

  const signatures: Signature[] = [];
  for (let i = 0; i < transactions.length; i++) {
    const step = actionIndex === -1 || i < actionIndex ? "proofs" : actionStep;
    try {
      signatures.push(await simulateAndSend(ctx, transactions[i], step));
    } catch (e) {
      const actionLanded = actionIndex !== -1 && i > actionIndex;
      if (i === actionIndex && isConfidentialTransfersError(e, "TRANSACTION_OUTCOME_UNKNOWN")) {
        // The transfer or withdraw itself may have landed. Its proof accounts stay as they are:
        // they are not the SDK's to close while that is open, and recoverProofAccounts closes
        // them once the transaction has been looked up.
        const leftOpen = [...flow.proofAccounts];
        throw new ConfidentialTransfersError(
          e.code,
          `${e.message}\nIts ${leftOpen.length} proof account(s) were left open: ${leftOpen.join(", ")}. ` +
            "Once the transaction is settled, recoverProofAccounts() closes them and returns their rent.",
          { operation: ctx.operation, step, signatures, signature: e.signature, proofAccounts: { closed: [], leftOpen }, cause: e.cause ?? e },
        );
      }
      const proofAccounts = await closeProofAccounts(ctx, flow.proofAccounts);
      if (actionLanded) {
        // The transfer or withdraw itself went through; only the cleanup did not.
        return { signatures, proofAccountsLeftOpen: proofAccounts.leftOpen };
      }
      const error = isConfidentialTransfersError(e)
        ? e
        : new ConfidentialTransfersError("TRANSACTION_FAILED", `${ctx.operation} failed: ${String(e)}`, { cause: e });
      // A proof step whose outcome is unknown leaves the operation's own outcome known: the
      // transfer or withdraw was never sent.
      const unknownProofStep = error.code === "TRANSACTION_OUTCOME_UNKNOWN";
      const message = unknownProofStep ? `${error.message}\nThe ${actionStep} itself was not sent.` : error.message;
      throw new ConfidentialTransfersError(unknownProofStep ? "TRANSACTION_FAILED" : error.code, withCleanupNote(message, proofAccounts), {
        operation: ctx.operation,
        step,
        logs: error.logs,
        signatures,
        signature: error.signature,
        proofAccounts,
        retryable: error.retryable,
        cause: error.cause ?? e,
      });
    }
  }
  return { signatures, proofAccountsLeftOpen: [] };
}

function withCleanupNote(message: string, proofAccounts: { closed: readonly Address[]; leftOpen: readonly Address[] }): string {
  if (proofAccounts.leftOpen.length > 0) {
    return `${message}\n${proofAccounts.leftOpen.length} proof account(s) could not be closed: ${proofAccounts.leftOpen.join(", ")}. recoverProofAccounts() closes them and returns their rent.`;
  }
  if (proofAccounts.closed.length > 0) {
    return `${message}\nThe ${proofAccounts.closed.length} proof account(s) created before the failure were closed and their rent returned.`;
  }
  return message;
}

/** The fee payer and every account an instruction of `message` has as a signer. */
function signerAddresses(message: Message): Address[] {
  const signers = new Set<Address>([message.feePayer.address]);
  for (const instruction of message.instructions) {
    for (const account of instruction.accounts ?? []) if (isSignerRole(account.role)) signers.add(account.address);
  }
  return [...signers];
}

/**
 * Close whichever of `addresses` exist (proof context accounts whose authority is the payer).
 * They are looked up ACCOUNTS_PER_LOOKUP at a time, the most getMultipleAccounts takes, and closed
 * CLOSES_PER_TRANSACTION at a time. When a batch's transaction fails, its accounts are tried again
 * one by one, so that one account that cannot be closed does not keep the others open (not when
 * the batch's outcome is unknown: it may have closed them).
 */
export async function closeProofAccounts(
  ctx: SendContext,
  addresses: readonly Address[],
): Promise<{ closed: Address[]; leftOpen: Address[] }> {
  if (addresses.length === 0) return { closed: [], leftOpen: [] };
  const existing: Address[] = [];
  const unread: Address[] = [];
  for (let i = 0; i < addresses.length; i += ACCOUNTS_PER_LOOKUP) {
    const chunk = addresses.slice(i, i + ACCOUNTS_PER_LOOKUP);
    try {
      const { value } = await ctx.rpc.getMultipleAccounts(chunk, { encoding: "base64", commitment: "confirmed" }).send();
      existing.push(...chunk.filter((_, k) => value[k] != null && value[k]!.owner === ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS));
    } catch {
      unread.push(...chunk); // not known to be closed: reported as left open
    }
  }
  const closed: Address[] = [];
  const cleanupCtx = { ...ctx, operation: `${ctx.operation} (closing proof accounts)` };
  const close = (batch: readonly Address[]) =>
    sendInstructions(
      cleanupCtx,
      batch.map((contextState) => closeContextStateProof({ contextState, authority: ctx.payer, destination: ctx.payer.address })),
    );
  for (let i = 0; i < existing.length; i += CLOSES_PER_TRANSACTION) {
    const batch = existing.slice(i, i + CLOSES_PER_TRANSACTION);
    try {
      await close(batch);
      closed.push(...batch);
    } catch (e) {
      if (batch.length === 1 || isConfidentialTransfersError(e, "TRANSACTION_OUTCOME_UNKNOWN")) continue;
      for (const account of batch) {
        try {
          await close([account]);
          closed.push(account);
        } catch {
          // left open; reported to the caller
        }
      }
    }
  }
  const done = new Set(closed);
  return { closed, leftOpen: [...unread, ...existing.filter((a) => !done.has(a))] };
}

const ACCOUNTS_PER_LOOKUP = 100;
const CLOSES_PER_TRANSACTION = 8;

/** Run `attempt`, again up to `retries` times while it fails with a retryable error. */
export async function withRetries<T>(retries: number | undefined, attempt: () => Promise<T>): Promise<T> {
  for (let n = 0; ; n++) {
    try {
      return await attempt();
    } catch (e) {
      if (n >= (retries ?? 0) || !(isConfidentialTransfersError(e) && e.retryable)) throw e;
    }
  }
}
