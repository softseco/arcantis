// SPDX-License-Identifier: BUSL-1.1
//
// Fakes for validator-free tests: an RPC and RPC subscriptions that answer the way a test scripts
// them (to reach the sending code's error paths, which a local validator cannot be made to take),
// and Token-2022 accounts encoded with the token-2022 client, served from memory.
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS } from "@solana-program/zk-elgamal-proof";
import {
  AccountState,
  TOKEN_2022_PROGRAM_ADDRESS,
  extension,
  getMintEncoder,
  getTokenEncoder,
  type ExtensionArgs,
} from "@solana-program/token-2022";
import {
  getBase64Encoder,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
  none,
  some,
  type Address,
  type KeyPairSigner,
  type ReadonlyUint8Array,
  type TransactionModifyingSigner,
} from "@solana/kit";

import { isConfidentialTransfersError, type ConfidentialTransfersError } from "../src/errors";

export { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS };

/** The error a promise rejects with; fails the test if it resolves or throws something else. */
export async function rejection(promise: Promise<unknown>): Promise<ConfidentialTransfersError> {
  try {
    await promise;
  } catch (e) {
    if (isConfidentialTransfersError(e)) return e;
    throw e;
  }
  throw new Error("expected the call to reject");
}

/** A keypair behind a wallet's interface, counting signing requests. It cannot sign messages. */
export function walletLike(keypair: KeyPairSigner) {
  const counts = { requests: 0 };
  const signer: TransactionModifyingSigner = {
    address: keypair.address,
    async modifyAndSignTransactions(txs) {
      counts.requests += 1;
      const dictionaries = await keypair.signTransactions(txs as never);
      return txs.map((tx, i) => Object.freeze({ ...tx, signatures: { ...tx.signatures, ...dictionaries[i] } })) as never;
    },
  };
  return { signer, counts };
}

/** The accounts a wire transaction names (to script answers by what a transaction touches). */
export function accountsOf(wire: string): readonly Address[] {
  const { messageBytes } = getTransactionDecoder().decode(getBase64Encoder().encode(wire));
  return getCompiledTransactionMessageDecoder().decode(messageBytes).staticAccounts;
}

type Status = { err: unknown; confirmationStatus: "processed" | "confirmed" | "finalized" } | null;

export type NetworkScript = {
  /** A simulation error for this transaction, or nothing for success. */
  simulate?: (wire: string) => unknown;
  /** Throw to make the n-th sendTransaction fail. */
  send?: (wire: string, n: number) => void;
  /** The n-th signature subscription: "confirmed" (default), or an Error it fails with. */
  confirm?: (n: number) => "confirmed" | Error;
  /** The n-th status lookup by the SDK itself; throw to make it fail. Default: not found. */
  status?: (n: number) => Status;
  /** The n-th block height read (getEpochInfo; its slot is the same number). Default 50 (the blockhash is valid up to 100). */
  blockHeight?: (n: number) => bigint;
  /** The slot of the n-th status answer. Default 1,000,000: a node past any expiry. */
  statusSlot?: (n: number) => bigint;
  /** getMultipleAccounts. Default: none exists. */
  accounts?: (addresses: readonly Address[]) => Array<{ owner: Address } | null>;
};

/**
 * An RPC and RPC subscriptions for the sending code. The blockhash is valid up to block height 100.
 * kit's own status lookup during a confirmation never answers, so a confirmation comes from the
 * signature subscription alone.
 */
export function fakeNetwork(script: NetworkScript = {}) {
  const calls = { sent: [] as string[], statusReads: 0, blockHeightReads: 0, lookups: [] as number[], subscriptions: 0 };
  const answer = <T>(value: () => T) => ({ send: async () => value() });
  const rpc = {
    getLatestBlockhash: () =>
      answer(() => ({ context: { slot: 1n }, value: { blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 100n } })),
    simulateTransaction: (wire: string) =>
      answer(() => ({ context: { slot: 1n }, value: { err: script.simulate?.(wire) ?? null, logs: ["Program log: simulated"] } })),
    sendTransaction: (wire: string) =>
      answer(() => {
        calls.sent.push(wire);
        script.send?.(wire, calls.sent.length);
        return "unused";
      }),
    getEpochInfo: () =>
      answer(() => {
        const height = script.blockHeight ? script.blockHeight(++calls.blockHeightReads) : 50n;
        return { absoluteSlot: height, blockHeight: height };
      }),
    getSignatureStatuses: (_signatures: unknown, config?: { searchTransactionHistory?: boolean }) =>
      config?.searchTransactionHistory
        ? answer(() => {
            const n = ++calls.statusReads;
            const value = [script.status ? script.status(n) : null];
            return { context: { slot: script.statusSlot ? script.statusSlot(n) : 1_000_000n }, value };
          })
        : { send: () => new Promise(() => {}) },
    getTransaction: () => answer(() => ({ meta: { logMessages: ["Program log: failed on chain"] } })),
    getMultipleAccounts: (addresses: readonly Address[]) =>
      answer(() => {
        calls.lookups.push(addresses.length);
        if (addresses.length > 100) throw new Error("getMultipleAccounts takes at most 100 accounts");
        return { context: { slot: 1n }, value: script.accounts ? script.accounts(addresses) : addresses.map(() => null) };
      }),
  };
  const rpcSubscriptions = {
    signatureNotifications: () => ({
      subscribe: async () => {
        const outcome = script.confirm ? script.confirm(++calls.subscriptions) : "confirmed";
        if (outcome instanceof Error) throw outcome;
        return (async function* () {
          yield { context: { slot: 1n }, value: { err: null } };
        })();
      },
    }),
    slotNotifications: () => ({ subscribe: () => new Promise(() => {}) }),
  };
  return { rpc: rpc as never, rpcSubscriptions: rpcSubscriptions as never, calls };
}

/** Proof accounts as getMultipleAccounts shows them. */
export const proofAccountsExist = (addresses: readonly Address[]) => addresses.map(() => ({ owner: ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS }));

const zeros = (n: number) => new Uint8Array(n);

/** A token account configured for confidential transfers, able to receive. */
export function tokenAccountBytes(mint: Address, owner: Address, state: AccountState = AccountState.Initialized): ReadonlyUint8Array {
  return getTokenEncoder().encode({
    mint,
    owner,
    amount: 0n,
    delegate: none(),
    state,
    isNative: none(),
    delegatedAmount: 0n,
    closeAuthority: none(),
    extensions: some([
      extension("ConfidentialTransferAccount", {
        approved: true,
        elgamalPubkey: owner,
        pendingBalanceLow: zeros(64),
        pendingBalanceHigh: zeros(64),
        availableBalance: zeros(64),
        decryptableAvailableBalance: zeros(36),
        allowConfidentialCredits: true,
        allowNonConfidentialCredits: true,
        pendingBalanceCreditCounter: 0n,
        maximumPendingBalanceCreditCounter: 65536n,
        expectedPendingBalanceCreditCounter: 0n,
        actualPendingBalanceCreditCounter: 0n,
      }),
    ]),
  });
}

/** A mint configured for confidential transfers, with `more` extensions. */
export function mintBytes(more: ExtensionArgs[] = []): ReadonlyUint8Array {
  return getMintEncoder().encode({
    mintAuthority: none(),
    supply: 0n,
    decimals: 2,
    isInitialized: true,
    freezeAuthority: none(),
    extensions: some([
      extension("ConfidentialTransferMint", { authority: none(), autoApproveNewAccounts: true, auditorElgamalPubkey: none() }),
      ...more,
    ]),
  });
}

/** An RPC that serves these accounts' data (owned by Token-2022 unless said otherwise) and nothing else. */
export function accountsRpc(accounts: Map<Address, { data: ReadonlyUint8Array; owner?: Address }>) {
  return {
    getAccountInfo: (address: Address) => ({
      send: async () => {
        const account = accounts.get(address);
        return {
          context: { slot: 1n },
          value: account
            ? {
                data: [Buffer.from(account.data).toString("base64"), "base64"],
                executable: false,
                lamports: 1_000_000n,
                owner: account.owner ?? TOKEN_2022_PROGRAM_ADDRESS,
                space: BigInt(account.data.length),
                rentEpoch: 0n,
              }
            : null,
        };
      },
    }),
  } as never;
}
