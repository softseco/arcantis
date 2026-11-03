// SPDX-License-Identifier: BUSL-1.1
//
// recoverProofAccounts(): close proof accounts left behind by a transfer or withdraw that did not
// finish (the process stopped halfway, or closing them failed), and get their rent back.
//
// A transfer verifies its proofs into context-state accounts of the ZK ElGamal Proof Program,
// owned by the payer, and closes them at the end. transfer() and withdraw() already close them
// when a step fails; this is for what is left when the process itself stopped.
import {
  type Address,
  type Base58EncodedBytes,
  type Lamports,
  type Rpc,
  type RpcSubscriptions,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
  type TransactionSigner,
} from "@solana/kit";
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS } from "@solana-program/zk-elgamal-proof";

import { closeProofAccounts } from "./internal/send";

export type RecoverProofAccountsInput = {
  /** RPC client. It must serve `getProgramAccounts` for the ZK ElGamal Proof Program. */
  rpc: Rpc<SolanaRpcApi>;
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
  /**
   * The `payer` of the transfers or withdraws that left the accounts: it is their authority,
   * signs the closes, pays the fees and receives the rent.
   */
  authority: TransactionSigner;
  /** Priority fee in micro-lamports per compute unit. */
  computeUnitPrice?: bigint | number;
};

export type RecoverProofAccountsResult = {
  /** Accounts closed. */
  closed: Address[];
  /** Accounts found but not closed (the closing transaction failed); run again. */
  leftOpen: Address[];
  /** Rent returned to the authority, in lamports. */
  lamports: bigint;
};

/**
 * Find the proof accounts whose authority is `authority` and close them, returning their rent.
 * Do not run it while a transfer or withdraw paid by the same `authority` is still in progress:
 * that transfer's proof accounts would be closed under it, and it would fail.
 */
export async function recoverProofAccounts(input: RecoverProofAccountsInput): Promise<RecoverProofAccountsResult> {
  const found = await input.rpc
    .getProgramAccounts(ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS, {
      commitment: "confirmed",
      encoding: "base64",
      dataSlice: { offset: 0, length: 0 },
      // A proof context account starts with its authority's public key.
      filters: [{ memcmp: { offset: 0n, bytes: input.authority.address as unknown as Base58EncodedBytes, encoding: "base58" } }],
    })
    .send();
  const accounts = found as unknown as ReadonlyArray<{ pubkey: Address; account: { lamports: Lamports } }>;
  const { closed, leftOpen } = await closeProofAccounts(
    {
      rpc: input.rpc,
      rpcSubscriptions: input.rpcSubscriptions,
      payer: input.authority,
      operation: "recoverProofAccounts",
      computeUnitPrice: input.computeUnitPrice,
    },
    accounts.map((a) => a.pubkey),
  );
  const lamports = accounts
    .filter((a) => closed.includes(a.pubkey))
    .reduce((sum, a) => sum + BigInt(a.account.lamports), 0n);
  return { closed, leftOpen, lamports };
}
