// SPDX-License-Identifier: BUSL-1.1
//
// decryptBalance(): decrypt the owner's confidential AVAILABLE balance using the
// AES key derived from the owner's wallet signer (or the `keys` passed in).
// Read-only — no transaction.
import {
  type Address,
  type MessageSigner,
  type Rpc,
  type SolanaRpcApi,
  type TransactionSigner,
} from "@solana/kit";
import { TOKEN_2022_PROGRAM_ADDRESS, findAssociatedTokenPda } from "@solana-program/token-2022";

import { readConfiguredAccount } from "./internal/accounts";
import { readAvailableBalance } from "./internal/availableBalance";
import { assertKeysMatchAccount, ownerKeys } from "./internal/ownerKeys";
import { decryptPendingBalance } from "./internal/pendingBalance";
import type { ConfidentialKeypairs } from "./keys";

export type DecryptBalanceInput = {
  /** RPC client, e.g. `createSolanaRpc(url)`. */
  rpc: Rpc<SolanaRpcApi>;
  /**
   * Owner of the account. Signs the key-derivation message unless `keys` is given; nothing else
   * is signed.
   */
  owner: TransactionSigner | MessageSigner;
  mint: Address;
  /** Token account (defaults to the owner's ATA). */
  token?: Address;
  /** The owner's keys from {@link deriveConfidentialKeys}; skips the message signature. */
  keys?: ConfidentialKeypairs;
  /** Token program. Default: Token-2022. */
  programAddress?: Address;
  /**
   * Add what is pending (default `false`). transfer() and withdraw() spend pending amounts too, so
   * a wallet shows this sum as the spendable balance.
   */
  includePending?: boolean;
};

/**
 * The owner's confidential available balance in base units, decrypted locally. Sends no
 * transaction. Amounts still pending are left out unless `includePending` is set.
 */
export async function decryptBalance(input: DecryptBalanceInput): Promise<bigint> {
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const token =
    input.token ??
    (
      await findAssociatedTokenPda({
        owner: input.owner.address,
        tokenProgram: programAddress,
        mint: input.mint,
      })
    )[0];

  const operation = "decryptBalance";
  const { data, ct } = await readConfiguredAccount(input.rpc, token, operation);

  const keys = await ownerKeys(input.owner, input.keys, operation);
  assertKeysMatchAccount(keys, data, token, operation);

  const available = readAvailableBalance(ct, keys, token, operation);
  return input.includePending ? available + decryptPendingBalance(ct, keys, token, operation) : available;
}
