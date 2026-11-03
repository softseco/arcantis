// SPDX-License-Identifier: BUSL-1.1
//
// applyPendingBalance(): move an account's confidential PENDING balance into its
// AVAILABLE balance. The pending balance (ElGamal-encrypted) is decrypted locally
// with the owner's ElGamal secret key, added to the current available balance,
// and the new available balance is re-encrypted (AES) into the account's
// decryptable balance. Keys are derived from the owner's wallet signer, or passed
// in as `keys`.
import {
  type Address,
  type ReadonlyUint8Array,
  type Rpc,
  type RpcSubscriptions,
  type Signature,
  type SolanaRpcApi,
  type SolanaRpcSubscriptionsApi,
  type TransactionSigner,
} from "@solana/kit";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  findAssociatedTokenPda,
  getApplyConfidentialPendingBalanceInstruction,
} from "@solana-program/token-2022";

import { ConfidentialTransfersError } from "./errors";
import { readConfiguredAccount } from "./internal/accounts";
import { readAvailableBalance } from "./internal/availableBalance";
import { assertKeysMatchAccount, ownerKeys } from "./internal/ownerKeys";
import { sendInstructions, withRetries, type SendOptions } from "./internal/send";
import { ElGamalCiphertext } from "./internal/zk";
import type { ConfidentialKeypairs } from "./keys";

const PENDING_BALANCE_LO_BIT_LENGTH = 16n;

export type ApplyPendingBalanceInput = SendOptions & {
  /** RPC client, e.g. `createSolanaRpc(url)`. */
  rpc: Rpc<SolanaRpcApi>;
  /** Used to confirm the transaction(s). */
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
  /** Pays the transaction fee. */
  payer: TransactionSigner;
  /** Signs the instruction, and the key-derivation message unless `keys` is given. */
  owner: TransactionSigner;
  mint: Address;
  /** Token account (defaults to the owner's ATA). */
  token?: Address;
  /** The owner's keys from {@link deriveConfidentialKeys}; skips the message signature. */
  keys?: ConfidentialKeypairs;
  /** Token program. Default: Token-2022. */
  programAddress?: Address;
};

export type ApplyPendingBalanceResult = { token: Address; signature: Signature };

/**
 * Move the incoming (pending) confidential balance into the available balance, which can be
 * transferred or withdrawn. Decrypts the pending amounts locally and writes the new available
 * balance, encrypted, in one transaction.
 */
export async function applyPendingBalance(input: ApplyPendingBalanceInput): Promise<ApplyPendingBalanceResult> {
  const operation = "applyPendingBalance";
  const programAddress = input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;
  const token =
    input.token ??
    (await findAssociatedTokenPda({ owner: input.owner.address, tokenProgram: programAddress, mint: input.mint }))[0];

  let keys = input.keys;
  const signature = await withRetries(input.retries, async () => {
    // Read the account on every attempt: the pending balance and its credit counter change with
    // each incoming transfer, and the instruction has to match them.
    const { data, ct } = await readConfiguredAccount(input.rpc, token, operation, "your");
    keys ??= await ownerKeys(input.owner, undefined, operation);
    assertKeysMatchAccount(keys, data, token, operation);
    const { elgamalKeypair, aesKey } = keys;
    const elgamalSecretKey = elgamalKeypair.secret();

    const decrypt = (what: string, run: () => bigint) => {
      try {
        return run();
      } catch (e) {
        throw new ConfidentialTransfersError(
          "DECRYPTION_FAILED",
          `${operation}: could not decrypt the ${what} of ${token}. ` +
            (what === "pending balance (high part)"
              ? "Incoming amounts add up to more than can be decrypted at once (about 2^48 base units); " +
                "the pending balance cannot be applied with this SDK. "
              : "") +
            String(e),
          { operation, cause: e },
        );
      }
    };
    const parseElGamal = (bytes: ReadonlyUint8Array) => {
      const c = ElGamalCiphertext.fromBytes(new Uint8Array(bytes as Uint8Array));
      if (!c) throw new ConfidentialTransfersError("DECRYPTION_FAILED", `${operation}: failed to parse an ElGamal ciphertext`, { operation });
      return c;
    };

    const pendingLo = decrypt("pending balance (low part)", () => elgamalSecretKey.decrypt(parseElGamal(ct.pendingBalanceLow)));
    const pendingHi = decrypt("pending balance (high part)", () => elgamalSecretKey.decrypt(parseElGamal(ct.pendingBalanceHigh)));
    // The AES copy, or the corrected value if an earlier apply left the copy behind; the copy written
    // below then repairs it (internal/availableBalance.ts).
    const currentAvailable = readAvailableBalance(ct, keys, token, operation);
    const newAvailable = currentAvailable + ((pendingHi << PENDING_BALANCE_LO_BIT_LENGTH) + pendingLo);

    return sendInstructions(
      { rpc: input.rpc, rpcSubscriptions: input.rpcSubscriptions, payer: input.payer, operation, computeUnitPrice: input.computeUnitPrice },
      [
        getApplyConfidentialPendingBalanceInstruction(
          {
            token,
            authority: input.owner,
            expectedPendingBalanceCreditCounter: ct.pendingBalanceCreditCounter,
            newDecryptableAvailableBalance: aesKey.encrypt(newAvailable).toBytes(),
          },
          { programAddress },
        ),
      ],
    );
  });

  return { token, signature };
}
