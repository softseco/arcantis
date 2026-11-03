// SPDX-License-Identifier: BUSL-1.1
//
// Confidential Transfers SDK — public API.

/**
 * TypeScript SDK for Token-2022 confidential transfers on Solana, built on `@solana/kit` 8.
 * Encrypted balances and amounts, in a handful of async functions: {@link configureAccount},
 * {@link deposit}, {@link applyPendingBalance}, {@link transfer}, {@link withdraw} and
 * {@link decryptBalance}. Runs in Node and, since 3.1.0, in the browser (see the Web apps guide).
 *
 * ```ts
 * const { token } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
 * await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 1000n, decimals });
 * await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });
 * await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 600n });
 * const balance = await decryptBalance({ rpc, owner: alice, mint }); // 400n
 * ```
 *
 * Self-audited, not independently audited.
 *
 * @packageDocumentation
 * @document ../guides/web-apps.md
 * @document ../guides/auditors.md
 */
export { initConfidentialTransfers } from "./internal/zk";
export { ConfidentialTransfersError, isConfidentialTransfersError } from "./errors";
export type { ConfidentialTransfersErrorCode, ConfidentialTransfersErrorDetails } from "./errors";
export type { SendOptions } from "./internal/send";
export { recoverProofAccounts } from "./recoverProofAccounts";
export type { RecoverProofAccountsInput, RecoverProofAccountsResult } from "./recoverProofAccounts";
export type { InitConfidentialTransfersOptions } from "./internal/zk";
export { configureAccount } from "./configureAccount";
export type { ConfigureAccountInput, ConfigureAccountResult } from "./configureAccount";
export { deposit } from "./deposit";
export type { DepositInput, DepositResult } from "./deposit";
export { applyPendingBalance } from "./applyPendingBalance";
export type { ApplyPendingBalanceInput, ApplyPendingBalanceResult } from "./applyPendingBalance";
export { decryptBalance } from "./decryptBalance";
export type { DecryptBalanceInput } from "./decryptBalance";
export { transfer } from "./transfer";
export type { TransferInput, TransferResult } from "./transfer";
export { withdraw } from "./withdraw";
export type { WithdrawInput, WithdrawResult } from "./withdraw";
export {
  decryptTransferAmountAsAuditor,
  deriveAuditorElgamalKeypair,
  getAuditorElgamalPubkey,
} from "./auditor";
export type { DecryptTransferAmountAsAuditorInput } from "./auditor";
export {
  confidentialActivityToCsv,
  confidentialActivityToJson,
  listConfidentialActivity,
  parseConfidentialActivityJson,
} from "./auditorReport";
export type {
  ConfidentialActivity,
  ConfidentialActivityCsvOptions,
  ConfidentialActivityJsonOptions,
  ConfidentialActivityKind,
  ConfidentialActivityReport,
  ListConfidentialActivityInput,
} from "./auditorReport";
export { CONFIDENTIAL_ACTIVITY_FORMAT, CONFIDENTIAL_ACTIVITY_VERSION, KEY_DERIVATION_SCHEME } from "./formats";
export {
  findExtraAccountMetaListPda,
  getTransferHookProgram,
  resolveTransferHookAccounts,
} from "./internal/transferHook";
export type { ResolveTransferHookAccountsInput, ResolvedAccount } from "./internal/transferHook";
export {
  deriveAeKey,
  deriveConfidentialKeys,
  deriveConfidentialKeysWithSeed,
  deriveElGamalKeypair,
  getElGamalPubkeyAddress,
  pdaWalletPublicSeed,
} from "./keys";
export type { ConfidentialKeypairs, DerivedElGamalKeypair } from "./keys";
