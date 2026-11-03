// SPDX-License-Identifier: BUSL-1.1
//
// Vendored confidential-transfer instruction plan, adapted from
// @solana-program/token-2022 (clients/js/src/confidentialTransferHelpers.ts).
//
// The upstream helper is published only against the `bundler` build of
// @solana/zk-sdk, whose JS `require()`s its .wasm and therefore cannot be loaded
// under Node/tsx. This copy imports the identical API from ./zk, which is the
// Node build of @solana/zk-sdk here and its web build in the browser build of
// this package, so the SDK runs in both with no shim. The proof math and on-chain
// layout are unchanged.
import {
  type AccountRole,
  generateKeyPairSigner,
  getAddressEncoder,
  isSome,
  parallelInstructionPlan,
  sequentialInstructionPlan,
  address,
  type Address,
  type GetMinimumBalanceForRentExemptionApi,
  type Instruction,
  type InstructionPlan,
  type ReadonlyUint8Array,
  type Rpc,
  type TransactionSigner,
} from "@solana/kit";
import {
  closeContextStateProof,
  verifyBatchedGroupedCiphertext3HandlesValidity,
  verifyBatchedRangeProofU128,
  verifyBatchedRangeProofU64,
  verifyCiphertextCommitmentEquality,
} from "@solana-program/zk-elgamal-proof";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  getConfidentialTransferInstruction,
  getConfidentialWithdrawInstruction,
  type Token,
} from "@solana-program/token-2022";
import {
  AeKey,
  BatchedGroupedCiphertext3HandlesValidityProofData,
  BatchedRangeProofU128Data,
  BatchedRangeProofU64Data,
  CiphertextCommitmentEqualityProofData,
  ElGamalCiphertext,
  ElGamalKeypair,
  ElGamalPubkey,
  GroupedElGamalCiphertext3Handles,
  PedersenCommitment,
  PedersenOpening,
} from "./zk";

import { ConfidentialTransfersError } from "../errors";
import { readAvailableBalance } from "./availableBalance";
import {
  extractCiphertextFromGroupedBytes,
  subtractAmountFromCiphertext,
  subtractWithLoHiCiphertexts,
} from "./confidentialTransferArithmetic";

/** The instructions sysvar, through which an instruction reads the others in its transaction. */
const SYSVAR_INSTRUCTIONS_ADDRESS = address("Sysvar1nstructions1111111111111111111111111");

const TRANSFER_AMOUNT_LO_BIT_LENGTH = 16n;
const TRANSFER_AMOUNT_HI_BIT_LENGTH = 32n;
const REMAINING_BALANCE_BIT_LENGTH = 64;
const RANGE_PROOF_PADDING_BIT_LENGTH = 16;

/** Max confidential-transfer amount: lo (16 bits) + hi (32 bits) = 2^48 - 1. */
const MAX_TRANSFER_AMOUNT =
  (1n << (TRANSFER_AMOUNT_LO_BIT_LENGTH + TRANSFER_AMOUNT_HI_BIT_LENGTH)) - 1n;

/** Minimal shape of the decoded ConfidentialTransferAccount extension we read. */
type ConfidentialTransferAccountExtension = {
  __kind: "ConfidentialTransferAccount";
  elgamalPubkey: Address;
  availableBalance: ReadonlyUint8Array;
  decryptableAvailableBalance: ReadonlyUint8Array;
};

export type GetConfidentialTransferInstructionPlanInput = {
  sourceToken: Address;
  mint: Address;
  destinationToken: Address;
  sourceTokenAccount: Token;
  auditorElgamalPubkey?: Address;
  authority: Address | TransactionSigner;
  amount: number | bigint;
  sourceElgamalKeypair: ElGamalKeypair;
  aesKey: AeKey;
  multiSigners?: Array<TransactionSigner>;
  /** Accounts the mint's transfer hook needs, appended to the transfer instruction. */
  transferHookAccounts?: ReadonlyArray<{ address: Address; role: AccountRole }>;
  programAddress?: Address;
  payer: TransactionSigner;
  rpc: Rpc<GetMinimumBalanceForRentExemptionApi>;
  proofMode?: "context-state";
} & (
  | { destinationTokenAccount: Token; destinationElgamalPubkey?: Address }
  | { destinationElgamalPubkey: Address; destinationTokenAccount?: never }
);

function getRequiredConfidentialTransferAccountExtension(
  tokenAccount: Token,
): ConfidentialTransferAccountExtension {
  if (!isSome(tokenAccount.extensions)) {
    throw new ConfidentialTransfersError("ACCOUNT_NOT_CONFIGURED", "Token account is missing extensions.");
  }
  const extension = tokenAccount.extensions.value.find(
    (candidate) => candidate.__kind === "ConfidentialTransferAccount",
  ) as ConfidentialTransferAccountExtension | undefined;
  if (!extension) {
    throw new ConfidentialTransfersError(
      "ACCOUNT_NOT_CONFIGURED",
      "Token account is missing the ConfidentialTransferAccount extension.",
    );
  }
  return extension;
}

function parseElGamalCiphertext(bytes: ReadonlyUint8Array) {
  const ciphertext = ElGamalCiphertext.fromBytes(new Uint8Array(bytes));
  if (!ciphertext) {
    throw new ConfidentialTransfersError("DECRYPTION_FAILED", "Failed to deserialize an ElGamal ciphertext.");
  }
  return ciphertext;
}

function getElGamalPubkeyFromAddress(value: Address) {
  return ElGamalPubkey.fromBytes(getAddressEncoder().encode(value) as Uint8Array);
}

function getDefaultAuditorElGamalPubkey() {
  return ElGamalPubkey.fromBytes(new Uint8Array(32));
}

function getDestinationElGamalPubkey(input: GetConfidentialTransferInstructionPlanInput) {
  if (input.destinationElgamalPubkey) {
    return getElGamalPubkeyFromAddress(input.destinationElgamalPubkey);
  }
  if (!input.destinationTokenAccount) {
    throw new ConfidentialTransfersError("INVALID_INPUT", "Destination confidential transfer state is required.");
  }
  return getElGamalPubkeyFromAddress(
    getRequiredConfidentialTransferAccountExtension(input.destinationTokenAccount).elgamalPubkey,
  );
}

function splitAmount(amount: bigint, bitLength: bigint): [bigint, bigint] {
  const mask = (1n << bitLength) - 1n;
  return [amount & mask, amount >> bitLength];
}

function assertNonNegativeAmount(amount: bigint): void {
  if (amount < 0n) {
    throw new ConfidentialTransfersError("INVALID_INPUT", "Amount must be non-negative.");
  }
}

function computeNewAvailableBalance(currentBalance: bigint, amount: bigint): bigint {
  assertNonNegativeAmount(amount);
  const newBalance = currentBalance - amount;
  if (newBalance < 0n) {
    throw new ConfidentialTransfersError(
      "INSUFFICIENT_FUNDS",
      // No amounts in the message: error messages end up in logs, and these are confidential.
      `Insufficient funds: the confidential available balance is less than the amount.`,
    );
  }
  return newBalance;
}

/**
 * The parts of a transfer or withdraw: verify the proofs into context-state accounts (`setup`), run
 * the instruction that uses them (`action`), close them again (`cleanup`). The executor sends
 * them in that order and, if something fails before `action` lands, closes whichever of
 * `proofAccounts` were created.
 */
export type ProofFlow = {
  proofAccounts: Address[];
  setup: InstructionPlan;
  action: Instruction;
  cleanup: Instruction[];
  /**
   * Accounts appended to `action` for the mint's transfer hook. None of them may sign the
   * transaction that carries `action`; the executor checks that before signing.
   */
  transferHookAccounts?: Address[];
};

/** The flow as one instruction plan: setup, then the action, then cleanup. */
export function proofFlowToPlan(flow: ProofFlow): InstructionPlan {
  return sequentialInstructionPlan([flow.setup, flow.action, parallelInstructionPlan(flow.cleanup)]);
}

/**
 * Builds the setup-and-cleanup plans for a single proof's context-state account.
 * The setup creates the context-state account and verifies the proof into it; the
 * cleanup closes the account to recover its rent.
 */
async function buildContextStateProofPlan(
  proofData: ReadonlyUint8Array,
  verifyAction: (args: {
    rpc: Rpc<GetMinimumBalanceForRentExemptionApi>;
    payer: TransactionSigner;
    proofData: Uint8Array;
    contextState: {
      contextAccount: Awaited<ReturnType<typeof generateKeyPairSigner>>;
      authority: Address;
    };
  }) => Promise<Instruction[]>,
  payer: TransactionSigner,
  rpc: Rpc<GetMinimumBalanceForRentExemptionApi>,
  contextStateAuthority: TransactionSigner = payer,
): Promise<{ address: Address; setup: InstructionPlan; cleanup: Instruction }> {
  const contextAccount = await generateKeyPairSigner();
  const setupInstructions = await verifyAction({
    rpc,
    payer,
    proofData: new Uint8Array(proofData),
    contextState: { contextAccount, authority: contextStateAuthority.address },
  });
  return {
    address: contextAccount.address,
    setup: sequentialInstructionPlan(setupInstructions),
    cleanup: closeContextStateProof({
      contextState: contextAccount.address,
      authority: contextStateAuthority,
      destination: payer.address,
    }),
  };
}

/**
 * Returns an instruction plan that confidentially transfers tokens between two
 * accounts. Splits the amount into lo/hi halves and verifies the three required
 * proofs (equality, grouped-ciphertext validity, batched range) via context-state
 * accounts.
 */
/** Append the mint's transfer-hook accounts to an instruction, if it has any. */
function withTransferHookAccounts<T extends { accounts?: unknown }>(
  instruction: T,
  hookAccounts?: ReadonlyArray<{ address: Address; role: AccountRole }>,
): T {
  if (hookAccounts == null || hookAccounts.length === 0) return instruction;
  return {
    ...instruction,
    accounts: [...((instruction.accounts ?? []) as unknown[]), ...hookAccounts],
  } as unknown as T;
}

export async function getConfidentialTransferInstructionPlan(
  input: GetConfidentialTransferInstructionPlanInput,
): Promise<InstructionPlan> {
  return proofFlowToPlan(await getConfidentialTransferProofFlow(input));
}

/** The three proofs of a transfer and the values its instruction carries. */
type TransferProofs = {
  equality: Uint8Array;
  ciphertextValidity: Uint8Array;
  range: Uint8Array;
  newSourceDecryptableAvailableBalance: Uint8Array;
  transferAmountAuditorCiphertextLo: Uint8Array;
  transferAmountAuditorCiphertextHi: Uint8Array;
};

async function buildTransferProofs(input: GetConfidentialTransferInstructionPlanInput): Promise<TransferProofs> {
  const sourceAccount = getRequiredConfidentialTransferAccountExtension(input.sourceTokenAccount);
  const amount = BigInt(input.amount);
  assertNonNegativeAmount(amount);
  if (amount > MAX_TRANSFER_AMOUNT) {
    throw new ConfidentialTransfersError(
      "AMOUNT_TOO_LARGE",
      `amount ${amount} exceeds the confidential-transfer maximum of ${MAX_TRANSFER_AMOUNT} (2^48-1)`,
    );
  }
  const [transferAmountLo, transferAmountHi] = splitAmount(amount, TRANSFER_AMOUNT_LO_BIT_LENGTH);

  const sourcePubkey = input.sourceElgamalKeypair.pubkey();
  const destinationPubkey = getDestinationElGamalPubkey(input);
  const auditorPubkey = input.auditorElgamalPubkey
    ? getElGamalPubkeyFromAddress(input.auditorElgamalPubkey)
    : getDefaultAuditorElGamalPubkey();

  const openingLo = new PedersenOpening();
  const openingHi = new PedersenOpening();
  const groupedCiphertextLo = GroupedElGamalCiphertext3Handles.encryptWith(
    sourcePubkey,
    destinationPubkey,
    auditorPubkey,
    transferAmountLo,
    openingLo,
  );
  const groupedCiphertextHi = GroupedElGamalCiphertext3Handles.encryptWith(
    sourcePubkey,
    destinationPubkey,
    auditorPubkey,
    transferAmountHi,
    openingHi,
  );

  const groupedCiphertextLoBytes = groupedCiphertextLo.toBytes();
  const groupedCiphertextHiBytes = groupedCiphertextHi.toBytes();
  const transferAmountSourceCiphertextLo = extractCiphertextFromGroupedBytes(groupedCiphertextLoBytes, 0);
  const transferAmountSourceCiphertextHi = extractCiphertextFromGroupedBytes(groupedCiphertextHiBytes, 0);
  const transferAmountAuditorCiphertextLo = extractCiphertextFromGroupedBytes(groupedCiphertextLoBytes, 2);
  const transferAmountAuditorCiphertextHi = extractCiphertextFromGroupedBytes(groupedCiphertextHiBytes, 2);

  const newAvailableBalance = computeNewAvailableBalance(
    readAvailableBalance(
      sourceAccount,
      { elgamalKeypair: input.sourceElgamalKeypair, aesKey: input.aesKey },
      input.sourceToken,
      "transfer",
    ),
    amount,
  );
  const newAvailableBalanceOpening = new PedersenOpening();
  const newAvailableBalanceCommitment = PedersenCommitment.from(newAvailableBalance, newAvailableBalanceOpening);
  const newAvailableBalanceCiphertext = parseElGamalCiphertext(
    subtractWithLoHiCiphertexts(
      sourceAccount.availableBalance,
      transferAmountSourceCiphertextLo,
      transferAmountSourceCiphertextHi,
      TRANSFER_AMOUNT_LO_BIT_LENGTH,
    ),
  );

  const equalityProofData = new CiphertextCommitmentEqualityProofData(
    input.sourceElgamalKeypair,
    newAvailableBalanceCiphertext,
    newAvailableBalanceCommitment,
    newAvailableBalanceOpening,
    newAvailableBalance,
  );
  const ciphertextValidityProofData = new BatchedGroupedCiphertext3HandlesValidityProofData(
    sourcePubkey,
    destinationPubkey,
    auditorPubkey,
    groupedCiphertextLo,
    groupedCiphertextHi,
    transferAmountLo,
    transferAmountHi,
    openingLo,
    openingHi,
  );

  const commitmentLo = PedersenCommitment.fromBytes(groupedCiphertextLoBytes.slice(0, 32));
  const commitmentHi = PedersenCommitment.fromBytes(groupedCiphertextHiBytes.slice(0, 32));
  const paddingOpening = new PedersenOpening();
  const paddingCommitment = PedersenCommitment.from(0n, paddingOpening);
  const rangeProofData = new BatchedRangeProofU128Data(
    [newAvailableBalanceCommitment, commitmentLo, commitmentHi, paddingCommitment],
    new BigUint64Array([newAvailableBalance, transferAmountLo, transferAmountHi, 0n]),
    Uint8Array.from([
      REMAINING_BALANCE_BIT_LENGTH,
      Number(TRANSFER_AMOUNT_LO_BIT_LENGTH),
      Number(TRANSFER_AMOUNT_HI_BIT_LENGTH),
      RANGE_PROOF_PADDING_BIT_LENGTH,
    ]),
    [newAvailableBalanceOpening, openingLo, openingHi, paddingOpening],
  );

  return {
    equality: equalityProofData.toBytes(),
    ciphertextValidity: ciphertextValidityProofData.toBytes(),
    range: rangeProofData.toBytes(),
    newSourceDecryptableAvailableBalance: input.aesKey.encrypt(newAvailableBalance).toBytes(),
    transferAmountAuditorCiphertextLo,
    transferAmountAuditorCiphertextHi,
  };
}

/**
 * A transfer in one transaction: the three proofs are verified from instruction data, right before
 * the transfer, which finds them by their offset (-3, -2, -1) through the instructions sysvar. No
 * proof accounts are created, so there is nothing to close. Too large for a legacy or v0
 * transaction (1,232 bytes); it needs a v1 transaction (up to 4,096 bytes).
 */
export async function getConfidentialTransferInlineInstructions(
  input: GetConfidentialTransferInstructionPlanInput,
): Promise<Instruction[]> {
  const proofs = await buildTransferProofs(input);
  const [[equality], [ciphertextValidity], [range]] = await Promise.all([
    verifyCiphertextCommitmentEquality({ rpc: input.rpc, payer: input.payer, proofData: proofs.equality }),
    verifyBatchedGroupedCiphertext3HandlesValidity({ rpc: input.rpc, payer: input.payer, proofData: proofs.ciphertextValidity }),
    verifyBatchedRangeProofU128({ rpc: input.rpc, payer: input.payer, proofData: proofs.range }),
  ]);
  const transfer = withTransferHookAccounts(
    getConfidentialTransferInstruction(
      {
        sourceToken: input.sourceToken,
        mint: input.mint,
        destinationToken: input.destinationToken,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_ADDRESS,
        authority: input.authority,
        newSourceDecryptableAvailableBalance: proofs.newSourceDecryptableAvailableBalance,
        transferAmountAuditorCiphertextLo: proofs.transferAmountAuditorCiphertextLo,
        transferAmountAuditorCiphertextHi: proofs.transferAmountAuditorCiphertextHi,
        equalityProofInstructionOffset: -3,
        ciphertextValidityProofInstructionOffset: -2,
        rangeProofInstructionOffset: -1,
        multiSigners: input.multiSigners,
      },
      { programAddress: input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS },
    ),
    input.transferHookAccounts,
  );
  return [equality, ciphertextValidity, range, transfer];
}

export async function getConfidentialTransferProofFlow(
  input: GetConfidentialTransferInstructionPlanInput,
): Promise<ProofFlow> {
  const proofs = await buildTransferProofs(input);
  const [equalityProofPlan, ciphertextValidityProofPlan, rangeProofPlan] = await Promise.all([
    buildContextStateProofPlan(proofs.equality, verifyCiphertextCommitmentEquality, input.payer, input.rpc),
    buildContextStateProofPlan(
      proofs.ciphertextValidity,
      verifyBatchedGroupedCiphertext3HandlesValidity,
      input.payer,
      input.rpc,
    ),
    buildContextStateProofPlan(proofs.range, verifyBatchedRangeProofU128, input.payer, input.rpc),
  ]);

  return {
    proofAccounts: [equalityProofPlan.address, ciphertextValidityProofPlan.address, rangeProofPlan.address],
    setup: parallelInstructionPlan([
      equalityProofPlan.setup,
      ciphertextValidityProofPlan.setup,
      rangeProofPlan.setup,
    ]),
    action: withTransferHookAccounts(
      getConfidentialTransferInstruction(
      {
        sourceToken: input.sourceToken,
        mint: input.mint,
        destinationToken: input.destinationToken,
        equalityRecord: equalityProofPlan.address,
        ciphertextValidityRecord: ciphertextValidityProofPlan.address,
        rangeRecord: rangeProofPlan.address,
        authority: input.authority,
        newSourceDecryptableAvailableBalance: proofs.newSourceDecryptableAvailableBalance,
        transferAmountAuditorCiphertextLo: proofs.transferAmountAuditorCiphertextLo,
        transferAmountAuditorCiphertextHi: proofs.transferAmountAuditorCiphertextHi,
        equalityProofInstructionOffset: 0,
        ciphertextValidityProofInstructionOffset: 0,
        rangeProofInstructionOffset: 0,
        multiSigners: input.multiSigners,
      },
      { programAddress: input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS },
      ),
      input.transferHookAccounts,
    ),
    cleanup: [equalityProofPlan.cleanup, ciphertextValidityProofPlan.cleanup, rangeProofPlan.cleanup],
    transferHookAccounts: (input.transferHookAccounts ?? []).map((account) => account.address),
  };
}

export type GetConfidentialWithdrawInstructionPlanInput = {
  /** Token account to withdraw from. */
  token: Address;
  mint: Address;
  /** The decoded token account, read just before building the plan. */
  tokenAccount: Token;
  authority: Address | TransactionSigner;
  amount: number | bigint;
  decimals: number;
  elgamalKeypair: ElGamalKeypair;
  aesKey: AeKey;
  multiSigners?: Array<TransactionSigner>;
  programAddress?: Address;
  payer: TransactionSigner;
  rpc: Rpc<GetMinimumBalanceForRentExemptionApi>;
};

/**
 * Returns an instruction plan that moves tokens from the encrypted available
 * balance back to the public balance of the same account. Verifies the two
 * required proofs (ciphertext-commitment equality and a U64 range proof on the
 * remaining balance) via context-state accounts, runs the withdraw, and closes
 * the proof accounts. Adapted from the upstream helper of the same name.
 */
export async function getConfidentialWithdrawInstructionPlan(
  input: GetConfidentialWithdrawInstructionPlanInput,
): Promise<InstructionPlan> {
  return proofFlowToPlan(await getConfidentialWithdrawProofFlow(input));
}

/** The two proofs of a withdraw and the new decryptable balance its instruction carries. */
type WithdrawProofs = {
  amount: bigint;
  equality: Uint8Array;
  range: Uint8Array;
  newDecryptableAvailableBalance: Uint8Array;
};

async function buildWithdrawProofs(input: GetConfidentialWithdrawInstructionPlanInput): Promise<WithdrawProofs> {
  const account = getRequiredConfidentialTransferAccountExtension(input.tokenAccount);
  const amount = BigInt(input.amount);
  if (amount <= 0n) {
    throw new ConfidentialTransfersError("INVALID_INPUT", `withdraw amount must be greater than zero, got ${amount}`);
  }
  const newAvailableBalance = computeNewAvailableBalance(
    readAvailableBalance(account, { elgamalKeypair: input.elgamalKeypair, aesKey: input.aesKey }, input.token, "withdraw"),
    amount,
  );

  const remainingBalanceOpening = new PedersenOpening();
  const remainingBalanceCommitment = PedersenCommitment.from(newAvailableBalance, remainingBalanceOpening);
  const remainingBalanceCiphertext = parseElGamalCiphertext(
    subtractAmountFromCiphertext(account.availableBalance, amount),
  );

  const equalityProofData = new CiphertextCommitmentEqualityProofData(
    input.elgamalKeypair,
    remainingBalanceCiphertext,
    remainingBalanceCommitment,
    remainingBalanceOpening,
    newAvailableBalance,
  );
  const rangeProofData = new BatchedRangeProofU64Data(
    [remainingBalanceCommitment],
    new BigUint64Array([newAvailableBalance]),
    Uint8Array.from([REMAINING_BALANCE_BIT_LENGTH]),
    [remainingBalanceOpening],
  );

  return {
    amount,
    equality: equalityProofData.toBytes(),
    range: rangeProofData.toBytes(),
    newDecryptableAvailableBalance: input.aesKey.encrypt(newAvailableBalance).toBytes(),
  };
}

/**
 * A withdraw in one transaction: the two proofs are verified from instruction data right before
 * the withdraw, which finds them by their offset (-2, -1). Like the one-transaction transfer, it
 * needs a v1 transaction.
 */
export async function getConfidentialWithdrawInlineInstructions(
  input: GetConfidentialWithdrawInstructionPlanInput,
): Promise<Instruction[]> {
  const proofs = await buildWithdrawProofs(input);
  const [[equality], [range]] = await Promise.all([
    verifyCiphertextCommitmentEquality({ rpc: input.rpc, payer: input.payer, proofData: proofs.equality }),
    verifyBatchedRangeProofU64({ rpc: input.rpc, payer: input.payer, proofData: proofs.range }),
  ]);
  const withdraw = getConfidentialWithdrawInstruction(
    {
      token: input.token,
      mint: input.mint,
      instructionsSysvar: SYSVAR_INSTRUCTIONS_ADDRESS,
      authority: input.authority,
      amount: proofs.amount,
      decimals: input.decimals,
      newDecryptableAvailableBalance: proofs.newDecryptableAvailableBalance,
      equalityProofInstructionOffset: -2,
      rangeProofInstructionOffset: -1,
      multiSigners: input.multiSigners,
    },
    { programAddress: input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS },
  );
  return [equality, range, withdraw];
}

export async function getConfidentialWithdrawProofFlow(
  input: GetConfidentialWithdrawInstructionPlanInput,
): Promise<ProofFlow> {
  const proofs = await buildWithdrawProofs(input);
  const [equalityProofPlan, rangeProofPlan] = await Promise.all([
    buildContextStateProofPlan(proofs.equality, verifyCiphertextCommitmentEquality, input.payer, input.rpc),
    buildContextStateProofPlan(proofs.range, verifyBatchedRangeProofU64, input.payer, input.rpc),
  ]);

  return {
    proofAccounts: [equalityProofPlan.address, rangeProofPlan.address],
    setup: parallelInstructionPlan([equalityProofPlan.setup, rangeProofPlan.setup]),
    action: getConfidentialWithdrawInstruction(
      {
        token: input.token,
        mint: input.mint,
        equalityRecord: equalityProofPlan.address,
        rangeRecord: rangeProofPlan.address,
        authority: input.authority,
        amount: proofs.amount,
        decimals: input.decimals,
        newDecryptableAvailableBalance: proofs.newDecryptableAvailableBalance,
        equalityProofInstructionOffset: 0,
        rangeProofInstructionOffset: 0,
        multiSigners: input.multiSigners,
      },
      { programAddress: input.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS },
    ),
    cleanup: [equalityProofPlan.cleanup, rangeProofPlan.cleanup],
  };
}
