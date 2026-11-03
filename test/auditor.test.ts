// SPDX-License-Identifier: BUSL-1.1
//
// Auditor-key selective disclosure. The unit tests read hand-made transactions; the integration
// test needs a CT-capable validator:  CT_LOCAL_PROGRAM=1 npm test
import { getBase58Decoder, type Address, type Signature } from "@solana/kit";
import { TOKEN_2022_PROGRAM_ADDRESS, getConfidentialTransferInstructionDataEncoder } from "@solana-program/token-2022";
import { AeKey, ElGamalKeypair } from "@solana/zk-sdk/node";
import { expect } from "chai";

import { applyPendingBalance } from "../src/applyPendingBalance";
import {
  decryptTransferAmountAsAuditor,
  deriveAuditorElgamalKeypair,
  getAuditorElgamalPubkey,
} from "../src/auditor";
import { configureAccount } from "../src/configureAccount";
import { deposit } from "../src/deposit";
import { isConfidentialTransfersError } from "../src/errors";
import { transfer } from "../src/transfer";
import {
  createConfidentialMint,
  fundedSigner,
  mintPublicTokens,
  rpc,
  rpcSubscriptions,
} from "./_helpers";

describe("auditor reading one transaction", () => {
  const auditor = new ElGamalKeypair();
  const signature = "1111111111111111111111111111111111111111111111111111111111111111" as Signature;
  // A transfer of 70,000 (lo 4,464, hi 1) as Token-2022 records it: the instruction data in base58.
  const data = getBase58Decoder().decode(
    getConfidentialTransferInstructionDataEncoder().encode({
      newSourceDecryptableAvailableBalance: new AeKey().encrypt(0n).toBytes(),
      transferAmountAuditorCiphertextLo: auditor.pubkey().encryptU64(70_000n & 0xffffn).toBytes(),
      transferAmountAuditorCiphertextHi: auditor.pubkey().encryptU64(70_000n >> 16n).toBytes(),
      equalityProofInstructionOffset: 0,
      ciphertextValidityProofInstructionOffset: 0,
      rangeProofInstructionOffset: 0,
    }),
  );
  const rpcReturning = (transaction: unknown) =>
    ({ getTransaction: () => ({ send: async () => transaction }) }) as never;
  // A program's instruction at index 0, which made the transfer through a cross-program call; Token-2022
  // is the second account, from an address lookup table.
  const throughAProgram = (err: unknown) => ({
    transaction: { message: { accountKeys: ["Vault111111111111111111111111111111111111111"], instructions: [{ programIdIndex: 0, data: "" }] } },
    meta: {
      err,
      innerInstructions: [{ index: 0, instructions: [{ programIdIndex: 1, data }] }],
      loadedAddresses: { writable: [], readonly: [TOKEN_2022_PROGRAM_ADDRESS] },
    },
  });

  it("reads a transfer a program made through a cross-program call", async () => {
    const amount = await decryptTransferAmountAsAuditor({ rpc: rpcReturning(throughAProgram(null)), signature, auditorKeypair: auditor });
    expect(amount).to.equal(70_000n);
  });

  it("reports a key that cannot decrypt the amount as DECRYPTION_FAILED", async () => {
    let error: unknown;
    try {
      await decryptTransferAmountAsAuditor({ rpc: rpcReturning(throughAProgram(null)), signature, auditorKeypair: new ElGamalKeypair() });
    } catch (e) {
      error = e;
    }
    expect(isConfidentialTransfersError(error, "DECRYPTION_FAILED")).to.equal(true);
  });

  it("reads the transfer of the mint asked for, or else the first one", async () => {
    // Two transfers in one transaction: 70,000 of mint A, then 5 of mint B.
    const five = getBase58Decoder().decode(
      getConfidentialTransferInstructionDataEncoder().encode({
        newSourceDecryptableAvailableBalance: new AeKey().encrypt(0n).toBytes(),
        transferAmountAuditorCiphertextLo: auditor.pubkey().encryptU64(5n).toBytes(),
        transferAmountAuditorCiphertextHi: auditor.pubkey().encryptU64(0n).toBytes(),
        equalityProofInstructionOffset: 0,
        ciphertextValidityProofInstructionOffset: 0,
        rangeProofInstructionOffset: 0,
      }),
    );
    const mintA = "So11111111111111111111111111111111111111112" as Address;
    const mintB = "SysvarC1ock11111111111111111111111111111111" as Address;
    const source = "Vault111111111111111111111111111111111111111";
    const transaction = {
      transaction: {
        message: {
          accountKeys: [TOKEN_2022_PROGRAM_ADDRESS, mintA, mintB, source],
          instructions: [
            { programIdIndex: 0, accounts: [3, 1, 3], data },
            { programIdIndex: 0, accounts: [3, 2, 3], data: five },
          ],
        },
      },
      meta: { err: null },
    };
    const read = (mint?: Address) => decryptTransferAmountAsAuditor({ rpc: rpcReturning(transaction), signature, auditorKeypair: auditor, mint });
    expect(await read()).to.equal(70_000n);
    expect(await read(mintA)).to.equal(70_000n);
    expect(await read(mintB)).to.equal(5n);
    let error: unknown;
    try {
      await read(source as Address);
    } catch (e) {
      error = e;
    }
    expect(isConfidentialTransfersError(error, "INVALID_INPUT")).to.equal(true);
  });

  it("refuses a transaction that failed, which transferred nothing", async () => {
    let error: unknown;
    try {
      await decryptTransferAmountAsAuditor({ rpc: rpcReturning(throughAProgram({ InstructionError: [0, "Custom"] })), signature, auditorKeypair: auditor });
    } catch (e) {
      error = e;
    }
    expect(isConfidentialTransfersError(error, "TRANSACTION_FAILED")).to.equal(true);
  });
});

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

describeOnChain("auditor selective disclosure (integration)", function () {
  this.timeout(180000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("lets the designated auditor recover a confidential transfer amount", async () => {
    const payer = await fundedSigner();
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    const auditor = await fundedSigner();

    // The auditor holds an ElGamal keypair; its public key goes into the mint.
    const auditorKeypair = await deriveAuditorElgamalKeypair(auditor);
    const auditorPubkey = getAuditorElgamalPubkey(auditorKeypair);
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer, 2, auditorPubkey);

    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });

    const amount = 1000n;
    await mintPublicTokens({ payer, mint, token: aliceToken, mintAuthority, amount });
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount, decimals });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });

    // Transfer must encrypt the amount to the mint's auditor too.
    const { signatures } = await transfer({
      rpc,
      rpcSubscriptions,
      payer,
      owner: alice,
      mint,
      destinationOwner: bob.address,
      amount,
      auditorElgamalPubkey: auditorPubkey,
    });

    // The auditor recovers the amount from whichever transaction holds the transfer.
    let recovered: bigint | undefined;
    for (const signature of signatures) {
      try {
        recovered = await decryptTransferAmountAsAuditor({ rpc, signature, auditorKeypair });
        break;
      } catch {
        // not the transfer instruction's transaction — try the next signature
      }
    }
    expect(recovered).to.equal(amount);
  });
});
