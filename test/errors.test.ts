// SPDX-License-Identifier: BUSL-1.1
//
// Integration tests for error / guard paths. Require a CT-capable validator:
//   TOKEN_2022_SO=/path/to/spl_token_2022.so npm run validator
//   CT_LOCAL_PROGRAM=1 npm test
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  findAssociatedTokenPda,
  getApproveConfidentialTransferAccountInstruction,
  getCreateAssociatedTokenIdempotentInstruction,
  getDisableConfidentialCreditsInstruction,
} from "@solana-program/token-2022";
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS } from "@solana-program/zk-elgamal-proof";
import { expect } from "chai";

import { applyPendingBalance } from "../src/applyPendingBalance";
import { configureAccount } from "../src/configureAccount";
import { decryptBalance } from "../src/decryptBalance";
import { deposit } from "../src/deposit";
import { transfer } from "../src/transfer";
import { isConfidentialTransfersError, type ConfidentialTransfersErrorCode } from "../src/errors";
import {
  createConfidentialMint,
  fundedSigner,
  mintPublicTokens,
  rpc,
  rpcSubscriptions,
  sendInstructions,
} from "./_helpers";

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

async function expectRejection(
  promise: Promise<unknown>,
  contains: string,
  code?: ConfidentialTransfersErrorCode,
): Promise<void> {
  let err: unknown;
  try {
    await promise;
  } catch (e) {
    err = e;
  }
  expect(err, "expected the call to reject").to.be.an("error");
  expect((err as Error).message).to.contain(contains);
  if (code) expect(isConfidentialTransfersError(err, code), `expected code ${code}`).to.equal(true);
}

/** Create the owner's ATA without configuring it for confidential transfers. */
async function createUnconfiguredAccount(payer: Awaited<ReturnType<typeof fundedSigner>>, mint: string) {
  const owner = await fundedSigner();
  const [token] = await findAssociatedTokenPda({
    owner: owner.address,
    tokenProgram: TOKEN_2022_PROGRAM_ADDRESS,
    mint: mint as never,
  });
  await sendInstructions(payer, [
    getCreateAssociatedTokenIdempotentInstruction({
      ata: token,
      mint: mint as never,
      owner: owner.address,
      payer,
      tokenProgram: TOKEN_2022_PROGRAM_ADDRESS,
    }),
  ]);
  return owner;
}

describeOnChain("error & guard paths (integration)", function () {
  this.timeout(120000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("decryptBalance and applyPendingBalance reject an account without the CT extension", async () => {
    const payer = await fundedSigner();
    const { mint } = await createConfidentialMint(payer);
    const owner = await createUnconfiguredAccount(payer, mint);

    await expectRejection(decryptBalance({ rpc, owner, mint }), "ConfidentialTransferAccount", "ACCOUNT_NOT_CONFIGURED");
    await expectRejection(
      applyPendingBalance({ rpc, rpcSubscriptions, payer, owner, mint }),
      "ConfidentialTransferAccount",
      "ACCOUNT_NOT_CONFIGURED",
    );
  });

  it("deposit refuses an account that is not configured, before sending anything", async () => {
    const payer = await fundedSigner();
    const { mint, decimals } = await createConfidentialMint(payer);
    const owner = await createUnconfiguredAccount(payer, mint);

    await expectRejection(
      deposit({ rpc, rpcSubscriptions, payer, owner, mint, amount: 1n, decimals }),
      "configureAccount first",
      "ACCOUNT_NOT_CONFIGURED",
    );
  });

  it("deposit surfaces program logs when the chain refuses it", async () => {
    const payer = await fundedSigner();
    const owner = await fundedSigner();
    const { mint, mintAuthority } = await createConfidentialMint(payer, 2);
    const { token } = await configureAccount({ rpc, rpcSubscriptions, payer, owner, mint });
    await mintPublicTokens({ payer, mint, token, mintAuthority, amount: 10n });

    // Wrong decimals: only the program can tell, so the error comes from simulation, with logs.
    let err: unknown;
    try {
      await deposit({ rpc, rpcSubscriptions, payer, owner, mint, amount: 1n, decimals: 9 });
    } catch (e) {
      err = e;
    }
    expect(isConfidentialTransfersError(err, "TRANSACTION_FAILED")).to.equal(true);
    expect((err as Error).message).to.contain("failed simulation");
    expect((err as { logs?: string[] }).logs?.join("\n")).to.contain("Program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
  });

  it("transfer rejects an amount greater than the available balance", async () => {
    const payer = await fundedSigner();
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);

    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    await mintPublicTokens({ payer, mint, token: aliceToken, mintAuthority, amount: 100n });
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 100n, decimals });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });

    await expectRejection(
      transfer({
        rpc,
        rpcSubscriptions,
        payer,
        owner: alice,
        mint,
        destinationOwner: bob.address,
        amount: 1000n,
      }),
      "Insufficient funds",
      "INSUFFICIENT_FUNDS",
    );
  });

  it("configureAccount fails when the account is already configured", async () => {
    const payer = await fundedSigner();
    const owner = await fundedSigner();
    const { mint } = await createConfidentialMint(payer);
    await configureAccount({ rpc, rpcSubscriptions, payer, owner, mint });
    await expectRejection(
      configureAccount({ rpc, rpcSubscriptions, payer, owner, mint }),
      "already configured",
      "ACCOUNT_ALREADY_CONFIGURED",
    );
  });

  it("transfer refuses a recipient that is not approved or refuses confidential credits, before signing", async () => {
    const payer = await fundedSigner();
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    // New accounts wait for the confidential-transfer authority's approval.
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer, 2, undefined, undefined, false);
    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    const { token: bobToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    const approve = (token: typeof aliceToken) =>
      sendInstructions(payer, [getApproveConfidentialTransferAccountInstruction({ token, mint, authority: mintAuthority })]);
    await approve(aliceToken);
    await mintPublicTokens({ payer, mint, token: aliceToken, mintAuthority, amount: 100n });
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 100n, decimals });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });

    const send = () => transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 10n });
    await expectRejection(send(), "has not been approved", "ACCOUNT_NOT_APPROVED");
    await approve(bobToken);
    await sendInstructions(payer, [getDisableConfidentialCreditsInstruction({ token: bobToken, authority: bob })]);
    await expectRejection(send(), "does not accept confidential credits", "RECIPIENT_REJECTS_CONFIDENTIAL");

    // Both refusals came before anything was created.
    const proofAccounts = await rpc
      .getProgramAccounts(ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS, {
        encoding: "base64",
        dataSlice: { offset: 0, length: 0 },
        filters: [{ memcmp: { offset: 0n, bytes: payer.address as never, encoding: "base58" } }],
      })
      .send();
    expect(proofAccounts).to.have.length(0);
    expect(await decryptBalance({ rpc, owner: alice, mint })).to.equal(100n);
  });
});
