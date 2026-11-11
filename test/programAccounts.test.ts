// SPDX-License-Identifier: BUSL-1.1
//
// prepareConfigure, prepareApply, prepareWithdraw and prepareTransfer: instructions for an account
// whose owner is a program. Here the owner is an ordinary keypair standing in for the program: the
// test marks it as a signer of the instructions that name it, which is what a program does with
// invoke_signed. Runs only with a client-matching Token-2022 program loaded into the validator:
//   Terminal 1:  TOKEN_2022_SO=/path/to/spl_token_2022.so npm run validator
//   Terminal 2:  CT_LOCAL_PROGRAM=1 npm test
import { expect } from "chai";
import { AccountRole, type Instruction, type KeyPairSigner } from "@solana/kit";
import { TOKEN_2022_PROGRAM_ADDRESS, findAssociatedTokenPda, getCreateAssociatedTokenIdempotentInstruction } from "@solana-program/token-2022";

import { configureAccount } from "../src/configureAccount";
import { decryptBalance } from "../src/decryptBalance";
import { deposit } from "../src/deposit";
import { sendSingleTransaction } from "../src/internal/send";
import { deriveConfidentialKeysWithSeed, pdaWalletPublicSeed } from "../src/keys";
import { prepareApply, prepareConfigure, prepareTransfer, prepareWithdraw } from "../src/programAccounts";
import { createConfidentialMint, fundedSigner, mintPublicTokens, rpc, rpcSubscriptions, sendInstructions } from "./_helpers";

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

/** What a program does with invoke_signed: the owner signs every instruction that names it. */
function signedBy(owner: KeyPairSigner, instructions: Instruction[]): Instruction[] {
  return instructions.map((ix) => ({
    ...ix,
    accounts: ix.accounts?.map((meta) =>
      meta.address === owner.address
        ? {
            ...meta,
            role: meta.role === AccountRole.WRITABLE || meta.role === AccountRole.WRITABLE_SIGNER ? AccountRole.WRITABLE_SIGNER : AccountRole.READONLY_SIGNER,
            signer: owner,
          }
        : meta,
    ),
  }));
}

describeOnChain("accounts owned by a program (integration)", function () {
  this.timeout(240000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("configures, applies with a check, withdraws and transfers for an owner that only signs through its program", async () => {
    const payer = await fundedSigner();
    const vault = await fundedSigner(); // the program's PDA, in effect
    const bob = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
    const [token] = await findAssociatedTokenPda({ owner: vault.address, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS, mint });
    await sendInstructions(payer, [
      getCreateAssociatedTokenIdempotentInstruction({ ata: token, mint, owner: vault.address, payer, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS }),
    ]);
    await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });

    // The keys of a program-owned account: seeded, from the operator's signature.
    const operator = await fundedSigner();
    const keys = await deriveConfidentialKeysWithSeed({
      signer: operator,
      publicSeed: pdaWalletPublicSeed({ programId: TOKEN_2022_PROGRAM_ADDRESS, walletPda: vault.address, mint, tokenAccount: token }),
    });

    const configure = await prepareConfigure({ rpc, payer, token, mint, authority: vault.address, keys });
    expect(configure).to.have.length(3);
    await sendInstructions(payer, signedBy(vault, configure));

    await mintPublicTokens({ payer, mint, token, mintAuthority, amount: 1000n });
    await deposit({ rpc, rpcSubscriptions, payer, owner: vault, mint, amount: 1000n, decimals, keys });

    // 1000 pending; prepareApply says what the apply will leave.
    const preview = await prepareApply({ rpc, token, authority: vault.address, keys });
    expect(preview.instructions).to.have.length(1);
    expect(preview.value).to.equal(1000n);
    expect(preview.availableBalance).to.have.length(64);

    // A checked apply: apply, two proofs and a withdrawal of zero.
    const checked = await prepareWithdraw({ rpc, payer, mint, token, authority: vault.address, amount: 0n, keys });
    expect(checked).to.have.length(4);
    const ctx = { rpc, rpcSubscriptions, payer, operation: "test" };
    expect(await sendSingleTransaction(ctx, signedBy(vault, checked))).to.not.equal(null);
    expect(await decryptBalance({ rpc, owner: vault, mint, keys })).to.equal(1000n);
    expect((await prepareApply({ rpc, token, authority: vault.address, keys })).instructions).to.have.length(0);

    // 300 to Bob, then 200 back to the public balance.
    const [bobToken] = await findAssociatedTokenPda({ owner: bob.address, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS, mint });
    const transfer = await prepareTransfer({ rpc, payer, mint, sourceToken: token, authority: vault.address, destinationToken: bobToken, amount: 300n, keys });
    expect(await sendSingleTransaction(ctx, signedBy(vault, transfer))).to.not.equal(null);
    expect(await decryptBalance({ rpc, owner: bob, mint, includePending: true })).to.equal(300n);
    const withdraw = await prepareWithdraw({ rpc, payer, mint, token, authority: vault.address, amount: 200n, keys });
    expect(await sendSingleTransaction(ctx, signedBy(vault, withdraw))).to.not.equal(null);
    expect(await decryptBalance({ rpc, owner: vault, mint, keys })).to.equal(500n);

    // The source must belong to the authority named.
    let refused: unknown;
    try {
      await prepareTransfer({ rpc, payer, mint, sourceToken: token, authority: bob.address, destinationToken: bobToken, amount: 1n, keys });
    } catch (e) {
      refused = e;
    }
    expect(String(refused)).to.match(/belongs to/);
  });
});
