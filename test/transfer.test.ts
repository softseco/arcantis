// SPDX-License-Identifier: BUSL-1.1
//
// Integration test for transfer() — the full confidential-transfer flow between
// two accounts. Runs only with a client-matching Token-2022 program loaded into
// the validator:
//   Terminal 1:  TOKEN_2022_SO=/path/to/spl_token_2022.so npm run validator
//   Terminal 2:  CT_LOCAL_PROGRAM=1 npm test
import { expect } from "chai";

import { applyPendingBalance } from "../src/applyPendingBalance";
import { configureAccount } from "../src/configureAccount";
import { decryptBalance } from "../src/decryptBalance";
import { deposit } from "../src/deposit";
import { transfer } from "../src/transfer";
import {
  createConfidentialMint,
  fundedSigner,
  mintPublicTokens,
  rpc,
  rpcSubscriptions,
} from "./_helpers";

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

describeOnChain("transfer (integration)", function () {
  this.timeout(180000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("confidentially transfers tokens from one account to another", async () => {
    const payer = await fundedSigner();
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);

    // Configure both accounts for confidential transfers.
    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });

    // Fund Alice's confidential available balance: mint -> deposit -> apply.
    const amount = 1000n;
    await mintPublicTokens({ payer, mint, token: aliceToken, mintAuthority, amount });
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount, decimals });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    expect(await decryptBalance({ rpc, owner: alice, mint })).to.equal(amount);

    // Confidentially transfer the whole balance to Bob.
    const { signatures } = await transfer({
      rpc,
      rpcSubscriptions,
      payer,
      owner: alice,
      mint,
      destinationOwner: bob.address,
      amount,
    });
    expect(signatures.length).to.be.greaterThan(0);

    // Bob applies the received pending balance and can decrypt it.
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    expect(await decryptBalance({ rpc, owner: bob, mint })).to.equal(amount);

    // Alice's available balance is now zero.
    expect(await decryptBalance({ rpc, owner: alice, mint })).to.equal(0n);
  });
});
