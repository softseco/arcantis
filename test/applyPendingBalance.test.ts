// SPDX-License-Identifier: BUSL-1.1
//
// Integration test for applyPendingBalance() + decryptBalance(). Runs only with a
// client-matching Token-2022 program loaded into the validator:
//   Terminal 1:  TOKEN_2022_SO=/path/to/spl_token_2022.so npm run validator
//   Terminal 2:  CT_LOCAL_PROGRAM=1 npm test
import { expect } from "chai";

import { applyPendingBalance } from "../src/applyPendingBalance";
import { configureAccount } from "../src/configureAccount";
import { decryptBalance } from "../src/decryptBalance";
import { deposit } from "../src/deposit";
import {
  createConfidentialMint,
  fundedSigner,
  mintPublicTokens,
  rpc,
  rpcSubscriptions,
} from "./_helpers";

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

describeOnChain("applyPendingBalance + decryptBalance (integration)", function () {
  this.timeout(120000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("applies the pending balance and decrypts the available balance", async () => {
    const payer = await fundedSigner();
    const owner = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);

    const { token } = await configureAccount({ rpc, rpcSubscriptions, payer, owner, mint });

    const amount = 1000n;
    await mintPublicTokens({ payer, mint, token, mintAuthority, amount });
    await deposit({ rpc, rpcSubscriptions, payer, owner, mint, amount, decimals });

    // After deposit the amount sits in PENDING; available is still zero.
    expect(await decryptBalance({ rpc, owner, mint })).to.equal(0n);

    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner, mint });

    // Now it is available and decrypts to the deposited amount.
    expect(await decryptBalance({ rpc, owner, mint })).to.equal(amount);
  });
});
