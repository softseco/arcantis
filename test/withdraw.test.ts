// SPDX-License-Identifier: BUSL-1.1
//
// Integration test for withdraw(). Runs only against a local validator with a
// client-matching Token-2022 program (see README):
//   Terminal 1:  TOKEN_2022_SO=/path/to/spl_token_2022.so npm run validator
//   Terminal 2:  CT_LOCAL_PROGRAM=1 npm test
// Without CT_LOCAL_PROGRAM=1 the suite is skipped (keeps default/CI runs green).
import { fetchToken } from "@solana-program/token-2022";
import { expect } from "chai";

import { applyPendingBalance } from "../src/applyPendingBalance";
import { configureAccount } from "../src/configureAccount";
import { decryptBalance } from "../src/decryptBalance";
import { deposit } from "../src/deposit";
import { withdraw } from "../src/withdraw";
import {
  createConfidentialMint,
  fundedSigner,
  mintPublicTokens,
  rpc,
  rpcSubscriptions,
} from "./_helpers";

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

describeOnChain("withdraw (integration)", function () {
  this.timeout(180000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("moves part of the confidential balance back to the public balance", async () => {
    const payer = await fundedSigner();
    const owner = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
    const { token } = await configureAccount({ rpc, rpcSubscriptions, payer, owner, mint });

    await mintPublicTokens({ payer, mint, token, mintAuthority, amount: 1000n });
    await deposit({ rpc, rpcSubscriptions, payer, owner, mint, amount: 1000n, decimals });
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner, mint });

    const result = await withdraw({ rpc, rpcSubscriptions, payer, owner, mint, amount: 400n, decimals });
    expect(result.signatures.length).to.be.greaterThan(0);

    const account = await fetchToken(rpc, token);
    expect(account.data.amount).to.equal(400n);
    expect(await decryptBalance({ rpc, owner, mint })).to.equal(600n);
  });
});
