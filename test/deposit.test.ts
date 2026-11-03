// SPDX-License-Identifier: BUSL-1.1
//
// Integration test for deposit(). Runs only when the local validator is started
// with a client-matching Token-2022 program — the program bundled in Agave 4.x
// rejects the confidential `deposit` instruction. Build the matching program
// (see README) and run:
//   Terminal 1:  TOKEN_2022_SO=/path/to/spl_token_2022.so npm run validator
//   Terminal 2:  CT_LOCAL_PROGRAM=1 npm test
// Without CT_LOCAL_PROGRAM=1 the suite is skipped (keeps default/CI runs green).
import { fetchToken } from "@solana-program/token-2022";
import { expect } from "chai";

import { configureAccount } from "../src/configureAccount";
import { deposit } from "../src/deposit";
import {
  createConfidentialMint,
  fundedSigner,
  mintPublicTokens,
  rpc,
  rpcSubscriptions,
} from "./_helpers";

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

describeOnChain("deposit (integration)", function () {
  this.timeout(120000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("moves public tokens into the confidential pending balance", async () => {
    const payer = await fundedSigner();
    const owner = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);

    const { token } = await configureAccount({ rpc, rpcSubscriptions, payer, owner, mint });

    const amount = 1000n;
    await mintPublicTokens({ payer, mint, token, mintAuthority, amount });

    const before = await fetchToken(rpc, token);
    expect(before.data.amount).to.equal(amount);

    const result = await deposit({ rpc, rpcSubscriptions, payer, owner, mint, amount, decimals });
    expect(result.signature).to.be.a("string");

    const after = await fetchToken(rpc, token);
    expect(after.data.amount).to.equal(0n);
  });
});
