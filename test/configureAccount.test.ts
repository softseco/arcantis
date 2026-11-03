// SPDX-License-Identifier: BUSL-1.1
//
// Integration test for configureAccount(). Runs only with a CT-capable local
// validator and CT_LOCAL_PROGRAM=1:
//   Terminal 1:  TOKEN_2022_SO=/path/to/spl_token_2022.so npm run validator
//   Terminal 2:  CT_LOCAL_PROGRAM=1 npm test
// Skipped automatically in CI (CT_LOCAL_PROGRAM unset) and when no validator runs.
import { fetchToken } from "@solana-program/token-2022";
import { isSome } from "@solana/kit";
import { expect } from "chai";

import { configureAccount } from "../src/configureAccount";
import { createConfidentialMint, fundedSigner, rpc, rpcSubscriptions } from "./_helpers";

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

describeOnChain("configureAccount (integration)", function () {
  this.timeout(120000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("configures an account for confidential transfers", async () => {
    const payer = await fundedSigner();
    const owner = await fundedSigner();
    const { mint } = await createConfidentialMint(payer);

    const result = await configureAccount({ rpc, rpcSubscriptions, payer, owner, mint });

    expect(result.signature).to.be.a("string");
    expect(result.token).to.be.a("string");

    const { data } = await fetchToken(rpc, result.token);
    expect(isSome(data.extensions), "token account has no extensions").to.equal(true);
    const exts = isSome(data.extensions) ? data.extensions.value : [];
    const ct = exts.find((e) => e.__kind === "ConfidentialTransferAccount");
    expect(ct, "missing ConfidentialTransferAccount extension").to.not.equal(undefined);
  });
});
