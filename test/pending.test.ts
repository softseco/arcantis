// SPDX-License-Identifier: BUSL-1.1
//
// The pending balance applied inside the transaction that needs it, the checked apply, the pinned
// recipient key and closeAccount. Runs only with a client-matching Token-2022 program loaded into
// the validator:
//   Terminal 1:  TOKEN_2022_SO=/path/to/spl_token_2022.so npm run validator
//   Terminal 2:  CT_LOCAL_PROGRAM=1 npm test
import { expect } from "chai";
import { address, generateKeyPairSigner } from "@solana/kit";
import { fetchMaybeToken, fetchToken, getBurnCheckedInstruction } from "@solana-program/token-2022";

import { applyPendingBalance } from "../src/applyPendingBalance";
import { closeAccount } from "../src/closeAccount";
import { configureAccount } from "../src/configureAccount";
import { decryptBalance } from "../src/decryptBalance";
import { deposit } from "../src/deposit";
import { isConfidentialTransfersError } from "../src/errors";
import { readConfiguredAccount } from "../src/internal/accounts";
import { ciphertextHolds } from "../src/internal/availableBalance";
import { getConfidentialWithdrawInlineInstructions } from "../src/internal/confidentialTransferProof";
import { applyPendingLocally, isBalanceChangedError } from "../src/internal/pendingBalance";
import { sendSingleTransaction } from "../src/internal/send";
import { deriveConfidentialKeys } from "../src/keys";
import { transfer } from "../src/transfer";
import { withdraw } from "../src/withdraw";
import { createConfidentialMint, fundedSigner, mintPublicTokens, rpc, rpcSubscriptions, sendInstructions } from "./_helpers";

const describeOnChain = process.env.CT_LOCAL_PROGRAM === "1" ? describe : describe.skip;

describeOnChain("the pending balance (integration)", function () {
  this.timeout(240000);

  before(async function () {
    try {
      await rpc.getVersion().send();
    } catch {
      this.skip();
    }
  });

  it("spends and withdraws what is pending without a separate apply, and checks an apply against a credit that raced it", async () => {
    const payer = await fundedSigner();
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    await mintPublicTokens({ payer, mint, token: aliceToken, mintAuthority, amount: 1500n });

    // 400 deposited and left pending.
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 400n, decimals });
    expect(await decryptBalance({ rpc, owner: alice, mint })).to.equal(0n);
    expect(await decryptBalance({ rpc, owner: alice, mint, includePending: true })).to.equal(400n);

    // An apply built from what Alice read, then a credit that lands before it: Token-2022 refuses
    // the checked apply as a whole, and nothing changes.
    const keys = await deriveConfidentialKeys({ signer: alice });
    const before = await readConfiguredAccount(rpc, aliceToken, "test");
    const applied = applyPendingLocally(before.ct, keys, aliceToken, "test");
    const checkedApply = await getConfidentialWithdrawInlineInstructions({
      payer,
      rpc,
      token: aliceToken,
      mint,
      tokenAccount: before.data,
      authority: alice,
      amount: 0n,
      allowZero: true,
      decimals,
      elgamalKeypair: keys.elgamalKeypair,
      aesKey: keys.aesKey,
      applied,
    });
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 100n, decimals });
    let refused: unknown;
    try {
      await sendSingleTransaction({ rpc, rpcSubscriptions, payer, operation: "test" }, checkedApply);
    } catch (e) {
      refused = e;
    }
    expect(isBalanceChangedError(refused), String(refused)).to.equal(true);
    expect(await decryptBalance({ rpc, owner: alice, mint })).to.equal(0n);
    expect(await decryptBalance({ rpc, owner: alice, mint, includePending: true })).to.equal(500n);

    // The checked apply through the SDK: both copies of the balance agree afterwards.
    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: alice, mint, keys });
    const after = await readConfiguredAccount(rpc, aliceToken, "test");
    expect(BigInt(after.ct.pendingBalanceCreditCounter)).to.equal(0n);
    expect(ciphertextHolds(after.ct.availableBalance, keys.elgamalKeypair.secret().toBytes(), 500n)).to.equal(true);
    expect(await decryptBalance({ rpc, owner: alice, mint, keys })).to.equal(500n);

    // 300 more pending; Alice sends 650, more than her available 500, in one transaction.
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 300n, decimals });
    const sent = await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 650n, keys });
    expect(sent.signatures).to.have.length(1);
    expect(await decryptBalance({ rpc, owner: alice, mint, keys })).to.equal(150n);
    expect(await decryptBalance({ rpc, owner: alice, mint, keys, includePending: true })).to.equal(150n);

    // Bob withdraws 200 of the 650 still pending, without applying first.
    const bobToken = (await readConfiguredAccount(rpc, sent.destinationToken, "test")).data;
    expect(bobToken.amount).to.equal(0n);
    await withdraw({ rpc, rpcSubscriptions, payer, owner: bob, mint, amount: 200n, decimals });
    expect((await fetchToken(rpc, sent.destinationToken)).data.amount).to.equal(200n);
    expect(await decryptBalance({ rpc, owner: bob, mint })).to.equal(450n);

    // With applyPending: false the old rule holds: only the available balance can be spent.
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 300n, decimals });
    let insufficient: unknown;
    try {
      await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 400n, keys, applyPending: false });
    } catch (e) {
      insufficient = e;
    }
    expect(isConfidentialTransfersError(insufficient, "INSUFFICIENT_FUNDS"), String(insufficient)).to.equal(true);
  });

  it("refuses a recipient whose key is not the pinned one, before anything is signed", async () => {
    const payer = await fundedSigner();
    const alice = await fundedSigner();
    const bob = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
    const { token: aliceToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: alice, mint });
    const { token: bobToken } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    await mintPublicTokens({ payer, mint, token: aliceToken, mintAuthority, amount: 100n });
    await deposit({ rpc, rpcSubscriptions, payer, owner: alice, mint, amount: 100n, decimals });

    const stranger = (await generateKeyPairSigner()).address;
    let refused: unknown;
    try {
      await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 10n, destinationElgamalPubkey: stranger });
    } catch (e) {
      refused = e;
    }
    expect(isConfidentialTransfersError(refused, "RECIPIENT_KEY_MISMATCH"), String(refused)).to.equal(true);
    expect(await decryptBalance({ rpc, owner: alice, mint, includePending: true })).to.equal(100n);

    const bobKey = address((await readConfiguredAccount(rpc, bobToken, "test")).ct.elgamalPubkey);
    await transfer({ rpc, rpcSubscriptions, payer, owner: alice, mint, destinationOwner: bob.address, amount: 10n, destinationElgamalPubkey: bobKey });
    expect(await decryptBalance({ rpc, owner: bob, mint, includePending: true })).to.equal(10n);
  });

  it("closes an emptied account and returns its rent, and refuses one that still holds tokens", async () => {
    const payer = await fundedSigner();
    const carol = await fundedSigner();
    const { mint, mintAuthority, decimals } = await createConfidentialMint(payer);
    const { token } = await configureAccount({ rpc, rpcSubscriptions, payer, owner: carol, mint });
    await mintPublicTokens({ payer, mint, token, mintAuthority, amount: 100n });
    await deposit({ rpc, rpcSubscriptions, payer, owner: carol, mint, amount: 100n, decimals });

    let refused: unknown;
    try {
      await closeAccount({ rpc, rpcSubscriptions, payer, owner: carol, mint });
    } catch (e) {
      refused = e;
    }
    expect(isConfidentialTransfersError(refused, "INVALID_INPUT"), String(refused)).to.equal(true);

    // Everything back to public (the pending 100 included), then burned: the account is empty.
    await withdraw({ rpc, rpcSubscriptions, payer, owner: carol, mint, amount: 100n, decimals });
    let stillPublic: unknown;
    try {
      await closeAccount({ rpc, rpcSubscriptions, payer, owner: carol, mint });
    } catch (e) {
      stillPublic = e;
    }
    expect(String(stillPublic)).to.match(/still has a public balance/);
    await sendInstructions(payer, [getBurnCheckedInstruction({ account: token, mint, authority: carol, amount: 100n, decimals })]);

    const rent = (await rpc.getBalance(token).send()).value;
    const before = (await rpc.getBalance(carol.address).send()).value;
    await closeAccount({ rpc, rpcSubscriptions, payer, owner: carol, mint });
    expect((await fetchMaybeToken(rpc, token)).exists).to.equal(false);
    expect((await rpc.getBalance(carol.address).send()).value).to.equal(before + rent);
  });
});
