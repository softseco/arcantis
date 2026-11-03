// SPDX-License-Identifier: BUSL-1.1
//
// What transfer() and withdraw() refuse before any proof is built or the wallet is asked for
// anything, because Token-2022 would refuse it on chain: a mint with a transfer fee, a paused
// mint, a frozen account, and a recipient given two ways that disagree. The accounts are encoded
// with the token-2022 client and served from memory; no validator needed.
import { AccountState, TOKEN_2022_PROGRAM_ADDRESS, extension, findAssociatedTokenPda, type ExtensionArgs } from "@solana-program/token-2022";
import { generateKeyPairSigner, some, type Address } from "@solana/kit";
import { expect } from "chai";

import { transfer, withdraw } from "../src/index";
import { accountsRpc, mintBytes, rejection, tokenAccountBytes, walletLike } from "./_offline";

async function setUp(options: { mint?: ExtensionArgs[]; source?: AccountState; recipient?: AccountState } = {}) {
  const [payerKey, ownerKey, recipient, other, mintKey] = await Promise.all(Array.from({ length: 5 }, () => generateKeyPairSigner()));
  const payer = walletLike(payerKey);
  const owner = walletLike(ownerKey);
  const mint = mintKey.address;
  const ata = async (o: Address) => (await findAssociatedTokenPda({ owner: o, mint, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS }))[0];
  const recipientToken = await ata(recipient.address);
  const rpc = accountsRpc(
    new Map([
      [mint, { data: mintBytes(options.mint) }],
      [await ata(owner.signer.address), { data: tokenAccountBytes(mint, owner.signer.address, options.source) }],
      [recipientToken, { data: tokenAccountBytes(mint, recipient.address, options.recipient) }],
    ]),
  );
  const base = { rpc, rpcSubscriptions: {} as never, payer: payer.signer, owner: owner.signer, mint };
  return {
    send: (more: Partial<Parameters<typeof transfer>[0]> = {}) =>
      transfer({ ...base, destinationOwner: recipient.address, amount: 1n, ...more }),
    withdraw: () => withdraw({ ...base, amount: 1n, decimals: 2 }),
    recipientToken,
    other: other.address,
    // Nothing was signed, and the owner (who cannot sign messages) was not asked for its keys.
    asked: () => payer.counts.requests + owner.counts.requests,
  };
}

const fee = extension("TransferFeeConfig", {
  transferFeeConfigAuthority: "11111111111111111111111111111111" as Address,
  withdrawWithheldAuthority: "11111111111111111111111111111111" as Address,
  withheldAmount: 0n,
  olderTransferFee: { epoch: 0n, maximumFee: 0n, transferFeeBasisPoints: 0 },
  newerTransferFee: { epoch: 0n, maximumFee: 0n, transferFeeBasisPoints: 0 },
});
const paused = extension("PausableConfig", { authority: some("11111111111111111111111111111111" as Address), paused: true });

describe("checks before a transfer is built", () => {
  it("refuses a mint with a transfer fee, which needs TransferWithFee", async () => {
    const s = await setUp({ mint: [fee] });
    const error = await rejection(s.send());
    expect(error.code).to.equal("INVALID_INPUT");
    expect(error.message).to.contain("transfer fee");
    expect(s.asked()).to.equal(0);
  });

  it("refuses a paused mint, for transfers and withdrawals", async () => {
    const s = await setUp({ mint: [paused] });
    for (const error of [await rejection(s.send()), await rejection(s.withdraw())]) {
      expect(error.code).to.equal("INVALID_INPUT");
      expect(error.message).to.contain("is paused");
    }
    expect(s.asked()).to.equal(0);
  });

  it("refuses a frozen source or recipient account", async () => {
    const source = await setUp({ source: AccountState.Frozen });
    expect((await rejection(source.send())).message).to.match(/your token account .* is frozen/);
    expect((await rejection(source.withdraw())).message).to.contain("is frozen");
    const recipient = await setUp({ recipient: AccountState.Frozen });
    expect((await rejection(recipient.send())).message).to.match(/recipient's token account .* is frozen/);
    expect(source.asked() + recipient.asked()).to.equal(0);
  });

  it("refuses destinationOwner and destinationToken that name different recipients", async () => {
    const s = await setUp();
    const error = await rejection(s.send({ destinationToken: s.recipientToken, destinationOwner: s.other }));
    expect(error.code).to.equal("INVALID_INPUT");
    expect(error.message).to.contain(`belongs to`);
    // Both naming the same recipient is fine: the call goes on, to ask the owner for its keys.
    const sameRecipient = await rejection(s.send({ destinationToken: s.recipientToken }));
    expect(sameRecipient.code).to.equal("CANNOT_SIGN_MESSAGES");
  });
});
