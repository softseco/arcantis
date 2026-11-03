// SPDX-License-Identifier: BUSL-1.1
//
// Softseco playground: Arcantis and Vigilantis in the browser, on Solana devnet, with throwaway keys.
//
//   Private amounts (Arcantis): fund -> create the token -> open accounts and deposit -> pay Bob
//                               -> who can read it -> Bob withdraws
//   Public rules (Vigilantis):  block a wallet -> freeze an account -> pause the token
//   Oversight:                  the auditor's report
//
// One token carries everything: Token-2022 with confidential transfers and an auditor key, and
// Vigilantis as its transfer hook, freeze authority and pause authority. Every Arcantis call below is
// the published SDK (@softseco/arcantis) as an app would use it; the Vigilantis instructions are
// encoded from its IDL in ./vigilantis.js.
import {
  address,
  appendTransactionMessageInstructions,
  assertIsTransactionWithBlockhashLifetime,
  createKeyPairSignerFromPrivateKeyBytes,
  createSolanaRpc,
  createTransactionMessage,
  generateKeyPairSigner,
  getSignatureFromTransaction,
  lamports,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  some,
} from "@solana/kit";
import { getCreateAccountInstruction } from "@solana-program/system";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  extension,
  fetchToken,
  findAssociatedTokenPda,
  getInitializeConfidentialTransferMintInstruction,
  getInitializeMint2Instruction,
  getInitializePausableConfigInstruction,
  getInitializeTransferHookInstruction,
  getMintSize,
  getMintToInstruction,
} from "@solana-program/token-2022";
import {
  applyPendingBalance,
  confidentialActivityToCsv,
  confidentialActivityToJson,
  configureAccount,
  decryptBalance,
  decryptTransferAmountAsAuditor,
  deposit,
  deriveAuditorElgamalKeypair,
  getAuditorElgamalPubkey,
  initConfidentialTransfers,
  isConfidentialTransfersError,
  listConfidentialActivity,
  recoverProofAccounts,
  transfer,
  withdraw,
} from "@softseco/arcantis";

import * as vigilantis from "./vigilantis.js";
import { createPollingSubscriptions } from "./polling.js";

// ---------------------------------------------------------------- setup

const DECIMALS = 6;
const UNIT = 10n ** BigInt(DECIMALS);
const CENT = UNIT / 100n;
const STORE = "softseco-playground-v2"; // the old playground on this origin used softseco-ct-playground-v1
const MIN_SOL = 100_000_000n; // a full run costs about 0.05 SOL; proof accounts hold more for a moment
const MINTED = 1000n * UNIT;
const LAST = 10;

const params = new URLSearchParams(location.search);
const customRpc = params.get("rpc");
// Any https endpoint, or a validator on this machine (http://127.0.0.1:8899) for local testing.
const RPC_URL =
  customRpc && (/^https:\/\//.test(customRpc) || /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\/?$/.test(customRpc))
    ? customRpc
    : "https://api.devnet.solana.com";
const LOCAL = /^http:\/\//.test(RPC_URL);

// The public endpoint answers 429 when it is busy; wait the way it asks instead of failing.
// Not for airdrops: there 429 means the faucet limit, and waiting does not help.
const realFetch = window.fetch.bind(window);
window.fetch = async (input, init) => {
  const airdrop = typeof init?.body === "string" && init.body.includes('"requestAirdrop"');
  for (let attempt = 0; ; attempt++) {
    const res = await realFetch(input, init);
    if (res.status !== 429 || airdrop || attempt >= 6) return res;
    const wait = (Number(res.headers.get("retry-after") ?? 2) + attempt) * 1000;
    await new Promise((r) => setTimeout(r, wait));
  }
};

const rpc = createSolanaRpc(RPC_URL);
const rpcSubscriptions = createPollingSubscriptions(rpc);
const sendAndConfirm = sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions });
const sdk = { rpc, rpcSubscriptions };

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const fmt = (units) => {
  const neg = units < 0n;
  const v = neg ? -units : units;
  return `${neg ? "-" : ""}${(v / UNIT).toLocaleString("en-US")}.${((v % UNIT) / CENT).toString().padStart(2, "0")}`;
};
const sol = (lam) => (Number(lam) / 1e9).toFixed(3);
const short = (a) => `${a.slice(0, 4)}…${a.slice(-4)}`;
const cluster = LOCAL ? `cluster=custom&customUrl=${encodeURIComponent(RPC_URL)}` : "cluster=devnet";
const txUrl = (s) => `https://explorer.solana.com/tx/${s}?${cluster}`;
const addrUrl = (a) => `https://explorer.solana.com/address/${a}?${cluster}`;
const esc = (t) => String(t).replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[ch]);
const link = (href, text) => `<a href="${esc(href)}" target="_blank" rel="noopener">${esc(text)}</a>`;
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const nap = (ms) => new Promise((r) => setTimeout(r, ms));
// An error meant for the visitor as written, not a chain failure.
const hint = (text) => Object.assign(new Error(text), { hint: true });

/** "12.5" -> 12_500_000n. Whole cents only, between 0.01 and 1,000,000. */
function parseAmount(text) {
  const m = /^\s*(\d{1,7})(?:\.(\d{1,2}))?\s*$/.exec(text);
  if (!m) throw hint("Enter an amount like 25 or 12.50.");
  const units = BigInt(m[1]) * UNIT + BigInt((m[2] ?? "").padEnd(2, "0")) * CENT;
  if (units <= 0n) throw hint("Enter an amount above zero.");
  return units;
}

// ---------------------------------------------------------------- state

function load() {
  try {
    const raw = localStorage.getItem(STORE);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function save() {
  try {
    localStorage.setItem(STORE, JSON.stringify(state));
  } catch {
    /* private mode: the run still works, it just will not survive a reload */
  }
}
const seed = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const fresh = (you = seed()) => ({
  seeds: { you, bob: seed(), auditor: seed(), mallory: seed() },
  // The issuer's private salt for case references (see vigilantis.caseRef).
  salt: seed(),
  done: 0,
  mint: null,
  step: {}, // per-step progress, so a retry resumes where it stopped
});
let state = load() ?? fresh();
let keys; // { you, bob, auditor, mallory }: kit signers
let auditorKeypair; // the ElGamal keypair derived from the auditor's wallet
let busy = false;

const progress = (n) => (state.step[n] ??= { stage: 0 });

async function signers() {
  const make = (h) => createKeyPairSignerFromPrivateKeyBytes(unhex(h));
  const [you, bob, auditor, mallory] = await Promise.all(
    [state.seeds.you, state.seeds.bob, state.seeds.auditor, state.seeds.mallory].map(make),
  );
  return { you, bob, auditor, mallory };
}

// ---------------------------------------------------------------- chain helpers

async function send(instructions) {
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send();
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(keys.you, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, m),
    (m) => appendTransactionMessageInstructions(instructions, m),
  );
  const signed = await signTransactionMessageWithSigners(message);
  assertIsTransactionWithBlockhashLifetime(signed);
  await sendAndConfirm(signed, { commitment: "confirmed" });
  return getSignatureFromTransaction(signed);
}

const mint = () => address(state.mint);
const ataOf = async (owner) =>
  (await findAssociatedTokenPda({ owner, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS, mint: mint() }))[0];

async function publicBalance(owner) {
  try {
    const { value } = await rpc.getTokenAccountBalance(await ataOf(owner), { commitment: "confirmed" }).send();
    return BigInt(value.amount);
  } catch {
    return 0n;
  }
}
const confidentialBalance = (owner) => decryptBalance({ rpc, owner, mint: mint() });

async function solBalance() {
  const { value } = await rpc.getBalance(keys.you.address, { commitment: "confirmed" }).send();
  return value;
}

/** The auditor's reading of a transfer: only the transfer transaction itself carries the ciphertext. */
async function auditorReads(signatures) {
  for (const signature of [...signatures].reverse()) {
    try {
      return await decryptTransferAmountAsAuditor({ rpc, signature, auditorKeypair, mint: mint() });
    } catch {
      /* a proof transaction: try the next one */
    }
  }
  return null;
}

// What refused a transaction: Vigilantis (its error code), or Token-2022 (a frozen account, a paused
// mint). Returns { by, name, message, log } or null for any other failure.
const TOKEN_REFUSALS = {
  17: { name: "AccountFrozen", message: "Account is frozen" },
  67: { name: "MintPaused", message: "Transferring, minting, and burning is paused on this mint" },
};
function refusal(err) {
  const logs = [];
  const texts = [];
  for (let e = err, depth = 0; e && depth < 8; e = e.cause, depth++) {
    if (Array.isArray(e.logs)) logs.push(...e.logs);
    if (Array.isArray(e.context?.logs)) logs.push(...e.context.logs);
    if (e.message) texts.push(e.message);
  }
  const all = [...logs, ...texts].join("\n");
  const anchor = /Error Code: (\w+)\. Error Number: (\d+)/.exec(all);
  if (anchor && all.includes(vigilantis.VIGILANTIS_PROGRAM_ADDRESS)) {
    const known = vigilantis.vigilantisError(Number(anchor[2]));
    const line = logs.find((l) => l.includes("Error Code:")) ?? "";
    return { by: "Vigilantis", name: anchor[1], message: known?.message ?? anchor[1], log: line.replace(/^\s*Program log:\s*/, "").trim() };
  }
  const failed = logs.find((l) => l.startsWith(`Program ${TOKEN_2022_PROGRAM_ADDRESS} failed: custom program error: 0x`));
  if (failed) {
    const code = parseInt(failed.split("0x")[1], 16);
    const known = TOKEN_REFUSALS[code];
    if (known) return { by: "Token-2022", ...known, log: failed.replace(/^Program \w+ /, "Token-2022 ") };
  }
  for (const [code, known] of Object.entries(TOKEN_REFUSALS)) {
    if (all.includes(known.message)) return { by: "Token-2022", ...known, log: `custom program error: 0x${Number(code).toString(16)}` };
  }
  // kit's browser build may give only the instruction's custom error code.
  for (let e = err, depth = 0; e && depth < 8; e = e.cause, depth++) {
    const known = TOKEN_REFUSALS[e.context?.code];
    if (known && e.context?.index === 0) return { by: "Token-2022", ...known, log: `custom program error: 0x${e.context.code.toString(16)}` };
  }
  return null;
}

/**
 * A public transfer that the chain should refuse. Arcantis would refuse a confidential payment
 * from a frozen account, or on a paused mint, before building its proofs; a public transfer shows
 * that Token-2022 itself refuses it.
 */
async function expectRefusedPublic(what, from, to, amount) {
  const ix = await vigilantis.transferChecked({
    mint: mint(),
    source: await ataOf(from.address),
    destination: await ataOf(to.address),
    authority: from,
    sourceOwner: from.address,
    destinationOwner: to.address,
    amount,
    decimals: DECIMALS,
  });
  try {
    await send([ix]);
  } catch (err) {
    const why = refusal(err);
    if (!why) throw err;
    return why;
  }
  throw hint(`${what} went through, which should not happen. Start over with new keys, and please open an issue on GitHub.`);
}

/**
 * A transfer that should be refused. Returns the refusal; throws if it went through or failed for
 * another reason. transfer() closes the proof accounts of a refused transfer itself; anything it
 * could not close is collected with recoverProofAccounts().
 */
async function expectRefused(n, what, input) {
  try {
    await transfer({ ...sdk, payer: keys.you, mint: mint(), auditorElgamalPubkey: getAuditorElgamalPubkey(auditorKeypair), ...input });
  } catch (err) {
    const why = refusal(err);
    if (!why) throw err;
    const leftOpen = isConfidentialTransfersError(err) ? err.proofAccounts?.leftOpen.length ?? 0 : 0;
    if (leftOpen > 0) {
      say(n, "Closing the proof accounts the refused payment left open…");
      await recoverProofAccounts({ ...sdk, authority: keys.you });
    }
    return why;
  }
  throw hint(`${what} went through, which should not happen. Start over with new keys, and please open an issue on GitHub.`);
}

// ---------------------------------------------------------------- the steps

const REASON_NAMES = Object.fromEntries(Object.entries(vigilantis.REASONS).map(([k, v]) => [v, k.replace(/[A-Z]/g, (c) => ` ${c.toLowerCase()}`)]));

async function enforcement(caseId, reason) {
  return { reasonCode: vigilantis.REASONS[reason], caseRef: await vigilantis.caseRef(caseId, state.salt) };
}

function refusedRow(who, why) {
  return `<div class="who stop"><b>${esc(who)}</b><span>refused by ${esc(why.by)}: <strong>${esc(why.name)}</strong> · ${esc(why.message)}</span>${why.log ? `<code class="log">${esc(why.log)}</code>` : ""}</div>`;
}
function caseRow(label, caseId, reason, signature) {
  return `<div class="kv"><span>${esc(label)}</span><b>${esc(REASON_NAMES[vigilantis.REASONS[reason]])}</b><em>case ${esc(caseId)}, stored as a salted hash</em>${link(txUrl(signature), "transaction")}</div>`;
}

const STEPS = {
  1: async () => {
    say(1, "Asking the faucet for 1 SOL…");
    try {
      await rpc.requestAirdrop(keys.you.address, lamports(1_000_000_000n)).send();
    } catch {
      throw new Error("faucet");
    }
    say(1, "Airdrop sent. Waiting for it to land…");
    for (let i = 0; i < 30; i++) {
      if ((await solBalance()) >= MIN_SOL) return;
      await nap(2000);
    }
    throw new Error("faucet");
  },

  2: async () => {
    const p = progress(2);
    if (p.stage < 1) {
      say(2, "Creating a Token-2022 mint: confidential transfers, an auditor, and Vigilantis as hook, freeze and pause authority…");
      const mintSigner = await generateKeyPairSigner();
      const auditorElgamalPubkey = getAuditorElgamalPubkey(auditorKeypair);
      const freezeAuthority = await vigilantis.pdas.freezeAuthority(mintSigner.address);
      const pauseAuthority = await vigilantis.pdas.pauseAuthority(mintSigner.address);
      const ct = { authority: some(keys.you.address), autoApproveNewAccounts: true, auditorElgamalPubkey: some(auditorElgamalPubkey) };
      const space = BigInt(getMintSize([
        extension("TransferHook", { authority: keys.you.address, programId: vigilantis.VIGILANTIS_PROGRAM_ADDRESS }),
        extension("ConfidentialTransferMint", ct),
        extension("PausableConfig", { authority: some(pauseAuthority), paused: false }),
      ]));
      const rent = await rpc.getMinimumBalanceForRentExemption(space).send();
      p.createdTx = await send([
        getCreateAccountInstruction({ payer: keys.you, newAccount: mintSigner, lamports: rent, space, programAddress: TOKEN_2022_PROGRAM_ADDRESS }),
        // extensions first, then the mint itself
        getInitializeTransferHookInstruction({ mint: mintSigner.address, authority: keys.you.address, programId: vigilantis.VIGILANTIS_PROGRAM_ADDRESS }),
        getInitializeConfidentialTransferMintInstruction({ mint: mintSigner.address, ...ct }),
        getInitializePausableConfigInstruction({ mint: mintSigner.address, authority: pauseAuthority }),
        getInitializeMint2Instruction({ mint: mintSigner.address, decimals: DECIMALS, mintAuthority: keys.you.address, freezeAuthority: some(freezeAuthority) }),
      ]);
      state.mint = mintSigner.address;
      p.stage = 1;
      save();
    }
    if (p.stage < 2) {
      say(2, "Vigilantis: registering the accounts the hook reads, and the token's policy…");
      p.policyTx = await send([
        await vigilantis.initializeExtraAccountMetaList({ payer: keys.you, mint: mint() }),
        await vigilantis.initializePolicy({
          authority: keys.you,
          mint: mint(),
          allowlist: false,
          blocklist: true,
          maxTransferAmount: 0n,
          allowConfidential: true,
        }),
      ]);
      p.stage = 2;
      save();
    }
    out(2, `
      <div class="kv"><span>Token</span>${link(addrUrl(state.mint), short(state.mint))}<em>Token-2022, 6 decimals</em>${link(txUrl(p.createdTx), "transaction")}</div>
      <div class="kv"><span>Amounts</span><b>encrypted</b><em>confidential transfers, auditor ${esc(short(keys.auditor.address))}</em></div>
      <div class="kv"><span>Rules</span><b>Vigilantis</b><em>transfer hook, freeze and pause authority; blocklist on</em>${link(txUrl(p.policyTx), "transaction")}</div>`);
  },

  3: async () => {
    const p = progress(3);
    const owners = [["your", keys.you], ["Bob's", keys.bob], ["Mallory's", keys.mallory]];
    for (const [i, [whose, owner]] of owners.entries()) {
      if (p.stage < 1 + i) {
        say(3, `Opening ${whose} token account for confidential transfers…`);
        await configureAccount({ ...sdk, payer: keys.you, owner, mint: mint() });
        p.stage = 1 + i;
        save();
      }
    }
    if (p.stage < 4) {
      say(3, "Minting 1,000 test dollars to you…");
      await send([getMintToInstruction({ mint: mint(), token: await ataOf(keys.you.address), mintAuthority: keys.you, amount: MINTED })]);
      p.stage = 4;
      save();
    }
    if (p.stage < 5) {
      say(3, "Depositing them into your confidential balance…");
      p.depositTx = (await deposit({ ...sdk, payer: keys.you, owner: keys.you, mint: mint(), amount: MINTED, decimals: DECIMALS })).signature;
      p.stage = 5;
      save();
    }
    if (p.stage < 6) {
      say(3, "Applying the pending balance, so it can be spent…");
      await applyPendingBalance({ ...sdk, payer: keys.you, owner: keys.you, mint: mint() });
      p.stage = 6;
      save();
    }
    const [pub, conf] = await Promise.all([publicBalance(keys.you.address), confidentialBalance(keys.you)]);
    out(3, `
      <div class="kv"><span>Accounts</span><b>3 opened</b><em>you, Bob and Mallory</em></div>
      <div class="kv"><span>Your public</span><b>${fmt(pub)}</b></div>
      <div class="kv"><span>Your confidential</span><b>${fmt(conf)}</b><em>decrypted with your key</em>${p.depositTx ? link(txUrl(p.depositTx), "deposit") : ""}</div>`);
  },

  4: async () => {
    const p = progress(4);
    if (p.stage < 1) {
      const amount = parseAmount($("#amount").value);
      const available = await confidentialBalance(keys.you);
      if (amount > available) throw hint(`You have ${fmt(available)} in your confidential balance.`);
      say(4, "Building the zero-knowledge proofs and sending the transfer. Vigilantis checks it on the way…");
      const { signatures } = await transfer({
        ...sdk,
        payer: keys.you,
        owner: keys.you,
        mint: mint(),
        destinationOwner: keys.bob.address,
        amount,
        auditorElgamalPubkey: getAuditorElgamalPubkey(auditorKeypair),
      });
      p.signatures = signatures.map(String);
      p.amount = amount.toString();
      p.stage = 1;
      save();
    }
    if (p.stage < 2) {
      say(4, "Bob applies his pending balance…");
      await applyPendingBalance({ ...sdk, payer: keys.you, owner: keys.bob, mint: mint() });
      p.stage = 2;
      save();
    }
    const n = p.signatures.length;
    out(4, n === 1
      ? `
      <div class="kv"><span>Transfer</span><b>one transaction</b><em>the three proofs travel inside it</em>${link(txUrl(p.signatures[0]), "transaction")}</div>
      <p class="note">Open it in the explorer: the sender, the recipient, the proofs and Vigilantis's check are all there. The amount is not.</p>`
      : `
      <p class="note">Open them in the explorer: the sender, the recipient, the proofs and Vigilantis's check are all there. The amount is not.</p>
      <ul class="links">${p.signatures.map((s, i) => `<li>${link(txUrl(s), i === n - 1 ? "the transfer" : `proof ${i + 1} of ${n - 1}`)}</li>`).join("")}</ul>`);
  },

  5: async () => {
    say(5, "Decrypting with each key…");
    const [mine, bobs, seen] = await Promise.all([
      confidentialBalance(keys.you),
      confidentialBalance(keys.bob),
      auditorReads(progress(4).signatures ?? []),
    ]);
    const last = progress(4).signatures?.at(-1) ?? "";
    out(5, `
      <div class="who ok"><b>You</b><span>your confidential balance: <strong>${fmt(mine)}</strong></span></div>
      <div class="who ok"><b>Bob</b><span>his confidential balance: <strong>${fmt(bobs)}</strong></span></div>
      <div class="who ok"><b>The auditor</b><span>the transfer was <strong>${seen === null ? "not found" : fmt(seen)}</strong></span></div>
      <div class="who no"><b>Everyone else</b><span>ciphertext only · ${link(txUrl(last), "see for yourself")}</span></div>`);
  },

  6: async () => {
    const p = progress(6);
    if (p.stage < 1) {
      const held = await confidentialBalance(keys.bob);
      if (held < 2n * CENT) throw hint("Bob's confidential balance is empty.");
      const amount = (held / 2n / CENT) * CENT; // half, in whole cents
      say(6, `Bob withdraws ${fmt(amount)} to his public balance: an equality proof and a range proof…`);
      const { signatures } = await withdraw({ ...sdk, payer: keys.you, owner: keys.bob, mint: mint(), amount, decimals: DECIMALS });
      p.tx = String(signatures.at(-1));
      p.amount = amount.toString();
      p.stage = 1;
      save();
    }
    const [pub, conf] = await Promise.all([publicBalance(keys.bob.address), confidentialBalance(keys.bob)]);
    out(6, `
      <div class="kv"><span>Bob public</span><b>${fmt(pub)}</b><em>visible to anyone</em></div>
      <div class="kv"><span>Bob confidential</span><b>${fmt(conf)}</b><em>still encrypted</em>${link(txUrl(p.tx), "withdraw")}</div>
      <p class="note done">That is Arcantis: configure, deposit, transfer, decrypt, withdraw. Next, the issuer's rules.</p>`);
  },

  7: async () => {
    const p = progress(7);
    const caseId = "DEMO-001";
    if (p.stage < 1) {
      say(7, "Vigilantis: blocking Mallory, reason sanctions, case DEMO-001…");
      p.tx = await send([
        await vigilantis.blockWallet({ authority: keys.you, mint: mint(), wallet: keys.mallory.address, ...(await enforcement(caseId, "sanctions")) }),
      ]);
      p.stage = 1;
      save();
    }
    if (p.stage < 2) {
      say(7, "Paying Mallory 50.00. The proofs go first, then Token-2022 asks Vigilantis…");
      p.refused = await expectRefused(7, "The payment to Mallory", { owner: keys.you, destinationOwner: keys.mallory.address, amount: 50n * UNIT });
      p.stage = 2;
      save();
    }
    out(7, `
      ${caseRow("Blocked", caseId, "sanctions", p.tx)}
      ${refusedRow("Pay Mallory", p.refused)}
      <p class="note">The amount was encrypted, and the rule still held: the hook checks who sends and who receives, not how much.</p>`);
  },

  8: async () => {
    const p = progress(8);
    const caseId = "DEMO-002";
    const bobToken = await ataOf(keys.bob.address);
    if (p.stage < 1) {
      say(8, "Vigilantis: freezing Bob's account, reason fraud, case DEMO-002…");
      p.freezeTx = await send([
        await vigilantis.freezeTokenAccount({ authority: keys.you, mint: mint(), tokenAccount: bobToken, ...(await enforcement(caseId, "fraud")) }),
      ]);
      p.stage = 1;
      save();
    }
    if (p.stage < 2) {
      say(8, "Bob tries to pay you 10.00 from his frozen account…");
      p.refused = await expectRefusedPublic("Bob's payment from a frozen account", keys.bob, keys.you, 10n * UNIT);
      p.stage = 2;
      save();
    }
    if (p.stage < 3) {
      say(8, "Case closed: thawing Bob's account…");
      p.thawTx = await send([
        await vigilantis.thawTokenAccount({ authority: keys.you, mint: mint(), tokenAccount: bobToken, ...(await enforcement(caseId, "caseClosed")) }),
      ]);
      p.stage = 3;
      save();
    }
    const account = await fetchToken(rpc, bobToken, { commitment: "confirmed" });
    out(8, `
      ${caseRow("Frozen", caseId, "fraud", p.freezeTx)}
      ${refusedRow("Bob pays you", p.refused)}
      ${caseRow("Thawed", caseId, "caseClosed", p.thawTx)}
      <div class="kv"><span>Bob's account</span><b>${account.data.state === 1 ? "active" : "frozen"}</b><em>his balance never moved</em></div>`);
  },

  9: async () => {
    const p = progress(9);
    const caseId = "DEMO-003";
    if (p.stage < 1) {
      say(9, "Vigilantis: pausing the whole token, reason internal review, case DEMO-003…");
      p.pauseTx = await send([await vigilantis.pause({ authority: keys.you, mint: mint(), ...(await enforcement(caseId, "internalReview")) })]);
      p.stage = 1;
      save();
    }
    if (p.stage < 2) {
      say(9, "Bob tries to pay you 10.00 while the token is paused…");
      p.refused = await expectRefusedPublic("A payment while the token is paused", keys.bob, keys.you, 10n * UNIT);
      p.stage = 2;
      save();
    }
    if (p.stage < 3) {
      say(9, "Review done: resuming transfers…");
      p.resumeTx = await send([await vigilantis.resume({ authority: keys.you, mint: mint(), ...(await enforcement(caseId, "caseClosed")) })]);
      p.stage = 3;
      save();
    }
    out(9, `
      ${caseRow("Paused", caseId, "internalReview", p.pauseTx)}
      ${refusedRow("Bob pays you", p.refused)}
      ${caseRow("Resumed", caseId, "caseClosed", p.resumeTx)}
      <p class="note done">That is Vigilantis: every action has a reason and a case on-chain, and none of them can move anyone's tokens.</p>`);
  },

  10: async () => {
    say(10, "Reading every transaction of the token and decrypting the amounts with the auditor's key…");
    const activity = await listConfidentialActivity({ rpc, mint: mint(), auditorKeypair, concurrency: LOCAL ? 4 : 2 });
    report = { activity, generatedAt: new Date() };
    const who = new Map([
      [keys.you.address, "You"],
      [keys.bob.address, "Bob"],
      [keys.mallory.address, "Mallory"],
    ]);
    const name = (owner) => (owner ? who.get(owner) ?? short(owner) : "—");
    const rows = activity
      .map((a) => `<tr><td>${a.blockTime ? esc(a.blockTime.toISOString().slice(11, 19)) : "—"}</td><td>${esc(a.kind)}</td><td>${esc(name(a.fromOwner))}</td><td>${esc(name(a.toOwner))}</td><td class="num">${a.amount === null ? "—" : fmt(a.amount)}</td><td>${link(txUrl(a.signature), "tx")}</td></tr>`)
      .join("");
    out(10, `
      <div class="table-wrap"><table class="report"><thead><tr><th>Time (UTC)</th><th>Kind</th><th>From</th><th>To</th><th class="num">Amount</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      <div class="controls"><button class="btn btn-ink" type="button" data-download="csv">Download CSV</button><button class="btn btn-line dark" type="button" data-download="json">Download JSON</button></div>
      <p class="note">Refused payments never happened, so they are not in the report. The files are the formats of <code>arcantis audit-report</code>.</p>`);
  },
};

let report = null;

function download(kind) {
  if (!report) return;
  const options = { mint: mint(), auditorElgamalPubkey: getAuditorElgamalPubkey(auditorKeypair), decimals: DECIMALS, generatedAt: report.generatedAt };
  const text = kind === "csv" ? confidentialActivityToCsv(report.activity, { decimals: DECIMALS }) : confidentialActivityToJson(report.activity, options);
  const blob = new Blob([text], { type: kind === "csv" ? "text/csv" : "application/json" });
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `auditor-report-${short(state.mint).replace("…", "-")}.${kind}` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ---------------------------------------------------------------- UI

function say(n, text, kind = "") {
  const el = $(`.step[data-step="${n}"] .status`);
  el.className = `status ${kind}`;
  el.textContent = text;
}
function out(n, html) {
  $(`.step[data-step="${n}"] .out`).innerHTML = html;
}

function paint() {
  for (const el of $$(".step")) {
    const n = Number(el.dataset.step);
    el.dataset.state = n <= state.done ? "done" : n === state.done + 1 ? "ready" : "locked";
    const button = $("button[data-run]", el);
    if (button) button.disabled = busy || !keys || n !== state.done + 1;
  }
  for (const id of ["#reset", "#restart", "#again"]) $(id).disabled = busy;
  $("#finale").hidden = state.done < LAST;
}

async function refreshSide() {
  if (!keys) return;
  for (const who of ["you", "bob", "auditor", "mallory"]) {
    const a = $(`#addr-${who}`);
    a.textContent = short(keys[who].address);
    a.href = addrUrl(keys[who].address);
  }
  try {
    $("#sol").textContent = sol(await solBalance());
  } catch {
    $("#sol").textContent = "—";
  }
  const token = $("#token");
  if (!state.mint || state.done < 2) {
    token.textContent = "not created yet";
    token.removeAttribute("href");
    return;
  }
  token.textContent = short(state.mint);
  token.href = addrUrl(state.mint);
  if (state.done < 3) return;
  const rows = [
    ["#you-pub", () => publicBalance(keys.you.address)],
    ["#you-conf", () => confidentialBalance(keys.you)],
    ["#bob-pub", () => publicBalance(keys.bob.address)],
    ["#bob-conf", () => confidentialBalance(keys.bob)],
  ];
  await Promise.all(rows.map(async ([sel, read]) => {
    try {
      $(sel).textContent = fmt(await read());
    } catch {
      $(sel).textContent = "—";
    }
  }));
}

// kit's browser build ships numeric error codes only; name the few a visitor can act on.
const NO_SOL = new Set([7050003, 7050005, 7050031, 4615006]); // account not found, fee, rent, insufficient funds
const EXPIRED = new Set([1, 7050008]); // block height exceeded, blockhash not found
const UNREACHABLE = new Set([8100002, -32005]); // HTTP error, node unhealthy
const NO_PROGRAM = new Set([7050004, 7050013]); // program account not found, not executable: Vigilantis not deployed

function explain(err) {
  const text = String(err?.message ?? err);
  if (err?.hint) return text;
  if (text === "faucet") {
    return "The faucet said no: it limits requests. Copy your address and get devnet SOL at faucet.solana.com, or send some from a devnet wallet. This step completes by itself when it arrives.";
  }
  if (isConfidentialTransfersError(err, "TRANSACTION_EXPIRED")) return "Devnet was slow and the transaction expired. Press the button again.";
  const codes = [];
  const logs = [];
  for (let e = err, depth = 0; e && depth < 8; e = e.cause, depth++) {
    if (e.context?.__code !== undefined) codes.push(Number(e.context.__code));
    if (Array.isArray(e.context?.logs)) logs.push(...e.context.logs);
    if (Array.isArray(e.logs)) logs.push(...e.logs);
    if (e.message) logs.push(e.message);
  }
  const all = [text, ...logs].join("\n");
  if (codes.some((c) => NO_PROGRAM.has(c)) || /Program 4DoDFZJmJWYuBx86UqXi3y24GkQ3Cq4nUBHZwDE5PQM5 is not deployed|ProgramAccountNotFound|InvalidProgramForExecution|program that does not exist/.test(all)) {
    return "Vigilantis is not deployed on this cluster yet. Try again later.";
  }
  if (codes.some((c) => NO_SOL.has(c)) || /insufficient (funds|lamports)|InsufficientFunds/i.test(all)) {
    return "Not enough devnet SOL for this step. Top up your address and press the button again.";
  }
  if (codes.some((c) => EXPIRED.has(c))) return "Devnet was slow and the transaction expired. Press the button again.";
  if (codes.some((c) => UNREACHABLE.has(c)) || /Failed to fetch|NetworkError|network/i.test(all)) {
    return "Devnet did not answer. Wait a moment and press the button again.";
  }
  const line = text.split("\n--- program logs ---")[0];
  const code = codes[0] !== undefined ? ` (Solana error ${codes[0]})` : "";
  return `${/^Solana error/.test(line) ? "Devnet rejected the transaction" : line.slice(0, 240)}${code}. Press the button again; if it keeps failing, start over with new keys.`;
}

async function run(n) {
  if (busy) return;
  busy = true;
  paint();
  try {
    await STEPS[n]();
    state.done = Math.max(state.done, n);
    save();
    say(n, "Done.", "ok");
  } catch (err) {
    console.error(err);
    say(n, explain(err), "err");
  } finally {
    busy = false;
    paint();
    refreshSide();
  }
}

// Step 1 also completes by itself when SOL arrives from somewhere else (the faucet site, a wallet).
async function watchFunding() {
  while (state.done < 1) {
    try {
      const balance = await solBalance();
      $("#sol").textContent = sol(balance);
      if (balance >= MIN_SOL && !busy) {
        state.done = 1;
        save();
        say(1, "Funded.", "ok");
        paint();
        return;
      }
    } catch {
      /* try again on the next tick */
    }
    await nap(5000);
  }
}

function reloadAtTop() {
  history.scrollRestoration = "manual";
  window.scrollTo(0, 0);
  location.reload();
}

// Run the steps again with the same funded wallet: a new token, Bob, Mallory and auditor.
function resetSimulation() {
  if (busy) return;
  state = { ...fresh(state.seeds.you), done: Math.min(state.done, 1) };
  save();
  reloadAtTop();
}

// Throw every key away, including the funded wallet.
function restart() {
  if (busy) return;
  state = fresh();
  save();
  reloadAtTop();
}

function banner(text) {
  const el = $("#ready");
  el.hidden = false;
  el.classList.add("err");
  el.textContent = text;
}

async function main() {
  $("#rpc").textContent = new URL(RPC_URL).host;
  $("#hook-version").textContent = vigilantis.VIGILANTIS_VERSION;
  $$("button[data-run]").forEach((b) => b.addEventListener("click", () => run(Number(b.dataset.run))));
  $("#reset").addEventListener("click", resetSimulation);
  $("#again").addEventListener("click", resetSimulation);
  $("#restart").addEventListener("click", restart);
  document.addEventListener("click", (e) => {
    const kind = e.target.closest?.("[data-download]")?.dataset.download;
    if (kind) download(kind);
  });
  $("#copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(keys.you.address);
      $("#copy").textContent = "Copied";
      setTimeout(() => ($("#copy").textContent = "Copy address"), 1500);
    } catch {
      /* clipboard blocked: the address is still on screen */
    }
  });
  paint();

  try {
    await generateKeyPairSigner();
  } catch {
    banner("This browser cannot make Ed25519 keys (WebCrypto). Use a recent Chrome, Edge, Firefox or Safari.");
    return;
  }
  try {
    await initConfidentialTransfers({ wasmUrl: new URL("./zk_sdk_bg.wasm", import.meta.url) });
  } catch (err) {
    console.error(err);
    banner("The zero-knowledge module did not load. Reload the page.");
    return;
  }
  keys = await signers();
  auditorKeypair = await deriveAuditorElgamalKeypair(keys.auditor);
  $("#ready").hidden = true;
  if (state.done >= 1) say(1, "Funded.", "ok");
  for (let n = 2; n <= state.done; n++) say(n, "Done.", "ok");
  paint();
  refreshSide();
  watchFunding();
}

main();
