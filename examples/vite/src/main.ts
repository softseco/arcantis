// A small web app on top of @softseco/arcantis: connect a wallet, unlock the
// confidential balance once, then deposit, apply, send and withdraw.
//
// The pattern to copy: derive the keys once with deriveConfidentialKeys({ signer }) (one wallet
// prompt to sign a message), keep them in memory, and pass them as `keys` to every SDK call.
import {
  applyPendingBalance,
  configureAccount,
  decryptBalance,
  deposit,
  deriveConfidentialKeys,
  initConfidentialTransfers,
  transfer,
  withdraw,
  type ConfidentialKeypairs,
} from "@softseco/arcantis";
import {
  TOKEN_2022_PROGRAM_ADDRESS,
  fetchMaybeToken,
  fetchMint,
  findAssociatedTokenPda,
} from "@solana-program/token-2022";
import {
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  isAddress,
  isMessageSigner,
  isSome,
  type Address,
} from "@solana/kit";
import type { IdentifierString } from "@wallet-standard/base";

import { connectWallet, signsV1Transactions, watchWallets, type WalletSigner } from "./wallet";

const RPC_URL: string = import.meta.env.VITE_RPC_URL ?? "https://api.devnet.solana.com";
const WS_URL: string = import.meta.env.VITE_WS_URL ?? websocketUrlFor(RPC_URL);
const CHAIN = (import.meta.env.VITE_CHAIN ?? "solana:devnet") as IdentifierString;

const rpc = createSolanaRpc(RPC_URL);
const rpcSubscriptions = createSolanaRpcSubscriptions(WS_URL);

// Start loading the cryptography (the zk-sdk WebAssembly) right away. Every SDK function would also
// do it on first use, so this only makes the first step faster.
void initConfidentialTransfers().catch((e) => setStatus("error", String(e)));

let signer: WalletSigner | undefined;
// One transaction per transfer or withdrawal needs a wallet that signs v1 transactions.
let singleTransaction = true;
// The keys belong to the wallet, not to a mint: one set works for every mint.
let keys: ConfidentialKeypairs | undefined;
let mintDecimals: { mint: Address; decimals: number } | undefined;

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const input = (id: string) => $<HTMLInputElement>(id).value.trim();

$("network").textContent = `${CHAIN} (${new URL(RPC_URL).host})`;
$<HTMLInputElement>("mint").value = import.meta.env.VITE_MINT ?? "";

watchWallets(CHAIN, (wallets) => {
  const box = $("wallets");
  box.replaceChildren();
  if (wallets.length === 0) {
    box.innerHTML = `<span class="note">No wallet found for ${CHAIN}. Install one (Phantom, Solflare, Backpack…) and reload.</span>`;
    return;
  }
  for (const { wallet, canSignMessages } of wallets) {
    const button = document.createElement("button");
    button.className = "ghost";
    button.dataset.wallet = wallet.name;
    button.textContent = canSignMessages ? `Connect ${wallet.name}` : `${wallet.name} (cannot sign messages)`;
    button.onclick = () =>
      run(`Connecting ${wallet.name}`, async () => {
        signer = await connectWallet(wallet, CHAIN);
        singleTransaction = signsV1Transactions(wallet);
        keys = undefined;
        $("address").textContent = signer.address;
        return `Connected ${signer.address}`;
      });
    box.append(button);
  }
});

$("unlock").onclick = () =>
  run("Unlocking: approve the message in your wallet", async () => {
    const owner = requireSigner();
    await currentMint();
    if (!isMessageSigner(owner)) {
      throw new Error("This wallet cannot sign messages, which the confidential keys come from. Try another wallet.");
    }
    keys = await deriveConfidentialKeys({ signer: owner });
    await refresh();
    return "Unlocked. The keys stay in this tab and are reused for every step.";
  });

$("setup").onclick = () =>
  run("Setting up your token account", async () => {
    const { mint } = await currentMint();
    const { signature } = await configureAccount({ rpc, rpcSubscriptions, payer: requireSigner(), owner: requireSigner(), mint, keys: requireKeys() });
    log(`configure ${signature}`);
    await refresh();
    return "Token account ready for confidential transfers.";
  });

$("refresh").onclick = () => run("Reading balances", async () => (await refresh(), "Balances updated."));

$("apply").onclick = () =>
  run("Applying incoming amounts", async () => {
    const { mint } = await currentMint();
    const { signature } = await applyPendingBalance({ rpc, rpcSubscriptions, payer: requireSigner(), owner: requireSigner(), mint, keys: requireKeys() });
    log(`apply ${signature}`);
    await refresh();
    return "Incoming amounts added to the confidential balance.";
  });

$("deposit").onclick = () =>
  run("Depositing", async () => {
    const { mint, decimals } = await currentMint();
    const amount = toBaseUnits(input("deposit-amount"), decimals);
    const { signature } = await deposit({ rpc, rpcSubscriptions, payer: requireSigner(), owner: requireSigner(), mint, amount, decimals });
    log(`deposit ${signature}`);
    await refresh();
    return "Deposited. Apply it to make it spendable.";
  });

$("transfer").onclick = () =>
  run("Sending: approve the transaction in your wallet", async () => {
    const to = input("to");
    if (!isAddress(to)) throw new Error("Enter the recipient's wallet address.");
    const { mint, decimals } = await currentMint();
    const amount = toBaseUnits(input("transfer-amount"), decimals);
    const [recipientToken] = await findAssociatedTokenPda({ owner: to, mint, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS });
    if (!(await fetchMaybeToken(rpc, recipientToken)).exists) {
      throw new Error("The recipient has no token account for this mint yet. They need to set one up first.");
    }
    const { signatures } = await transfer({
      rpc, rpcSubscriptions, payer: requireSigner(), owner: requireSigner(), mint,
      destinationOwner: to, amount, keys: requireKeys(), singleTransaction,
    });
    signatures.forEach((s) => log(`transfer ${s}`));
    await refresh();
    return `Sent in ${signatures.length === 1 ? "one transaction" : `${signatures.length} transactions`}. The amount is encrypted on chain.`;
  });

$("withdraw").onclick = () =>
  run("Withdrawing: approve the transaction in your wallet", async () => {
    const { mint, decimals } = await currentMint();
    const amount = toBaseUnits(input("withdraw-amount"), decimals);
    const { signatures } = await withdraw({ rpc, rpcSubscriptions, payer: requireSigner(), owner: requireSigner(), mint, amount, decimals, keys: requireKeys(), singleTransaction });
    signatures.forEach((s) => log(`withdraw ${s}`));
    await refresh();
    return "Withdrawn to the public balance.";
  });

async function refresh(): Promise<void> {
  const owner = requireSigner();
  const { mint, decimals } = await currentMint();
  const [token] = await findAssociatedTokenPda({ owner: owner.address, mint, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS });
  const account = await fetchMaybeToken(rpc, token);
  const show = (id: string, text: string) => ($(id).textContent = text);
  if (!account.exists) {
    show("public-balance", "no token account yet");
    show("confidential-balance", "—");
    show("pending", "—");
    return;
  }
  show("public-balance", fromBaseUnits(account.data.amount, decimals));
  const ct = isSome(account.data.extensions)
    ? account.data.extensions.value.find((e) => e.__kind === "ConfidentialTransferAccount")
    : undefined;
  if (!ct) {
    show("confidential-balance", "not set up");
    show("pending", "—");
    return;
  }
  show("confidential-balance", keys ? fromBaseUnits(await decryptBalance({ rpc, owner, mint, token, keys }), decimals) : "locked");
  const credits = ct.pendingBalanceCreditCounter;
  show("pending", credits === 0n ? "nothing" : `${credits} incoming (apply to spend)`);
}

// --- helpers ---------------------------------------------------------------------------------

function requireSigner(): WalletSigner {
  if (!signer) throw new Error("Connect a wallet first.");
  return signer;
}

function requireKeys(): ConfidentialKeypairs {
  if (!keys) throw new Error("Unlock the confidential balance first.");
  return keys;
}

/** The mint in the input box and its decimals (read once per mint). */
async function currentMint(): Promise<{ mint: Address; decimals: number }> {
  const value = input("mint");
  if (!isAddress(value)) throw new Error("Enter the mint address.");
  if (mintDecimals?.mint !== value) {
    mintDecimals = { mint: value, decimals: (await fetchMint(rpc, value)).data.decimals };
  }
  return mintDecimals;
}

function toBaseUnits(text: string, decimals: number): bigint {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (!match || (match[2]?.length ?? 0) > decimals) throw new Error(`Enter an amount with at most ${decimals} decimals.`);
  const amount = BigInt(match[1] + (match[2] ?? "").padEnd(decimals, "0"));
  if (amount === 0n) throw new Error("Enter an amount above zero.");
  return amount;
}

function fromBaseUnits(amount: bigint, decimals: number): string {
  if (decimals === 0) return amount.toString();
  const s = amount.toString().padStart(decimals + 1, "0");
  return `${s.slice(0, -decimals)}.${s.slice(-decimals)}`;
}

function websocketUrlFor(httpUrl: string): string {
  const url = new URL(httpUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  if (url.port === "8899") url.port = "8900"; // solana-test-validator
  return url.toString();
}

function setStatus(state: "busy" | "done" | "error", text: string): void {
  const status = $("status");
  status.dataset.state = state;
  status.textContent = text;
}

function log(line: string): void {
  const li = document.createElement("li");
  li.textContent = line;
  $("log").prepend(li);
}

let busy = false;
async function run(label: string, action: () => Promise<string>): Promise<void> {
  if (busy) return;
  busy = true;
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  setStatus("busy", `${label}…`);
  try {
    setStatus("done", await action());
  } catch (e) {
    setStatus("error", e instanceof Error ? e.message : String(e));
    console.error(e);
  } finally {
    busy = false;
    document.querySelectorAll<HTMLButtonElement>("#wallets button").forEach((b) => (b.disabled = false));
    $<HTMLButtonElement>("unlock").disabled = !signer;
    for (const id of ["setup", "refresh", "apply", "deposit", "transfer", "withdraw"]) {
      $<HTMLButtonElement>(id).disabled = !keys;
    }
  }
}
