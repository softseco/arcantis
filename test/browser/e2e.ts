// SPDX-License-Identifier: BUSL-1.1
//
// Browser test: the Vite example app in Chromium, with a Wallet Standard test wallet, against a
// local validator. It goes through what a user of a web app does (connect, unlock, set up,
// deposit, apply, send, withdraw) and checks the balances, then checks that Bob, set up from
// Node, received the amount. It also opens the app on Vite's dev server, where loading the
// WebAssembly is easiest to break, and unlocks there.
//
// Needs: a validator from `npm run validator` with TOKEN_2022_SO=test/fixtures/spl_token_2022.so,
// `npm run build`, and examples/vite built for the local validator:
//   (cd examples/vite && npm ci && VITE_RPC_URL=http://127.0.0.1:8899 VITE_CHAIN=solana:localnet npx vite build)
// Then: npm run test:browser   (CHROMIUM_PATH=/path/to/chrome to use a browser you already have)
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import path from "node:path";

import { ed25519 } from "@noble/curves/ed25519";
import { TOKEN_2022_PROGRAM_ADDRESS, findAssociatedTokenPda } from "@solana-program/token-2022";
import { airdropFactory, getBase58Decoder, lamports, type Address } from "@solana/kit";
import { build } from "esbuild";
import { chromium, type Browser, type Page } from "playwright-core";

import { applyPendingBalance, configureAccount, decryptBalance } from "../../src/index";
import { createConfidentialMint, fundedSigner, mintPublicTokens, rpc, rpcSubscriptions } from "../_helpers";

const ROOT = path.resolve(__dirname, "../..");
const EXAMPLE = path.join(ROOT, "examples/vite");
const ARTIFACTS = path.join(__dirname, "artifacts");
const STEP_TIMEOUT = 180_000;

type WalletStats = { signMessage: number; signTransaction: number; transactions: number };

async function main(): Promise<void> {
  const version = (await rpc.getVersion().send())["solana-core"];
  if (Number(version.split(".")[0]) < 4) {
    throw new Error(`the local validator is ${version}; confidential transfers need Agave 4.x`);
  }
  console.log(`validator ${version}`);

  // Chain setup from Node: a mint with confidential transfers, Bob ready to receive, and the test
  // wallet's key with some SOL for fees.
  const payer = await fundedSigner(10n);
  const { mint, mintAuthority } = await createConfidentialMint(payer, 2);
  const bob = await fundedSigner();
  await configureAccount({ rpc, rpcSubscriptions, payer, owner: bob, mint });
  const aliceSecret = new Uint8Array(randomBytes(32));
  const alice = getBase58Decoder().decode(ed25519.getPublicKey(aliceSecret)) as Address;
  await airdropFactory({ rpc, rpcSubscriptions })({
    recipientAddress: alice,
    lamports: lamports(5_000_000_000n),
    commitment: "confirmed",
  });
  const [aliceToken] = await findAssociatedTokenPda({ owner: alice, mint, tokenProgram: TOKEN_2022_PROGRAM_ADDRESS });
  console.log(`mint ${mint}\nalice (browser wallet) ${alice}\nbob ${bob.address}`);

  const walletScript = (
    await build({
      entryPoints: [path.join(__dirname, "test-wallet.ts")],
      bundle: true,
      format: "iife",
      platform: "browser",
      target: "es2022",
      write: false,
    })
  ).outputFiles[0].text;

  const server = await serveStatic(path.join(EXAMPLE, "dist"));
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined });
  let dev: ChildProcess | undefined;
  let page: Page | undefined;
  try {
    // 1. The production build.
    page = await openApp(browser, `http://127.0.0.1:${(server.address() as { port: number }).port}/`, aliceSecret, walletScript);
    await page.fill("#mint", mint);
    await act(page, '[data-wallet="Test wallet"]', "connect");
    await act(page, "#unlock", "unlock");
    await act(page, "#setup", "set up the token account");
    await mintPublicTokens({ payer, mint, token: aliceToken, mintAuthority, amount: 1000n });
    await page.fill("#deposit-amount", "10");
    await act(page, "#deposit", "deposit 10.00");
    await act(page, "#apply", "apply");
    await expectText(page, "#confidential-balance", "10.00");
    await expectText(page, "#public-balance", "0.00");
    await page.fill("#to", bob.address);
    await page.fill("#transfer-amount", "3");
    await act(page, "#transfer", "send 3.00 to Bob");
    await page.fill("#withdraw-amount", "2");
    await act(page, "#withdraw", "withdraw 2.00");
    await expectText(page, "#confidential-balance", "5.00");
    await expectText(page, "#public-balance", "2.00");

    const stats = (await page.evaluate(() => window.__testWallet)) as WalletStats;
    console.log(
      `wallet: ${stats.signMessage} message signature(s), ${stats.signTransaction} approval(s) for ${stats.transactions} transaction(s)`,
    );
    if (stats.signMessage !== 1) {
      throw new Error(`the wallet was asked to sign the key message ${stats.signMessage} times; expected once`);
    }
    // One approval per operation: set up, deposit, apply, transfer, withdraw. The test wallet signs
    // v1 transactions, so the transfer and the withdrawal are one transaction each.
    if (stats.signTransaction !== 5) {
      throw new Error(`the wallet was asked to approve transactions ${stats.signTransaction} times; expected 5, one per operation`);
    }
    if (stats.transactions !== 5) {
      throw new Error(`the wallet signed ${stats.transactions} transactions; expected 5, one per operation`);
    }
    await page.close();

    await applyPendingBalance({ rpc, rpcSubscriptions, payer, owner: bob, mint });
    const bobBalance = await decryptBalance({ rpc, owner: bob, mint });
    if (bobBalance !== 300n) throw new Error(`Bob has ${bobBalance} base units; expected 300`);
    console.log("ok   Bob received 3.00");

    // 2. Vite's dev server (needs `optimizeDeps.exclude: ["@solana/zk-sdk"]`).
    const devPort = 5174;
    dev = spawn(process.execPath, [path.join(EXAMPLE, "node_modules/vite/bin/vite.js"), "--port", String(devPort), "--strictPort", "--host", "127.0.0.1"], {
      cwd: EXAMPLE,
      env: { ...process.env, VITE_RPC_URL: "http://127.0.0.1:8899", VITE_CHAIN: "solana:localnet" },
      stdio: "ignore",
    });
    await waitForHttp(`http://127.0.0.1:${devPort}/`);
    page = await openApp(browser, `http://127.0.0.1:${devPort}/`, aliceSecret, walletScript);
    await page.fill("#mint", mint);
    await act(page, '[data-wallet="Test wallet"]', "connect (dev server)");
    await act(page, "#unlock", "unlock (dev server)");
    await expectText(page, "#confidential-balance", "5.00");
    console.log("\nbrowser test passed");
  } catch (e) {
    if (page && !page.isClosed()) {
      await mkdir(ARTIFACTS, { recursive: true });
      await page.screenshot({ path: path.join(ARTIFACTS, "failure.png"), fullPage: true });
      console.error(`screenshot: ${path.relative(ROOT, path.join(ARTIFACTS, "failure.png"))}`);
    }
    throw e;
  } finally {
    dev?.kill();
    await browser.close();
    server.close();
  }
}

async function openApp(browser: Browser, url: string, secret: Uint8Array, walletScript: string): Promise<Page> {
  const page = await browser.newPage();
  page.on("pageerror", (e) => console.error(`  [page error] ${e.message}`));
  page.on("console", (m) => m.type() === "error" && console.error(`  [console] ${m.text()}`));
  await page.addInitScript(`window.__testWalletSecret = ${JSON.stringify(Array.from(secret))};`);
  await page.addInitScript(walletScript);
  await page.goto(url);
  await page.waitForSelector('[data-wallet="Test wallet"]');
  return page;
}

/** Click a button and wait until the app reports the action done (or failed). */
async function act(page: Page, selector: string, label: string): Promise<void> {
  const started = Date.now();
  await page.evaluate(() => (document.getElementById("status")!.dataset.state = "waiting"));
  await page.click(selector);
  await page.waitForFunction(
    () => ["done", "error"].includes(document.getElementById("status")!.dataset.state ?? ""),
    undefined,
    { timeout: STEP_TIMEOUT },
  );
  const state = await page.getAttribute("#status", "data-state");
  const text = await page.textContent("#status");
  if (state !== "done") throw new Error(`${label}: ${text}`);
  console.log(`ok   ${label} (${((Date.now() - started) / 1000).toFixed(1)} s)`);
}

async function expectText(page: Page, selector: string, expected: string): Promise<void> {
  const actual = (await page.textContent(selector))?.trim();
  if (actual !== expected) throw new Error(`${selector} shows ${actual}; expected ${expected}`);
}

const TYPES: Record<string, string> = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".wasm": "application/wasm",
  ".svg": "image/svg+xml",
};

/** Serves a folder on 127.0.0.1 (a free port). */
function serveStatic(dir: string): Promise<Server> {
  const server = createServer(async (req, res) => {
    const urlPath = decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname);
    const file = path.join(dir, urlPath.endsWith("/") ? `${urlPath}index.html` : urlPath);
    if (!file.startsWith(dir)) return void res.writeHead(403).end();
    try {
      const body = await readFile(file);
      res.writeHead(200, { "content-type": TYPES[path.extname(file)] ?? "application/octet-stream" }).end(body);
    } catch {
      res.writeHead(404).end();
    }
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

async function waitForHttp(url: string): Promise<void> {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(url)).ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${url} did not come up`);
}

main().then(
  () => process.exit(0),
  (e) => {
    console.error(`\nbrowser test FAILED: ${e instanceof Error ? e.message : e}`);
    process.exit(1);
  },
);
