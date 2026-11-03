// SPDX-License-Identifier: BUSL-1.1
//
// Browser flavour of ./zk.ts, swapped in by the browser build (tsup.config.ts). The web build of
// @solana/zk-sdk needs one async init() that fetches its WebAssembly; every SDK function awaits
// `ensureZk()` first, so applications do not have to.
import initWasm from "@solana/zk-sdk/web";

import { ConfidentialTransfersError } from "../errors";

export * from "@solana/zk-sdk/web";

export type InitConfidentialTransfersOptions = {
  wasmUrl?: string | URL;
};

type WasmUrl = string | URL | undefined;

/** The URL given to initConfidentialTransfers, used by every later load. */
let wasmUrl: WasmUrl;
/** The load in progress, and the URL it loads from. Cleared when it fails, so it can be tried again. */
let loading: { url: WasmUrl; promise: Promise<void> } | undefined;
let loaded = false;

const sameUrl = (a: WasmUrl, b: WasmUrl) => (a === undefined ? undefined : String(a)) === (b === undefined ? undefined : String(b));

function load(url: WasmUrl): { url: WasmUrl; promise: Promise<void> } {
  const attempt = {
    url,
    promise: initWasm(url ? { module_or_path: url } : undefined).then(
      () => {
        loaded = true;
      },
      (error: unknown) => {
        if (loading === attempt) loading = undefined;
        throw new ConfidentialTransfersError(
          "CRYPTO_UNAVAILABLE",
          "@softseco/arcantis could not load the zk-sdk WebAssembly (index_bg.wasm from " +
            "@solana/zk-sdk/dist/web). With Vite's dev server, add " +
            '`optimizeDeps: { exclude: ["@solana/zk-sdk"] }` to vite.config, and if the request for the ' +
            ".wasm file is refused (403), add its node_modules folder to `server.fs.allow`. Or serve the " +
            "file yourself and pass its URL: `initConfidentialTransfers({ wasmUrl })`. Cause: " +
            String(error),
        );
      },
    ),
  };
  loading = attempt;
  return attempt;
}

/** Remembers `wasmUrl` for every later load, then loads (or waits for the load in progress). */
export function initConfidentialTransfers(options?: InitConfidentialTransfersOptions): Promise<void> {
  if (options?.wasmUrl !== undefined) wasmUrl = options.wasmUrl;
  return ensureZk();
}

/**
 * Loads the WebAssembly from the remembered URL (the zk-sdk's default without one), or waits for
 * the load in progress; only one runs at a time. A load that failed is tried again on the next
 * call, and one that failed from another URL than the one remembered since (a default load
 * started before `initConfidentialTransfers({ wasmUrl })`) is tried again at once from it.
 */
export async function ensureZk(): Promise<void> {
  while (!loaded) {
    const attempt = loading ?? load(wasmUrl);
    try {
      await attempt.promise;
    } catch (error) {
      if (sameUrl(attempt.url, wasmUrl)) throw error;
    }
  }
}

export function assertZkReady(what: string): void {
  if (!loaded) {
    throw new ConfidentialTransfersError(
      "CRYPTO_UNAVAILABLE",
      `${what} needs the zk-sdk WebAssembly, which is not loaded yet. ` +
        "Call `await initConfidentialTransfers()` once before using it in a browser.",
    );
  }
}
