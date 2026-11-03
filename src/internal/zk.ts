// SPDX-License-Identifier: BUSL-1.1
//
// The one module that imports @solana/zk-sdk.
//
// This is the Node flavour: @solana/zk-sdk/node reads its WASM from disk when it is first
// imported, so there is nothing to initialize. The browser build of this package (see
// tsup.config.ts) swaps this file for zk.web.ts, which uses the web flavour and fetches the WASM
// on first use. Everything else in the SDK imports the zk-sdk classes from here and calls
// `ensureZk()` before touching them, so the same source runs in both places.
export * from "@solana/zk-sdk/node";

/** Options for {@link initConfidentialTransfers}. Only the browser build uses them. */
export type InitConfidentialTransfersOptions = {
  /**
   * Where to load the zk-sdk WebAssembly from in a browser. By default it is fetched next to the
   * zk-sdk module itself, which bundlers handle; pass a URL to serve it from elsewhere.
   */
  wasmUrl?: string | URL;
};

/**
 * Load the cryptography (the zk-sdk WebAssembly). In Node this does nothing. In a browser every
 * SDK function calls it on first use, so calling it yourself is optional: do it early to start the
 * download sooner, or to pass `wasmUrl`. Safe to call more than once.
 */
export async function initConfidentialTransfers(
  _options?: InitConfidentialTransfersOptions,
): Promise<void> {}

/** Resolves once the zk-sdk can be used. */
export async function ensureZk(): Promise<void> {}

/** Throws if a synchronous zk-sdk call would fail because the WebAssembly is not loaded yet. */
export function assertZkReady(_what: string): void {}
