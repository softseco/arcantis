// SPDX-License-Identifier: BUSL-1.1
//
// The browser build's loader of the zk-sdk WebAssembly (src/internal/zk.web.ts), run in Node. Its
// default load fails here (Node cannot fetch the file next to the module), which is what a
// browser app sees when its bundler did not serve the file: an app then passes `wasmUrl`. The
// WebAssembly is passed as data: URLs. The browser test (npm run test:browser) loads it for real.
import { readFileSync } from "node:fs";
import path from "node:path";

import { expect } from "chai";

import { isConfidentialTransfersError } from "../src/errors";
import * as zk from "../src/internal/zk.web";

const wasmUrl = (bytes: Uint8Array) => `data:application/wasm;base64,${Buffer.from(bytes).toString("base64")}`;

describe("browser build: loading the WebAssembly", function () {
  this.timeout(60000);

  it("remembers wasmUrl, and a failed load does not stand in the way of a later one", async () => {
    const good = wasmUrl(readFileSync(path.join(path.dirname(require.resolve("@solana/zk-sdk/web")), "index_bg.wasm")));
    const broken = wasmUrl(new TextEncoder().encode("not WebAssembly"));
    const failure = (promise: Promise<void>) => promise.then(() => undefined, (e: unknown) => e);

    // An SDK call starts the default load, and the app passes its own URL while that is under way.
    // The default load fails; the app's call is not handed that failure but tries its own URL.
    const [defaultLoad, appLoad] = await Promise.all([failure(zk.ensureZk()), failure(zk.initConfidentialTransfers({ wasmUrl: broken }))]);
    for (const error of [defaultLoad, appLoad]) {
      expect(isConfidentialTransfersError(error, "CRYPTO_UNAVAILABLE")).to.equal(true);
      expect(String((error as Error).message)).to.contain("CompileError"); // from the URL passed, not the default
    }

    // Later SDK calls use the URL passed, not the default, and try again after a failure.
    expect(String(((await failure(zk.ensureZk())) as Error).message)).to.contain("CompileError");

    await zk.initConfidentialTransfers({ wasmUrl: good });
    await zk.ensureZk();
    expect(() => zk.assertZkReady("test")).not.to.throw();
    expect(new zk.ElGamalKeypair().pubkey().toBytes()).to.have.length(32);
  });
});
