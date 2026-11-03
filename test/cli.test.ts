// SPDX-License-Identifier: BUSL-1.1
//
// The `arcantis audit-report` command's input: times read as UTC, whole numbers checked before the
// RPC is asked anything, and a keypair file that is never quoted in an error. No validator needed
// (the report itself is tested in auditorReport.test.ts).
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { ed25519 } from "@noble/curves/ed25519";
import { expect } from "chai";

import { keypairFromFile, parsePositiveInteger, parseUtcTime } from "../src/internal/cliInput";

const NOT_A_KEYPAIR = "not a JSON keypair file (expected an array of 64 numbers)";

/** Run the command; resolves with its exit code and standard error. */
async function arcantis(...args: string[]): Promise<{ code: number; stderr: string }> {
  const tsx = path.resolve(__dirname, "../node_modules/.bin/tsx");
  try {
    const { stderr } = await promisify(execFile)(tsx, [path.resolve(__dirname, "../src/cli.ts"), ...args]);
    return { code: 0, stderr };
  } catch (e) {
    const failed = e as { code: number; stderr: string };
    return { code: failed.code, stderr: failed.stderr };
  }
}

const thrown = (run: () => unknown) => {
  try {
    run();
  } catch (e) {
    return (e as Error).message;
  }
  return "nothing thrown";
};

describe("the arcantis command's input", function () {
  this.timeout(60000);

  it("reads --since and --until without an offset as UTC, whatever the local time zone", () => {
    const zone = process.env.TZ;
    process.env.TZ = "Asia/Tokyo"; // where JavaScript alone would read 12:00 as 03:00 UTC
    try {
      expect(parseUtcTime("2026-10-01T12:00:00", "since").toISOString()).to.equal("2026-10-01T12:00:00.000Z");
      expect(parseUtcTime("2026-10-01T12:00", "since").toISOString()).to.equal("2026-10-01T12:00:00.000Z");
      expect(parseUtcTime("2026-10-01", "since").toISOString()).to.equal("2026-10-01T00:00:00.000Z");
      expect(parseUtcTime("2026-10-01T12:00:00Z", "since").toISOString()).to.equal("2026-10-01T12:00:00.000Z");
      expect(parseUtcTime("2026-10-01T12:00:00+02:00", "until").toISOString()).to.equal("2026-10-01T10:00:00.000Z");
    } finally {
      if (zone === undefined) delete process.env.TZ;
      else process.env.TZ = zone;
    }
  });

  it("refuses times it would have to guess, and days that do not exist", () => {
    for (const value of ["2026-02-30", "2026-13-01", "Oct 1 2026", "2026-10-01 12:00", "1759320000", ""]) {
      expect(thrown(() => parseUtcTime(value, "since")), value).to.contain("--since: not an ISO date or time");
    }
  });

  it("takes --max and --concurrency only as whole numbers of 1 or more", () => {
    expect(parsePositiveInteger("4", "concurrency")).to.equal(4);
    for (const value of ["abc", "0", "-1", "1.5", "1e3", " 4", ""]) {
      expect(thrown(() => parsePositiveInteger(value, "concurrency")), value).to.contain("--concurrency: not a whole number");
    }
  });

  it("never shows what is in a keypair file it cannot use", async () => {
    const secretLooking = "[201, 17, 99, oops-not-json";
    const unusable = [secretLooking, "[1, 2, 3]", JSON.stringify(Array(64).fill("7")), '{"secretKey": [1, 2]}', JSON.stringify(Array(64).fill(256))];
    for (const text of unusable) {
      const error = (await keypairFromFile(text, "wallet.json").catch((e: Error) => e)) as Error;
      expect(error.message, text).to.equal(`--keypair wallet.json: ${NOT_A_KEYPAIR}`);
    }
    // 64 bytes whose public half does not belong to the secret half.
    const mismatched = Array.from({ length: 64 }, (_, i) => i);
    const error = (await keypairFromFile(JSON.stringify(mismatched), "wallet.json").catch((e: Error) => e)) as Error;
    expect(error.message).to.contain("not a valid keypair").and.not.to.contain("0,1,2");

    const seed = new Uint8Array(randomBytes(32));
    const signer = await keypairFromFile(JSON.stringify([...seed, ...ed25519.getPublicKey(seed)]), "wallet.json");
    expect(signer.address).to.be.a("string");
  });

  it("refuses --concurrency abc before it reads the keypair or calls the RPC", async () => {
    const { code, stderr } = await arcantis(
      "audit-report", "--mint", "So11111111111111111111111111111111111111112", "--keypair", "/nonexistent/wallet.json",
      "--rpc", "http://127.0.0.1:9", "--concurrency", "abc",
    );
    expect(code).to.equal(1);
    expect(stderr).to.contain("--concurrency: not a whole number of 1 or more: abc");
  });

  it("names a bad keypair file without printing it", async () => {
    const file = path.join(mkdtempSync(path.join(tmpdir(), "arcantis-cli-")), "wallet.json");
    writeFileSync(file, "4f6e6c792d612d746573742d736563726574 not json", { mode: 0o600 });
    const { code, stderr } = await arcantis("audit-report", "--mint", "So11111111111111111111111111111111111111112", "--keypair", file, "--rpc", "http://127.0.0.1:9");
    expect(code).to.equal(1);
    expect(stderr).to.contain(NOT_A_KEYPAIR);
    expect(stderr).not.to.contain("4f6e6c79");
  });
});
