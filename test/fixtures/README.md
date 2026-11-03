# Test fixtures

## `spl_token_2022.so`

Token-2022 **v11.1.0**, built from the official source. The on-chain and browser tests load it into
the local validator in place of the bundled Token-2022:

```bash
TOKEN_2022_SO=test/fixtures/spl_token_2022.so npm run validator
```

The SDK uses `@solana-program/token-2022` 0.19. The Token-2022 that ships inside
`solana-test-validator` is older and rejects that client's confidential `Deposit` with
`InvalidInstructionData`, so the tests need a program that matches the client.

| | |
|---|---|
| Source | [solana-program/token-2022](https://github.com/solana-program/token-2022), tag `program@v11.1.0` (commit `8867f751c0f69367ba03af4f85510b5611989491`) |
| Built with | `cargo build-sbf --manifest-path program/Cargo.toml`, Solana CLI 4.2.2 (platform-tools v1.54) |
| SHA-256 | `6b76b305fae61f47e18640fb0121f0e8a85abe19d076b3c9c547c3e5eeadef4e` |

The same file is used by the [Sentinel](https://github.com/softseco/sentinel) tests. The JS client
0.19.0 was published from a commit whose program code is identical to `program@v11.1.0` apart from
the version number.

SBF builds are not byte-for-byte reproducible across toolchains, so a rebuild may hash differently.
To rebuild: `bash scripts/build-token-2022.sh`, then copy the `.so` it prints here and update the
hash above.

## `sentinel.so`

[Sentinel](https://github.com/softseco/sentinel) **2.1.0**, the transfer-hook program, at its
program id `5fH1jj6XeZC96jPCxKiSb2onAXcs7f4rMeqMmSsP6puD`. The Rust crate's on-chain tests load
it to send confidential transfers through a real transfer hook (refused until the issuer opts in,
then allowed):

```bash
TOKEN_2022_SO=test/fixtures/spl_token_2022.so SENTINEL_SO=test/fixtures/sentinel.so \
  bash scripts/start-test-validator.sh
```

| | |
|---|---|
| Source | [softseco/sentinel](https://github.com/softseco/sentinel), 2.1.0 (commit `1193793`) |
| Built with | `cargo build-sbf` (anchor-lang 0.31.1), Solana CLI 4.2.2 (platform-tools v1.54) |
| SHA-256 | `4bb3cfc935b7930bf59fa52f4afe49e72660ee2df180bef3308cfc0c048c4434` |

The validator itself must come from **Agave 4.x** (tested with 4.2.2). The ZK ElGamal Proof Program
in Agave 2.x and 3.x verifies proofs in an older format and rejects the ones `@solana/zk-sdk` makes
today, with `SigmaProof(PubkeyValidity, AlgebraicRelation)`.
