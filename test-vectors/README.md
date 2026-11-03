# Shared test vectors

`confidential-transfers.json` is read by both test suites — `test/vectors.test.ts` (TypeScript)
and `rust/tests/vectors.rs` (Rust) — so the two SDKs are checked against the same bytes:

- `standardDerivation`: wallet private key → ElGamal secret key, ElGamal public key, AES key
  (the standard `solana-conf-bal/v1` derivation, no seed).
- `pdaWalletDerivation`: the seed `programId || walletPda || mint || tokenAccount` for a
  program-owned account, and the keys an operator wallet derives with it.
- `auditorTransferAmount`: an amount encrypted to an auditor in two halves (low 16 bits, high
  32 bits), as a confidential transfer carries it; both SDKs must decrypt the same amount.
- `decryptableBalance`: an AES-encrypted available balance and the amount it holds.

Hex strings are bytes; amounts are decimal strings. The file was generated once with
`cargo test --test gen_vectors -- --ignored` in `rust/`; regenerating gives new ciphertexts (they
are randomized) but the same keys. Change it only on purpose: both suites pin it.
