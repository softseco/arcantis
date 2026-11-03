#!/usr/bin/env bash
#
# start-test-validator.sh — local Solana validator with Token-2022 Confidential
# Transfers enabled (for SDK integration tests).
#
# The ZK ElGamal Proof Program is force-enabled by deactivating the disable
# feature gate (Agave re-enables it for real in the 4.x cycle).
#
# Optional: set TOKEN_2022_SO to a path to a locally-built spl_token_2022.so to
# OVERRIDE the validator's bundled Token-2022 with a build that matches the
# @solana-program/token-2022 client. This is the approach the official
# solana-program/token-2022 tests use, and it is required for instructions whose
# format differs between the bundled program and the published client (e.g.
# confidential `deposit`). Example:
#   TOKEN_2022_SO=~/token-2022-src/target/deploy/spl_token_2022.so npm run validator
#
set -euo pipefail

KILL_SWITCH="zkdoVwnSFnSLtGJG7irJPEYUpmb4i7sGMGcnN6T9rnC"
TOKEN_2022="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

ARGS=(--reset --deactivate-feature "$KILL_SWITCH")

if [ -n "${TOKEN_2022_SO:-}" ]; then
  if [ ! -f "$TOKEN_2022_SO" ]; then
    echo "TOKEN_2022_SO is set but not found: $TOKEN_2022_SO" >&2
    exit 1
  fi
  echo ">> Overriding Token-2022 with client-matching program: $TOKEN_2022_SO"
  # <address> <program.so> <upgrade-authority-pubkey>  (authority is a placeholder for local testing)
  ARGS+=(--upgradeable-program "$TOKEN_2022" "$TOKEN_2022_SO" "$TOKEN_2022")
fi

# Optional extra programs for the Rust crate's on-chain tests:
#   SENTINEL_SO            Sentinel, the transfer hook (test/fixtures/sentinel.so)
#   CONFIDENTIAL_VAULT_SO  the Anchor example (rust/examples/anchor-vault)
if [ -n "${SENTINEL_SO:-}" ]; then
  ARGS+=(--bpf-program 5fH1jj6XeZC96jPCxKiSb2onAXcs7f4rMeqMmSsP6puD "$SENTINEL_SO")
fi
if [ -n "${CONFIDENTIAL_VAULT_SO:-}" ]; then
  ARGS+=(--bpf-program DzaS2RboEYWKC1EvuPPnWpDbjJesPheCw3KV14qVvoPn "$CONFIDENTIAL_VAULT_SO")
fi

echo ">> Local validator with ZK ElGamal Proof Program ENABLED"
exec solana-test-validator "${ARGS[@]}"
