#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Build the Token-2022 program used by the on-chain and browser tests (test/fixtures/).
# Needs git and the Solana CLI (cargo build-sbf).
set -euo pipefail
TAG="${1:-program@v11.1.0}"
WORK="$(mktemp -d)"
git clone --quiet --depth 1 --branch "$TAG" https://github.com/solana-program/token-2022 "$WORK/token-2022"
cd "$WORK/token-2022"
# The repository pins a host toolchain in rust-toolchain.toml; build-sbf uses its own.
RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" cargo build-sbf --manifest-path program/Cargo.toml
SO="$WORK/token-2022/target/deploy/spl_token_2022.so"
echo
echo "built $TAG ($(git rev-parse HEAD))"
echo "  $SO"
echo "  sha256 $(sha256sum "$SO" | cut -d' ' -f1)"
