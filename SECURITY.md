# Security Policy

This project implements cryptographic, security-sensitive functionality (ElGamal/AES key handling
and zero-knowledge proofs for Token-2022 Confidential Transfers). We take security reports
seriously and appreciate responsible disclosure.

> **Note:** Arcantis runs end-to-end on devnet and against a local validator. It is self-audited,
> not independently audited. It depends on Solana's ZK ElGamal Proof Program being enabled on the
> target cluster. Review the status notes in the [README](./README.md) before relying on it on
> mainnet-beta.

## Supported versions

| Package | Version | Supported |
|---|---|---|
| `@softseco/arcantis` (TypeScript) | `1.x` | ✅ from the first release |
| `arcantis` (Rust) | `1.x` | ✅ from the first release |
| `@softseco/confidential-transfers` (TypeScript, the earlier name) | all | ❌ (move to `@softseco/arcantis`) |
| `softseco-confidential-transfers` (Rust, the earlier name) | all | ❌ (move to `arcantis`) |

Security fixes land on the latest release of each package.

`2.0.0` changed key derivation to the ecosystem standard. Keys derived by `1.x` are different, so
the balance of an account configured under `1.x` has to be moved out with `1.x` before upgrading;
see [CHANGELOG.md](./CHANGELOG.md).

## Reporting a vulnerability

Please do **not** open a public GitHub issue, pull request, or social post for security reports.

Instead, use one of:

1. **GitHub private vulnerability reporting** (preferred) — on the repository, go to the
   **Security** tab → **Report a vulnerability**. This opens a private advisory with the maintainers.
2. **Email** — contact the maintainer at **hello@softseco.com** with the details.

Please include, where possible:

- A description of the issue and its potential impact
- Steps to reproduce or a proof of concept
- Affected version(s) and environment (cluster, Node/Rust versions)
- Any suggested remediation

## What to expect

- We aim to acknowledge a report within **72 hours**.
- We'll work with you to understand and validate the issue, and keep you updated on remediation.
- Once a fix is released, we're happy to credit you in the advisory unless you prefer to remain
  anonymous.

Thank you for helping keep the ecosystem safe.
