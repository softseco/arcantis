// SPDX-License-Identifier: BUSL-1.1
//
// The names and versions of the formats Arcantis writes or depends on. docs/formats.md describes
// each format, who defines it and how a change to it is handled.
//
// Two rules follow from them. A format is recognised by the name and version it carries, never
// guessed from its length or shape. And data in a format or version this release does not know is
// refused with UNSUPPORTED_FORMAT, never read as if it were a known one.

/**
 * The key derivation: one wallet signature over this message (followed by a public seed for the
 * seed-scoped keys), expanded with HKDF-SHA512 into the ElGamal secret key and the AES key. It is
 * the derivation every standard client uses. The version is part of the message, so a different
 * derivation would sign a different message and give different keys; Arcantis refuses to derive
 * keys if the cryptography library it runs on signs anything else.
 */
export const KEY_DERIVATION_SCHEME = "solana-conf-bal/v1";

/** The `format` field of an auditor report written as JSON by {@link confidentialActivityToJson}. */
export const CONFIDENTIAL_ACTIVITY_FORMAT = "arcantis.confidential-activity";

/**
 * The version of that JSON format this release writes. It reads this version and every earlier one.
 */
export const CONFIDENTIAL_ACTIVITY_VERSION = 1;
