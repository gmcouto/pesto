//! Cryptographic layer for yEnc body and control-line encryption.
//!
//! # Protocol Overview (Experimental)
//!
//! This module implements the experimental yEnc encryption standards:
//! - **Body Encryption:** Per-segment XChaCha20-Poly1305 AEAD before yEnc encoding.
//! - **Control-Line Encryption:** Radix 253 NIST SP 800-38G FF1 format-preserving encryption
//!   of all `=ybegin`, `=ypart`, `=yend`, and `=yencryption` control lines.
//! - **Key Derivation:** Argon2id (RFC 9106, t=1, m=64MB, p=4) with a 16-byte random session salt.
//!
//! # Threat Model
//!
//! - **Confidentiality:** Content encryption at the article layer protects stored Usenet articles
//!   from parties that do not possess the NZB and password. However, because the password is
//!   conventionally distributed via the NZB (`<meta type="password">`), release confidentiality
//!   depends strictly on private distribution of the NZB file.
//! - **Transport Security:** TLS protects network transit to and from NNTP providers;
//!   article-layer encryption protects content at rest on Usenet backend storage.
//! - **Integrity:** Poly1305 tags authenticate segment bodies. Authentication failure releases
//!   zero unauthenticated plaintext and is treated as provider corruption eligible for tier failover.
//!
//! # Operational Constraints
//!
//! - **Bootstrap-only identity (v1.2):** Per-segment identity (salt +
//!   globally unique `segmentIndex`) is carried exclusively in the 20-byte
//!   bootstrap prefix of encrypted control Line 1 and the `=yencryption`
//!   line — never in NZB XML attributes. Because each upload session uses
//!   an independent random salt and a distinct global `segmentIndex` space,
//!   merging NZBs from multiple sessions under one password is not
//!   supported for encrypted uploads.
//! - **Status:** The protocol is currently experimental (spec v1.2). All KDF
//!   parameters, tweak/nonce derivation rules, control-line formats, and test
//!   vectors are frozen for this release. An independent formal cryptographic
//!   review is recommended before stabilization.

pub(crate) mod adapter;
pub(crate) mod body;
pub(crate) mod control;
pub(crate) mod kdf;

#[cfg(test)]
mod tests;

pub use adapter::{DownloadDecryptionAdapter, UploadEncryptionAdapter};
pub use control::{extract_bootstrap_from_line1, generate_alphabet_salt};
pub use kdf::EncryptionSession;

// Error classification note (yEnc Body Encryption Standard §5 Two-Tier
// model; Control Std §8): crypto failures carry their classification in the
// message itself. Callers route every decode/decrypt failure to provider
// failover (penne's corrupt-copy path), while NZB parse failures are
// structural and already fatal before any network access — no downcastable
// error-kind envelope is needed. The wire error-code strings (e.g.
// `UNSUPPORTED_CIPHER`, `CONTROL_LINE_DECRYPT_FAILURE`) are conformance
// surface matched by the malformed-input vectors and MUST NOT change.
