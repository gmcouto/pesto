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

pub mod adapter;
pub mod body;
pub mod control;
pub mod kdf;

#[cfg(test)]
mod tests;

pub use adapter::{DownloadDecryptionAdapter, UploadEncryptionAdapter};
pub use kdf::EncryptionSession;

/// Typed two-tier error classification (yEnc Body Encryption Standard §5
/// Two-Tier model; Control Std §8). Constructed AT THE CRYPTO ORIGIN and
/// attached to the `anyhow::Error` via the downcastable
/// [`CryptoErrorKindEnvelope`]; consumers (penne's failover router) recover
/// the kind by downcasting — the type is defined HERE in pesto because penne
/// depends on pesto, never the reverse.
///
/// - [`CryptoErrorKind::MetadataValidation`] — structural: the failure would
///   reproduce identically against every server (missing password,
///   unsupported mode/version). Job-level failure, no provider rotation.
/// - [`CryptoErrorKind::ProviderFailover`] — retriable: the fetched copy is
///   corrupt/truncated/tampered; an alternate server may have an intact copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoErrorKind {
    MetadataValidation,
    ProviderFailover,
}

/// Downcastable `anyhow` wrapper carrying the origin-constructed
/// [`CryptoErrorKind`] on the error chain. Attach with
/// [`attach_crypto_error_kind`]; recover with [`crypto_error_kind_of`].
#[derive(Debug)]
pub struct CryptoErrorKindEnvelope {
    pub kind: CryptoErrorKind,
}

impl std::fmt::Display for CryptoErrorKindEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            CryptoErrorKind::MetadataValidation => write!(f, "METADATA_VALIDATION"),
            CryptoErrorKind::ProviderFailover => write!(f, "PROVIDER_FAILOVER"),
        }
    }
}

impl std::error::Error for CryptoErrorKindEnvelope {}

/// Attach `kind` to `err` at the crypto origin so downstream routers can
/// downcast it. The envelope becomes the error-chain ROOT (via
/// `Error::new(...).context(err)`), so human-readable `Display` still shows
/// the original message tokens while `crypto_error_kind_of` recovers the
/// kind anywhere on the chain. Never embed password/key/nonce material.
pub fn attach_crypto_error_kind(err: anyhow::Error, kind: CryptoErrorKind) -> anyhow::Error {
    anyhow::Error::new(CryptoErrorKindEnvelope { kind }).context(err)
}

/// Recover the origin-attached [`CryptoErrorKind`] from an error chain, if
/// any. `None` = unclassified (caller default routing applies).
pub fn crypto_error_kind_of(err: &anyhow::Error) -> Option<CryptoErrorKind> {
    err.chain()
        .find_map(|c| c.downcast_ref::<CryptoErrorKindEnvelope>())
        .map(|env| env.kind)
}
