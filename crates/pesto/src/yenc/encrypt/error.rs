//! Error surface for yEnc encryption primitives.
//!
//! Error names mirror the malformed-input taxonomy (VEC-05) so callers can
//! map failures onto the two-tier model (body standard §5): variants marked
//! retriable are provider corruption and may trigger alternate-provider
//! failover; `ZeroSegmentIndex` on a locally allocated index is a bug.
//!
//! None of these errors ever carries plaintext, key material, or nonces.

use std::fmt;

/// Encryption/decryption failure classifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionError {
    /// Argon2id, HMAC, or AEAD primitive failure (local, non-wire).
    Crypto(String),
    /// XChaCha20-Poly1305 tag verification failed (retriable tier).
    Authentication,
    /// Cipher token is not exactly `XChaCha20-Poly1305`, or the token
    /// layout is unrecognizable (retriable tier on the wire).
    UnsupportedCipher,
    /// Not exactly five SP-separated tokens (retriable tier).
    InvalidTokenCount,
    /// Tab separators, repeated spaces, or leading/trailing whitespace.
    InvalidWhitespace,
    /// Salt parameter is not exactly 32 hex chars (retriable tier).
    InvalidSaltLength,
    /// Salt parameter contains non-hex characters (retriable tier).
    InvalidSaltHex,
    /// A salt byte outside the 253-byte Alphabet (0x00, 0x0A, 0x0D).
    InvalidSaltCharacter,
    /// Tag parameter is not exactly 32 hex chars (retriable tier).
    InvalidTagLength,
    /// Tag parameter contains non-hex characters (retriable tier).
    InvalidTagHex,
    /// Index parameter is not exactly 8 hex chars (retriable tier).
    InvalidIndexLength,
    /// Index parameter contains non-hex characters (retriable tier).
    InvalidIndexHex,
    /// Hex digits are uppercase where lowercase is required (retriable tier).
    UppercaseHex,
    /// segmentIndex 0 is invalid everywhere it appears.
    ZeroSegmentIndex,
    /// uint32_be(segmentIndex) contains 0x0A or 0x0D (retriable tier).
    ForbiddenSegmentIndexByte,
    /// Line-1 content shorter than the 22-byte minimum (retriable tier).
    LineTruncated,
    /// Line content shorter than two bytes (retriable tier).
    LineTooShort,
    /// FF1 decryption of a control line failed or the plaintext does not
    /// start with the expected `=y` prefix (retriable tier).
    ControlLineDecryptFailure,
    /// `=yencryption` appears at a disallowed physical position.
    MisplacedEncryptionHeader,
    /// Restored Line-1 salt differs from the `=yencryption` salt.
    SaltMismatch,
    /// Restored Line-1 segmentIndex differs from the `=yencryption` index.
    DualIndexMismatch,
    /// NZB provenance metadata missing or invalid (structural tier).
    MetadataValidation(String),
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Crypto(m) => return write!(f, "crypto: {m}"),
            Self::Authentication => "AUTHENTICATION_FAILURE",
            Self::UnsupportedCipher => "UNSUPPORTED_CIPHER",
            Self::InvalidTokenCount => "INVALID_TOKEN_COUNT",
            Self::InvalidWhitespace => "INVALID_WHITESPACE",
            Self::InvalidSaltLength => "INVALID_SALT_LENGTH",
            Self::InvalidSaltHex => "INVALID_SALT_HEX",
            Self::InvalidSaltCharacter => "INVALID_SALT_CHARACTER",
            Self::InvalidTagLength => "INVALID_TAG_LENGTH",
            Self::InvalidTagHex => "INVALID_TAG_HEX",
            Self::InvalidIndexLength => "INVALID_INDEX_LENGTH",
            Self::InvalidIndexHex => "INVALID_INDEX_HEX",
            Self::UppercaseHex => "UPPERCASE_HEX",
            Self::ZeroSegmentIndex => "ZERO_SEGMENT_INDEX",
            Self::ForbiddenSegmentIndexByte => "FORBIDDEN_SEGMENT_INDEX_BYTE",
            Self::LineTruncated => "LINE_TRUNCATED",
            Self::LineTooShort => "LINE_TOO_SHORT",
            Self::ControlLineDecryptFailure => "CONTROL_LINE_DECRYPT_FAILURE",
            Self::MisplacedEncryptionHeader => "MISPLACED_ENCRYPTION_HEADER",
            Self::SaltMismatch => "SALT_MISMATCH",
            Self::DualIndexMismatch => "DUAL_INDEX_MISMATCH",
            Self::MetadataValidation(m) => return write!(f, "metadata validation: {m}"),
        };
        f.write_str(name)
    }
}

impl std::error::Error for EncryptionError {}

impl From<chacha20poly1305::Error> for EncryptionError {
    fn from(_: chacha20poly1305::Error) -> Self {
        Self::Authentication
    }
}
