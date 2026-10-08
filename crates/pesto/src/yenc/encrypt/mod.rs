//! yEnc body and control-line encryption primitives (standards v1.2).
//!
//! This module implements the wire contract defined by the yEnc Body
//! Encryption Standard v1.2 (§2-§5: key/nonce derivation, XChaCha20-Poly1305
//! body encryption before yEnc encoding, the canonical `=yencryption`
//! five-token grammar, decryption/two-tier error handling) and the yEnc
//! Control Lines Encryption Standard v1.2 (§2: 253-byte Alphabet and
//! bijection; §4: FF1 control-line encryption with Line-1 bootstrap; §5:
//! decryption loop and dual-bootstrap agreement; §6: combined-mode
//! placement).
//!
//! Boundaries honored here:
//! - Body encryption happens BEFORE yEnc encoding; only ciphertext is
//!   yEnc-encoded. The tag and salt ride in the `=yencryption` header.
//! - Control-line FF1 encryption happens AFTER the complete yEnc block
//!   exists (including `=yencryption`), before spool/NNTP.
//! - One shared 253-byte-Alphabet salt and one Argon2id session key per
//!   upload session; segmentIndex is release-wide and skips forbidden
//!   candidates (VEC-07).
//! - Authentication failure releases no plaintext or ciphertext: decrypt
//!   APIs return errors without any output bytes (body standard §5
//!   zero-output rule).
//!
//! Submodules: [`alphabet`] (domain + bijection), [`keys`] /
//! [`keys_argon2`] (derivations), [`body`] (AEAD + header grammar),
//! [`control`] (FF1 + bootstrap), [`index`] (VEC-07 allocator), [`error`]
//! (taxonomy-mapped error surface), [`session`] (per-upload session object).

pub mod alphabet;
pub mod body;
pub mod control;
pub mod error;
pub mod header;
pub mod index;
pub mod keys;
mod keys_argon2;
pub mod session;

pub use alphabet::{byte_to_numeral, is_alphabet_byte, numeral_to_byte, RADIX};
pub use body::{
    build_yencryption_line, decrypt_body, encrypt_body, parse_yencryption_line, EncryptionHeader,
};
pub use control::{
    build_bootstrap, decrypt_control_line, decrypt_line1, encrypt_control_line, encrypt_line1,
    extract_bootstrap, ff1_decrypt_line, ff1_encrypt_line, Bootstrap,
};
pub use error::EncryptionError;
pub use header::{
    BOOTSTRAP_LEN, ENCRYPTION_LINE_LEN, INDEX_HEX_LEN, LINE1_MIN_LEN, SALT_HEX_LEN,
    SEGMENT_INDEX_MAX, SEGMENT_INDEX_MIN, TAG_HEX_LEN,
};
pub use index::{index_is_forbidden, next_permitted_index, SegmentIndexAllocator};
pub use keys::{
    body_nonce, control_enc_key, control_tweak, derive_session_key, SessionKey, SALT_LEN,
};
pub use session::{decrypt_segment, sample_alphabet_salt, session_key_from, EncryptionSession};
