//! Key, nonce, and tweak derivation for yEnc encryption.
//!
//! Body standard v1.2 §2/§4: key = Argon2id(password, salt, time=1,
//! memory=64MB, threads=4, 32-byte output) derived once per upload session;
//! body nonce = HMAC-SHA256(key, "yenc-body nonce" || uint32_be(segmentIndex))
//! truncated to 24 bytes. Control standard v1.2 §4: masterKey uses the same
//! Argon2id parameters; encKey = HMAC-SHA256(masterKey, "yenc-control key")
//! (full 32-byte digest, AES-256 key); tweak = HMAC-SHA256(masterKey,
//! "yenc-control tweak" || uint32_be(segmentIndex) || uint32_be(lineIndex))
//! truncated to 8 bytes.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::keys_argon2::argon2id;

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// 32-byte body/control key derived once per upload session
/// (Argon2id(password, salt, time=1, memory=64MB, threads=4)).
pub type SessionKey = [u8; 32];

/// Derive the shared session key: Argon2id(password, salt) with the normative
/// parameters (body standard §4 step b; control standard §4 step b — both
/// use time=1, memory=64MB, threads=4, 256-bit output).
pub fn derive_session_key(password: &[u8], salt: &[u8; SALT_LEN]) -> SessionKey {
    argon2id(password, salt)
}

/// Salt byte length (16 raw bytes, hex-encoded as 32 chars on the wire).
pub const SALT_LEN: usize = 16;

/// Body nonce: first 24 bytes of HMAC-SHA256(key, "yenc-body nonce" ||
/// uint32_be(segmentIndex)) — an exact 19-byte HMAC message (body standard
/// §4 step c).
pub fn body_nonce(key: &SessionKey, segment_index: u32) -> [u8; 24] {
    let mut message = [0u8; 19];
    message[..15].copy_from_slice(b"yenc-body nonce");
    message[15..].copy_from_slice(&segment_index.to_be_bytes());
    let digest = hmac_sha256(key, &message);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&digest[..24]);
    nonce
}

/// FF1 AES-256 key: full 32-byte HMAC-SHA256(masterKey, "yenc-control key")
/// — an exact 16-byte HMAC message (control standard §4 step c).
pub fn control_enc_key(master_key: &SessionKey) -> SessionKey {
    hmac_sha256(master_key, b"yenc-control key")
}

/// FF1 tweak: first 8 bytes of HMAC-SHA256(masterKey, "yenc-control tweak" ||
/// uint32_be(segmentIndex) || uint32_be(lineIndex)) — an exact 26-byte HMAC
/// message (control standard §4 step d).
pub fn control_tweak(master_key: &SessionKey, segment_index: u32, line_index: u32) -> [u8; 8] {
    let mut message = [0u8; 26];
    message[..18].copy_from_slice(b"yenc-control tweak");
    message[18..22].copy_from_slice(&segment_index.to_be_bytes());
    message[22..].copy_from_slice(&line_index.to_be_bytes());
    let digest = hmac_sha256(master_key, &message);
    let mut tweak = [0u8; 8];
    tweak.copy_from_slice(&digest[..8]);
    tweak
}

#[cfg(test)]
mod tests {
    #[test]
    fn hmac_message_lengths_match_the_standards() {
        // body nonce message: 15-byte ASCII prefix + 4-byte BE index = 19
        let mut msg = Vec::new();
        msg.extend_from_slice(b"yenc-body nonce");
        msg.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(msg.len(), 19);

        // control tweak message: 18-byte ASCII prefix + 4 + 4 = 26
        let mut msg = Vec::new();
        msg.extend_from_slice(b"yenc-control tweak");
        msg.extend_from_slice(&1u32.to_be_bytes());
        msg.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(msg.len(), 26);
    }
}
