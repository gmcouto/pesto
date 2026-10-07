//! Upload-session cryptography: one shared salt, one Argon2id session key,
//! and per-segment body encryption — derived once per upload session (body
//! standard v1.2 §4 step a/b; combined-mode salt domain = the 253-byte
//! Alphabet per both standards' dual-bootstrap agreement rule).

use rand::rand_core::{OsRng, TryRngCore};

use super::alphabet::is_alphabet_byte;
use super::body::{build_yencryption_line, decrypt_body, encrypt_body};
use super::error::EncryptionError;
use super::index::SegmentIndexAllocator;
use super::keys::{derive_session_key, SessionKey, SALT_LEN};

/// Sample 16 salt bytes uniformly from the 253-byte Alphabet via rejection
/// sampling — never a modulo reduction of the full byte range (control
/// standard v1.2 §4: biased reduction MUST NOT be used).
pub fn sample_alphabet_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    let mut rng = OsRng;
    for slot in &mut salt {
        loop {
            let candidate: u8 = rng.try_next_u32().expect("OS entropy unavailable") as u8;
            if is_alphabet_byte(candidate) {
                *slot = candidate;
                break;
            }
        }
    }
    salt
}

/// Everything an encrypted upload session needs: the shared salt, the single
/// Argon2id-derived session key, and the release-wide segmentIndex
/// allocator. Create once per upload and thread through prepare/worker/spool
/// so retries reproduce decryptable articles.
#[derive(Debug)]
pub struct EncryptionSession {
    pub salt: [u8; SALT_LEN],
    pub key: SessionKey,
    pub allocator: SegmentIndexAllocator,
}

impl EncryptionSession {
    /// Create a session with a fresh Alphabet salt and a derived key
    /// (Argon2id — ~64MB, once per upload session).
    pub fn new(password: &[u8]) -> Self {
        let salt = sample_alphabet_salt();
        let key = derive_session_key(password, &salt);
        Self {
            salt,
            key,
            allocator: SegmentIndexAllocator::default(),
        }
    }

    /// Encrypt one segment body and produce the canonical `=yencryption`
    /// line content for it.
    pub fn encrypt_segment(
        &self,
        segment_index: u32,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), EncryptionError> {
        encrypt_body(&self.key, segment_index, plaintext)
    }

    /// Build the wire `=yencryption` line for a segment encrypted in this
    /// session.
    pub fn yencryption_line(
        &self,
        segment_index: u32,
        tag: &[u8; 16],
    ) -> Result<String, EncryptionError> {
        build_yencryption_line(&self.salt, segment_index, tag)
    }
}

/// The decryption-side mirror used by penne: derive the session key from a
/// password and a wire-provided salt. Exposed for T03's download seam.
pub fn session_key_from(password: &[u8], salt: &[u8; SALT_LEN]) -> SessionKey {
    derive_session_key(password, salt)
}

/// Full decrypt of one segment body given wire inputs. Returns the
/// plaintext only after successful Poly1305 authentication.
pub fn decrypt_segment(
    key: &SessionKey,
    segment_index: u32,
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, EncryptionError> {
    decrypt_body(key, segment_index, ciphertext, tag)
}

/// Re-export for downstream structural checks (dual-bootstrap agreement).
pub use super::body::parse_yencryption_line as parse_header;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_is_alphabet_only() {
        for _ in 0..16 {
            let salt = sample_alphabet_salt();
            assert!(salt.iter().all(|b| is_alphabet_byte(*b)));
        }
    }

    #[test]
    fn segment_round_trips_through_the_session() {
        let session = EncryptionSession::new(b"round-trip-pw");
        let (ciphertext, tag) = session
            .encrypt_segment(42, b"segment plaintext bytes")
            .unwrap();
        let line = session.yencryption_line(42, &tag).unwrap();
        let header = parse_header(&line).unwrap();
        assert_eq!(header.salt, session.salt);
        assert_eq!(header.segment_index, 42);
        assert_eq!(header.tag, tag);
        let key = session_key_from(b"round-trip-pw", &header.salt);
        let plaintext = decrypt_segment(&key, 42, &ciphertext, &tag).unwrap();
        assert_eq!(plaintext, b"segment plaintext bytes");
    }
}
