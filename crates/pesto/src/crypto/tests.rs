use hmac::Mac;
use proptest::prelude::*;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

use super::adapter::{parse_yencryption_line, DownloadDecryptionAdapter, UploadEncryptionAdapter};
use super::body::{decrypt_body, encrypt_body};
use super::control::{self, extract_bootstrap_from_line1, ff1_decrypt_line, ff1_encrypt_line};
use super::kdf::EncryptionSession;
use crate::yenc::PartSpec;

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2), "hex string length must be even");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn test_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

#[derive(Deserialize)]
struct Argon2idFixture {
    vectors: Vec<Argon2idVector>,
}

#[derive(Deserialize)]
struct Argon2idVector {
    id: String,
    #[serde(alias = "password")]
    transport_kdf_input: String,
    salt_hex: String,
    expected_key_hex: String,
}

#[test]
fn test_argon2id_kdf_test_vectors() {
    let path = test_vectors_dir().join("argon2id.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let fixture: Argon2idFixture = serde_json::from_str(&content).unwrap();

    for vec in &fixture.vectors {
        let salt_bytes = hex_decode(&vec.salt_hex);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);

        let session = EncryptionSession::new(&vec.transport_kdf_input, salt)
            .unwrap_or_else(|e| panic!("session creation failed for vector {}: {e}", vec.id));

        let derived_hex = hex_encode(session.master_key());
        assert_eq!(
            derived_hex, vec.expected_key_hex,
            "master key mismatch for vector {}",
            vec.id
        );
    }
}

#[derive(Deserialize)]
struct NonceTweakFixture {
    body_nonce_vectors: Vec<BodyNonceVector>,
    control_tweak_vectors: Vec<ControlTweakVector>,
}

#[derive(Deserialize)]
struct BodyNonceVector {
    id: String,
    key_hex: String,
    segment_index: u32,
    expected_nonce_hex: String,
}

#[derive(Deserialize)]
struct ControlTweakVector {
    id: String,
    segment_index: u32,
    line_index: u32,
    full_hmac_hex: String,
    expected_tweak_hex: String,
}

#[test]
fn test_nonce_and_tweak_test_vectors() {
    let path = test_vectors_dir().join("nonce_tweak.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let fixture: NonceTweakFixture = serde_json::from_str(&content).unwrap();

    for vec in &fixture.body_nonce_vectors {
        let key_bytes = hex_decode(&vec.key_hex);
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&key_bytes);

        // Derive nonce directly via HMAC-SHA256
        let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&master_key).unwrap();
        mac.update(b"yenc-body nonce");
        mac.update(&vec.segment_index.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let nonce_hex = hex_encode(&digest[0..24]);

        assert_eq!(
            nonce_hex, vec.expected_nonce_hex,
            "body nonce mismatch for vector {}",
            vec.id
        );
    }

    let argon2id_path = test_vectors_dir().join("argon2id.json");
    let argon2id_content = std::fs::read_to_string(&argon2id_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", argon2id_path.display()));
    let argon2id_fixture: Argon2idFixture = serde_json::from_str(&argon2id_content).unwrap();
    // v1.2 nonce_tweak.json no longer carries a
    // `control_tweak_argon2id_vector` reference; the control tweak vectors
    // carry `master_key_hex` directly. Anchor the Argon2id session on the
    // first control tweak vector's segment/line setup via its referenced
    // control_line_encryption vector instead.
    let first_tweak = fixture
        .control_tweak_vectors
        .first()
        .expect("control tweak vectors must be present");
    let _ = first_tweak;

    let control_path = test_vectors_dir().join("control_line_encryption.json");
    let control_content = std::fs::read_to_string(&control_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", control_path.display()));
    let control_fixture: ControlLineFixture = serde_json::from_str(&control_content).unwrap();
    let control_vector = control_fixture
        .vectors
        .iter()
        .find(|vector| vector["id"] == "control-vec-01-line-1-ybegin-single")
        .expect("canonical control-line vector must exist");
    // Rebuild the Argon2id session from the control vector's own password
    // and salt (v1.2 nonce_tweak.json carries no Argon2id back-reference).
    let session_salt_bytes = hex_decode(control_vector["salt_hex"].as_str().unwrap());
    let mut session_salt = [0u8; 16];
    session_salt.copy_from_slice(&session_salt_bytes);
    let session = EncryptionSession::new(
        control_vector
            .get("transport_kdf_input")
            .or_else(|| control_vector.get("password"))
            .unwrap()
            .as_str()
            .unwrap(),
        session_salt,
    )
    .unwrap();
    // Cross-check: the control vector's password/salt must match an
    // Argon2id vector (same password → same derived master key).
    let control_password = control_vector
        .get("transport_kdf_input")
        .or_else(|| control_vector.get("password"))
        .unwrap()
        .as_str()
        .unwrap();
    let matching_argon2id = argon2id_fixture
        .vectors
        .iter()
        .find(|v| {
            v.transport_kdf_input == control_password
                && v.salt_hex == control_vector["salt_hex"].as_str().unwrap()
        })
        .expect("control vector password+salt must reference an argon2id vector");
    assert_eq!(
        session.master_key().to_vec(),
        hex_decode(&matching_argon2id.expected_key_hex),
        "session master key must match the referenced argon2id vector"
    );

    let mut key_mac =
        <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(session.master_key()).unwrap();
    key_mac.update(b"yenc-control key");
    let enc_key = key_mac.finalize().into_bytes();
    assert_eq!(
        hex_encode(&enc_key),
        control_vector["derived_enc_key_hex"].as_str().unwrap(),
        "derived control key mismatch"
    );

    for vec in &fixture.control_tweak_vectors {
        let mut tweak_mac =
            <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(session.master_key()).unwrap();
        tweak_mac.update(b"yenc-control tweak");
        tweak_mac.update(&vec.segment_index.to_be_bytes());
        tweak_mac.update(&vec.line_index.to_be_bytes());
        let tweak = tweak_mac.finalize().into_bytes();
        assert_eq!(
            hex_encode(&tweak),
            vec.full_hmac_hex,
            "control HMAC mismatch for vector {}",
            vec.id
        );
        assert_eq!(
            hex_encode(&tweak[0..8]),
            vec.expected_tweak_hex,
            "control tweak mismatch for vector {}",
            vec.id
        );
    }
}

#[derive(Deserialize)]
struct BodyEncryptionFixture {
    vectors: Vec<BodyEncryptionVector>,
}

#[derive(Deserialize)]
struct BodyEncryptionVector {
    id: String,
    #[serde(alias = "password")]
    transport_kdf_input: String,
    salt_hex: String,
    segment_index: u32,
    #[serde(default)]
    aad: Option<AadVector>,
    plaintext_hex: String,
    expected_ciphertext_hex: String,
    #[serde(default)]
    expected_index_hex: Option<String>,
    expected_tag_hex: String,
    #[serde(default)]
    expected_yencryption_line: Option<String>,
}

#[derive(Deserialize)]
struct AadVector {
    expected_aad_hex: String,
}

#[test]
fn test_body_encryption_test_vectors() {
    let path = test_vectors_dir().join("body_encryption.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let fixture: BodyEncryptionFixture = serde_json::from_str(&content).unwrap();

    for vec in &fixture.vectors {
        let salt_bytes = hex_decode(&vec.salt_hex);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);

        let session = EncryptionSession::new(&vec.transport_kdf_input, salt).unwrap();
        let nonce = session.derive_body_nonce(vec.segment_index);

        let plaintext = hex_decode(&vec.plaintext_hex);
        let aad_hex = vec
            .aad
            .as_ref()
            .map(|a| a.expected_aad_hex.clone())
            .unwrap_or_default();
        let aad = hex_decode(&aad_hex);
        let (ct, tag) = encrypt_body(&plaintext, &aad, session.master_key(), &nonce)
            .unwrap_or_else(|e| panic!("encrypt failed for vector {}: {e}", vec.id));

        assert_eq!(
            hex_encode(&ct),
            vec.expected_ciphertext_hex,
            "ciphertext mismatch for vector {}",
            vec.id
        );
        assert_eq!(
            hex_encode(&tag),
            vec.expected_tag_hex,
            "tag mismatch for vector {}",
            vec.id
        );

        if let Some(expected_index) = &vec.expected_index_hex {
            let actual_index = format!("{:08x}", vec.segment_index);
            assert_eq!(
                actual_index, *expected_index,
                "index hex mismatch for vector {}",
                vec.id
            );
        }

        if let Some(expected_line) = &vec.expected_yencryption_line {
            let actual_line = format!(
                "=yencryption cipher=XChaCha20-Poly1305 salt={} index={:08x} tag={}",
                vec.salt_hex,
                vec.segment_index,
                hex_encode(&tag)
            );
            assert_eq!(
                actual_line, *expected_line,
                "header mismatch for vector {}",
                vec.id
            );
        }

        // Roundtrip decrypt
        let decrypted = decrypt_body(&ct, &tag, &aad, session.master_key(), &nonce)
            .unwrap_or_else(|e| panic!("decrypt failed for vector {}: {e}", vec.id));
        assert_eq!(
            decrypted, plaintext,
            "decrypted plaintext mismatch for vector {}",
            vec.id
        );
    }
}

#[derive(Deserialize)]
struct ControlLineFixture {
    vectors: Vec<serde_json::Value>,
}

mod control_vectors;
mod malformed;
