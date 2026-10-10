use hmac::Mac;
use proptest::prelude::*;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

use super::adapter::{
    extract_and_remove_yencryption, parse_yencryption_line, DownloadDecryptionAdapter,
    UploadEncryptionAdapter,
};
use super::body::{decrypt_body, encrypt_body};
use super::control::{self, extract_salt_from_line1, ff1_decrypt_line, ff1_encrypt_line};
use super::kdf::EncryptionSession;
use crate::poster::SegmentIdentity;
use crate::yenc::{self, PartSpec};

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
    plaintext_hex: String,
    expected_ciphertext_hex: String,
    #[serde(default)]
    expected_index_hex: Option<String>,
    expected_tag_hex: String,
    #[serde(default)]
    expected_yencryption_line: Option<String>,
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
        let (ct, tag) = encrypt_body(&plaintext, session.master_key(), &nonce)
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
        let decrypted = decrypt_body(&ct, &tag, session.master_key(), &nonce)
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

#[test]
fn test_control_line_encryption_test_vectors() {
    let path = test_vectors_dir().join("control_line_encryption.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let fixture: ControlLineFixture = serde_json::from_str(&content).unwrap();

    for vec in &fixture.vectors {
        let id = vec["id"].as_str().unwrap();

        if let Some(plaintext_line) = vec.get("plaintext_line").and_then(|v| v.as_str()) {
            let enc_key_bytes = hex_decode(vec["derived_enc_key_hex"].as_str().unwrap());
            let mut enc_key = [0u8; 32];
            enc_key.copy_from_slice(&enc_key_bytes);

            let tweak_bytes = hex_decode(vec["derived_tweak_hex"].as_str().unwrap());
            let mut tweak = [0u8; 8];
            tweak.copy_from_slice(&tweak_bytes);

            let pt_bytes = plaintext_line.as_bytes();
            let ct_bytes = ff1_encrypt_line(&enc_key, &tweak, pt_bytes)
                .unwrap_or_else(|e| panic!("ff1 encrypt failed for vector {id}: {e}"));

            let is_line_1 = vec["is_line_1"].as_bool().unwrap_or(false);
            let wire_bytes = if is_line_1 {
                let expected_wire = hex_decode(vec["expected_wire_hex"].as_str().unwrap());
                let bootstrap = &expected_wire[0..control::BOOTSTRAP_PREFIX_LEN];
                [bootstrap, &ct_bytes].concat()
            } else {
                ct_bytes.clone()
            };

            let expected_wire_hex = vec["expected_wire_hex"].as_str().unwrap();
            assert_eq!(
                hex_encode(&wire_bytes),
                expected_wire_hex,
                "control line wire mismatch for vector {id}"
            );

            // Decrypt
            let restored_pt = ff1_decrypt_line(&enc_key, &tweak, &ct_bytes)
                .unwrap_or_else(|e| panic!("ff1 decrypt failed for vector {id}: {e}"));
            assert_eq!(
                restored_pt, pt_bytes,
                "control line roundtrip mismatch for vector {id}"
            );
        } else if let Some(input_lines_val) = vec.get("input_lines").and_then(|v| v.as_array()) {
            let lines: Vec<&str> = input_lines_val
                .iter()
                .map(|l| l.as_str().unwrap())
                .collect();
            let expected_wire_hexes: Vec<&str> = vec["expected_wire_lines_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h.as_str().unwrap())
                .collect();

            let password = vec
                .get("transport_kdf_input")
                .or_else(|| vec.get("password"))
                .unwrap()
                .as_str()
                .unwrap();
            let salt_bytes = hex_decode(vec["salt_hex"].as_str().unwrap());
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&salt_bytes);
            let session = EncryptionSession::new(password, salt).unwrap();
            let segment_index = vec["segment_index"].as_u64().unwrap() as u32;

            let joined = lines.join("\r\n") + "\r\n";
            let encrypted_wire =
                control::encrypt_yenc_control_lines(&session, segment_index, joined.as_bytes())
                    .unwrap_or_else(|e| panic!("encrypt_yenc_control_lines failed for {id}: {e}"));

            let split_wire = control::split_lines_preserving_endings(&encrypted_wire);
            assert_eq!(
                split_wire.len(),
                expected_wire_hexes.len(),
                "line count mismatch for {id}"
            );
            for (actual, expected_hex) in split_wire.iter().zip(&expected_wire_hexes) {
                assert_eq!(
                    hex_encode(actual.content),
                    *expected_hex,
                    "wire line hex mismatch in {id}"
                );
            }

            let decrypted =
                control::decrypt_yenc_control_lines(&session, segment_index, &encrypted_wire)
                    .unwrap_or_else(|e| panic!("decrypt_yenc_control_lines failed for {id}: {e}"));
            assert_eq!(
                decrypted,
                joined.as_bytes(),
                "full article roundtrip failed for {id}"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn control_line_roundtrip_preserves_framing_for_arbitrary_session_identity(
        password in "[ -~]{1,32}",
        salt_numerals in prop::array::uniform16(0u16..253),
        // CR-02: the round-trip must exercise only wire-safe indices (the
        // uploader allocator never assigns forbidden ones); arbitrary u32
        // values including forbidden indices are rejected at the bootstrap.
        segment_index in (1u32..=200u32)
            .prop_filter("segment_index must be CR-02-safe", |i| {
                i.to_be_bytes().iter().all(|&b| b != 0x0A && b != 0x0D)
            }),
        name in "[A-Za-z0-9._-]{1,48}",
        payload in prop::collection::vec(any::<u8>(), 0..512),
        line_len in 1usize..129,
    ) {
        let mut salt = [0u8; 16];
        for (byte, numeral) in salt.iter_mut().zip(salt_numerals) {
            *byte = control::numeral_to_byte(numeral).unwrap();
        }
        let session = EncryptionSession::new(&password, salt).unwrap();
        let mut yenc = Vec::new();
        let spec = PartSpec {
            number: 1,
            total: 2,
            offset: 0,
        };
        let encoded = crate::yenc::encode_part_into(
            &name,
            payload.len().max(1) as u64,
            spec,
            &payload,
            line_len,
            None,
            &mut yenc,
        );
        let insertion = encoded.body
            .windows(7)
            .position(|window| window == b"\n=ypart")
            .map(|position| position + 1)
            .unwrap();
        let insertion = insertion
            + encoded.body[insertion..]
                .iter()
                .position(|&byte| byte == b'\n')
                .unwrap()
            + 1;
        let encryption_line = format!(
            "=yencryption cipher=XChaCha20-Poly1305 salt={} tag=00000000000000000000000000000000\r\n",
            hex_encode(&salt),
        );
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&encoded.body[..insertion]);
        plaintext.extend_from_slice(encryption_line.as_bytes());
        plaintext.extend_from_slice(&encoded.body[insertion..]);

        let wire = control::encrypt_yenc_control_lines(&session, segment_index, &plaintext).unwrap();
        let restored = control::decrypt_yenc_control_lines(&session, segment_index, &wire).unwrap();

        prop_assert_eq!(restored, plaintext);
    }
}

#[derive(Deserialize)]
struct MalformedFixture {
    vectors: Vec<serde_json::Value>,
}

#[test]
fn test_malformed_inputs_rejection() {
    let path = test_vectors_dir().join("malformed_inputs.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let fixture: MalformedFixture = serde_json::from_str(&content).unwrap();

    for vec in &fixture.vectors {
        let id = vec["id"].as_str().unwrap();
        let category = vec["category"].as_str().unwrap();
        let expected_err = vec["expected_error"].as_str().unwrap();

        match category {
            "header_syntax" => {
                let input_line = vec["input_line"].as_str().unwrap();
                let res = parse_yencryption_line(input_line.as_bytes());
                assert!(
                    res.is_err(),
                    "vector {id} expected error {expected_err}, but passed"
                );
                let err_msg = res.unwrap_err().to_string();
                assert!(
                    err_msg.contains(expected_err),
                    "vector {id} error message '{err_msg}' should contain '{expected_err}'"
                );
            }
            "auth_failure" => {
                let password = vec
                    .get("transport_kdf_input")
                    .or_else(|| vec.get("password"))
                    .unwrap()
                    .as_str()
                    .unwrap();
                let salt_bytes = hex_decode(vec["salt_hex"].as_str().unwrap());
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&salt_bytes);
                let session = EncryptionSession::new(password, salt).unwrap();

                let ct_hex = vec
                    .get("tampered_ciphertext_hex")
                    .or_else(|| vec.get("ciphertext_hex"))
                    .unwrap()
                    .as_str()
                    .unwrap();
                let ct = hex_decode(ct_hex);

                let tag_hex = vec
                    .get("tampered_tag_hex")
                    .or_else(|| vec.get("tag_hex"))
                    .unwrap()
                    .as_str()
                    .unwrap();
                let tag_bytes = hex_decode(tag_hex);
                let mut tag = [0u8; 16];
                tag.copy_from_slice(&tag_bytes);

                let segment_index = vec["segment_index"].as_u64().unwrap() as u32;
                let nonce = session.derive_body_nonce(segment_index);

                let res = decrypt_body(&ct, &tag, session.master_key(), &nonce);
                assert!(
                    res.is_err(),
                    "vector {id} expected error {expected_err}, but passed"
                );
            }
            "control_syntax" => {
                if let Some(salt_hex) = vec.get("tampered_salt_hex").and_then(|v| v.as_str()) {
                    let salt_bytes = hex_decode(salt_hex);
                    // construct a line1 with 16-byte salt + minimal content
                    let line1 = [salt_bytes.as_slice(), b"=ybegin line=128 size=18"].concat();
                    let res = extract_salt_from_line1(&line1);
                    assert!(res.is_err(), "vector {id} expected error {expected_err}");
                    let err_msg = res.unwrap_err().to_string();
                    assert!(
                        err_msg.contains(expected_err),
                        "vector {id} error '{err_msg}' should contain '{expected_err}'"
                    );
                } else if let Some(line_hex) = vec.get("line_hex").and_then(|v| v.as_str()) {
                    let bytes = hex_decode(line_hex);
                    let dummy_key = [1u8; 32];
                    let dummy_tweak = [2u8; 8];
                    let res = ff1_encrypt_line(&dummy_key, &dummy_tweak, &bytes);
                    assert!(res.is_err(), "vector {id} expected error {expected_err}");
                    let err_msg = res.unwrap_err().to_string();
                    assert!(
                        err_msg.contains(expected_err),
                        "vector {id} error '{err_msg}' should contain '{expected_err}'"
                    );
                } else if let Some(line1_hex) = vec.get("line1_hex").and_then(|v| v.as_str()) {
                    let bytes = hex_decode(line1_hex);
                    let res = extract_salt_from_line1(&bytes);
                    assert!(res.is_err(), "vector {id} expected error {expected_err}");
                    let err_msg = res.unwrap_err().to_string();
                    assert!(
                        err_msg.contains(expected_err),
                        "vector {id} error '{err_msg}' should contain '{expected_err}'"
                    );
                } else if let Some(wrong_pwd) = vec.get("wrong_password").and_then(|v| v.as_str()) {
                    // Try to decrypt with wrong password
                    let salt = [0x42u8; 16];
                    let correct_session = EncryptionSession::new("test123", salt).unwrap();
                    let wrong_session = EncryptionSession::new(wrong_pwd, salt).unwrap();
                    let input = b"=ybegin line=128 size=18 name=file.bin\r\n=yend size=18\r\n";
                    let wire =
                        control::encrypt_yenc_control_lines(&correct_session, 1, input).unwrap();
                    let res = control::decrypt_yenc_control_lines(&wrong_session, 1, &wire);
                    assert!(res.is_err(), "vector {id} expected error {expected_err}");
                    let err_msg = res.unwrap_err().to_string();
                    assert!(
                        err_msg.contains(expected_err),
                        "vector {id} error '{err_msg}' should contain '{expected_err}'"
                    );
                }
            }
            "salt_mismatch" => {
                let line1_salt_bytes = hex_decode(vec["line1_salt_hex"].as_str().unwrap());
                let header_salt_hex = vec["header_salt_hex"].as_str().unwrap();
                let line1_idx = vec["line1_index"].as_u64().unwrap() as u32;
                let header_idx = vec["header_index"].as_u64().unwrap() as u32;

                let mut salt = [0u8; 16];
                salt.copy_from_slice(&line1_salt_bytes);
                let session = Arc::new(EncryptionSession::new("test123", salt).unwrap());
                let upload_adapter = UploadEncryptionAdapter::new(session.clone());

                let payload = b"Hello World Dual Bootstrap Test";
                let spec = PartSpec {
                    number: 1,
                    total: 1,
                    offset: 0,
                };
                let identity = SegmentIdentity::checked(0, 1, 1, line1_idx).unwrap();
                let mut body = Vec::new();
                let enc = upload_adapter
                    .encode_article(
                        "file.bin",
                        payload.len() as u64,
                        spec,
                        payload,
                        128,
                        None,
                        identity,
                        &mut body,
                    )
                    .unwrap();

                let restored =
                    control::decrypt_yenc_control_lines(&session, line1_idx, &enc.body).unwrap();
                let split = control::split_lines_preserving_endings(&restored);
                let mut modified = Vec::new();
                for line in split {
                    if line.content.starts_with(b"=yencryption") {
                        let new_header = format!(
                            "=yencryption cipher=XChaCha20-Poly1305 salt={} index={:08x} tag=ed70d238067735a20783df5e094ccafa",
                            header_salt_hex, header_idx
                        );
                        modified.extend_from_slice(new_header.as_bytes());
                        modified.extend_from_slice(line.ending);
                    } else {
                        modified.extend_from_slice(line.content);
                        modified.extend_from_slice(line.ending);
                    }
                }
                let re_enc =
                    control::encrypt_yenc_control_lines(&session, line1_idx, &modified).unwrap();

                let download_adapter = DownloadDecryptionAdapter::with_password("test123");
                let res = download_adapter.decode_article(&re_enc, None);
                assert!(res.is_err(), "vector {id} expected error {expected_err}");
                let err_msg = res.unwrap_err().to_string();
                assert!(
                    err_msg.contains(expected_err),
                    "vector {id} error '{err_msg}' should contain '{expected_err}'"
                );
            }
            _ => {}
        }
    }
}

#[test]
fn test_adapter_contracts() {
    let salt = [0x42u8; 16];
    let session = Arc::new(EncryptionSession::new("test-password-123", salt).unwrap());
    let upload_adapter = UploadEncryptionAdapter::new(session.clone());

    let payload = b"Hello, encrypted Usenet world! 1234567890";
    let spec = PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    };
    let identity = SegmentIdentity::checked(0, 1, 1, 1).unwrap();

    let mut body = Vec::new();
    let encoded = upload_adapter
        .encode_article(
            "test.bin",
            payload.len() as u64,
            spec,
            payload,
            128,
            None,
            identity,
            &mut body,
        )
        .expect("encode_article failed");

    assert!(!encoded.body.is_empty());
    // Control line 1 starts with 16-byte salt, so not with "=ybegin"
    assert!(!encoded.body.starts_with(b"=ybegin"));

    let download_adapter = DownloadDecryptionAdapter::new(Some(session));
    let decoded = download_adapter
        .decode_article(&encoded.body, Some(identity.segment_index))
        .expect("decode_article failed");

    assert_eq!(decoded.data, payload);
    assert_eq!(decoded.name, "test.bin");
    assert_eq!(decoded.file_size, payload.len() as u64);
}

#[test]
fn test_adapter_multipart_roundtrip() {
    let salt = [0x99u8; 16];
    let session = Arc::new(EncryptionSession::new("multi-part-password", salt).unwrap());
    let upload_adapter = UploadEncryptionAdapter::new(session.clone());

    let payload = vec![0xAB; 2048];
    let spec = PartSpec {
        number: 2,
        total: 5,
        offset: 1024,
    };
    let identity = SegmentIdentity::checked(0, 1, 5, 2).unwrap();

    let mut body = Vec::new();
    let encoded = upload_adapter
        .encode_article(
            "multi.bin",
            5120,
            spec,
            &payload,
            128,
            Some(0x12345678),
            identity,
            &mut body,
        )
        .expect("encode_article failed");

    assert_eq!(encoded.number, 2);
    assert_eq!(encoded.total, 5);

    let download_adapter = DownloadDecryptionAdapter::with_password("multi-part-password");
    let decoded = download_adapter
        .decode_article(&encoded.body, Some(identity.segment_index))
        .expect("decode_article failed");

    assert_eq!(decoded.data, payload);
    assert_eq!(decoded.name, "multi.bin");
    assert_eq!(decoded.part, 2);
    assert_eq!(decoded.total, 5);
    assert_eq!(decoded.file_size, 5120);
    assert_eq!(decoded.begin, 1025);
    assert_eq!(decoded.end, 3072);
}

#[test]
fn test_upload_adapter_encapsulation() {
    // 1. Unencrypted delegation (no adapter present)
    let payload = b"Plain unencrypted payload bytes 12345";
    let spec = PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    };
    let mut unencrypted_buf = Vec::new();
    let unencrypted_part = crate::yenc::encode_part_into(
        "plain.bin",
        payload.len() as u64,
        spec,
        payload,
        128,
        None,
        &mut unencrypted_buf,
    );
    assert!(unencrypted_part.body.starts_with(b"=ybegin"));
    assert!(!unencrypted_part
        .body
        .windows(13)
        .any(|w| w == b"=yencryption "));

    // Verify unencrypted decode
    let plain_decoded = crate::yenc::decode_part(&unencrypted_part.body).unwrap();
    assert_eq!(plain_decoded.data, payload);

    // Also verify DownloadDecryptionAdapter passes unencrypted articles through untouched
    let download_adapter_empty = DownloadDecryptionAdapter::new(None);
    let pass_through_decoded = download_adapter_empty
        .decode_article(&unencrypted_part.body, None)
        .expect("unencrypted article should decode transparently without session");
    assert_eq!(pass_through_decoded.data, payload);

    // 2. Encrypted delegation (adapter present)
    let salt = [0x55u8; 16];
    let session = Arc::new(EncryptionSession::new("encapsulation-test-pass", salt).unwrap());
    let adapter = UploadEncryptionAdapter::new(session.clone());
    let identity = SegmentIdentity::checked(0, 1, 1, 1).unwrap();

    let mut encrypted_buf = Vec::new();
    let encrypted_part = adapter
        .encode_article(
            "secret.bin",
            payload.len() as u64,
            spec,
            payload,
            128,
            None,
            identity,
            &mut encrypted_buf,
        )
        .expect("encrypted encode failed");

    // Must NOT start with =ybegin because line 1 has prepended salt and FF1 encryption
    assert!(!encrypted_part.body.starts_with(b"=ybegin"));
    // Payload on wire must be ciphertext, not plaintext
    assert!(!encrypted_part
        .body
        .windows(payload.len())
        .any(|w| w == payload));

    // 3. Transparent decryption recovers original plaintext
    let download_adapter = DownloadDecryptionAdapter::new(Some(session));
    let decrypted_part = download_adapter
        .decode_article(&encrypted_part.body, Some(identity.segment_index))
        .expect("transparent decryption failed");

    assert_eq!(decrypted_part.data, payload);
    assert_eq!(decrypted_part.name, "secret.bin");
}

#[test]
fn test_generate_alphabet_salt_properties() {
    for _ in 0..1000 {
        let salt = control::generate_alphabet_salt();
        for &b in &salt {
            assert!(b != 0x00 && b != 0x0A && b != 0x0D);
            assert!(control::byte_to_numeral(b).is_ok());
        }
        let mut line1 = Vec::new();
        line1.extend_from_slice(&salt);
        line1.extend_from_slice(b"=ybegin part=1\r\n");
        let extracted = extract_salt_from_line1(&line1).expect("extract salt should succeed");
        assert_eq!(extracted, salt);
    }
}

#[test]
fn test_adapter_strict_header_order() {
    let password = "strict-header-test-password";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let upload_adapter = UploadEncryptionAdapter::new(session.clone());

    // 1. Single-part article: line 1 = =ybegin, line 2 = =yencryption
    let payload = b"Strict single part header verification payload";
    let spec_single = PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    };
    let identity_single = SegmentIdentity::checked(0, 1, 1, 1).unwrap();
    let mut body_single = Vec::new();
    let enc_single = upload_adapter
        .encode_article(
            "single.bin",
            payload.len() as u64,
            spec_single,
            payload,
            128,
            None,
            identity_single,
            &mut body_single,
        )
        .unwrap();

    let download_adapter = DownloadDecryptionAdapter::with_password(password);
    let dec_single = download_adapter
        .decode_article(&enc_single.body, Some(identity_single.segment_index))
        .expect("single-part decode must succeed");
    assert_eq!(dec_single.data, payload);
    // CRC normalization recomputes part_crc32 over the authenticated plaintext
    // (Body Standard §10, recompute variant); file_crc32 stays cleared.
    assert_eq!(dec_single.part_crc32, Some(yenc::crc32(payload)));
    assert_eq!(dec_single.file_crc32, None);

    // 2. Multipart article: line 1 = =ybegin, line 2 = =ypart, line 3 = =yencryption
    let spec_multi = PartSpec {
        number: 1,
        total: 2,
        offset: 0,
    };
    let identity_multi = SegmentIdentity::checked(0, 1, 2, 1).unwrap();
    let mut body_multi = Vec::new();
    let enc_multi = upload_adapter
        .encode_article(
            "multi.bin",
            payload.len() as u64 * 2,
            spec_multi,
            payload,
            128,
            None,
            identity_multi,
            &mut body_multi,
        )
        .unwrap();

    let dec_multi = download_adapter
        .decode_article(&enc_multi.body, Some(identity_multi.segment_index))
        .expect("multi-part decode must succeed");
    assert_eq!(dec_multi.data, payload);
    assert_eq!(dec_multi.part_crc32, Some(yenc::crc32(payload)));
    assert_eq!(dec_multi.file_crc32, None);
}

#[test]
fn test_adapter_ciphertext_crc_validation() {
    let password = "crc-validation-test-password";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let upload_adapter = UploadEncryptionAdapter::new(session.clone());

    let payload = b"Ciphertext CRC validation payload 123456789";
    let spec = PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    };
    let identity = SegmentIdentity::checked(0, 1, 1, 1).unwrap();
    let mut body = Vec::new();
    let enc = upload_adapter
        .encode_article(
            "test.bin",
            payload.len() as u64,
            spec,
            payload,
            128,
            None,
            identity,
            &mut body,
        )
        .unwrap();

    // Decrypting the intact article works
    let download_adapter = DownloadDecryptionAdapter::with_password(password);
    let dec = download_adapter
        .decode_article(&enc.body, Some(identity.segment_index))
        .expect("intact article decodes");
    assert_eq!(dec.data, payload);
    // Recompute variant: part_crc32 now covers the authenticated plaintext
    // (never the discarded ciphertext wire CRC); file_crc32 stays cleared.
    assert_eq!(dec.part_crc32, Some(yenc::crc32(payload)));
    assert_eq!(dec.file_crc32, None);

    // Tamper with the =yend crc in the wire
    // Note: line 1, 2, and =yend are FF1 encrypted.
    // If we decrypt the control lines, tamper the yend crc, and re-encrypt, we can verify that ciphertext CRC mismatch fails before body decryption.
    let restored =
        control::decrypt_yenc_control_lines(&session, identity.segment_index, &enc.body).unwrap();
    let text = String::from_utf8_lossy(&restored);
    // Mutate the crc32= in =yend
    let tampered_text = if let Some(idx) = text.find("crc32=") {
        let mut t = text.into_owned();
        t.replace_range(idx + 6..idx + 7, "f");
        t
    } else {
        panic!("missing crc32 in yend");
    };
    let re_encrypted = control::encrypt_yenc_control_lines(
        &session,
        identity.segment_index,
        tampered_text.as_bytes(),
    )
    .unwrap();
    let err = download_adapter
        .decode_article(&re_encrypted, Some(identity.segment_index))
        .unwrap_err();
    assert!(
        err.to_string().contains("ciphertext CRC mismatch")
            || err.to_string().contains("CRC")
            || err.to_string().contains("crc")
    );
}

#[test]
fn test_adapter_malformed_headers_matrix() {
    // 1. Test parse_yencryption_line on various malformed lines
    let bad_cases = [
        ("=yencryption", "MISSING_CIPHER"),
        ("=yencryption cipher=AES-256-GCM salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa", "UNSUPPORTED_CIPHER"),
        ("=yencryption cipher=XChaCha20-Poly1305 tag=ed70d238067735a20783df5e094ccafa salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001", "REORDERED_HEADER"),
        ("=yencryption salt=1a2b3c4d5e6f7890abcdef1234567890 cipher=XChaCha20-Poly1305 index=00000001 tag=ed70d238067735a20783df5e094ccafa", "UNSUPPORTED_CIPHER"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1A2B3C4D5E6F7890ABCDEF1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa", "UPPERCASE_HEX"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ED70D238067735A20783DF5E094CCAFA", "UPPERCASE_HEX"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef12345678 index=00000001 tag=ed70d238067735a20783df5e094ccafa", "INVALID_SALT_LENGTH"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef123456789011 index=00000001 tag=ed70d238067735a20783df5e094ccafa", "INVALID_SALT_LENGTH"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094cca", "INVALID_TAG_LENGTH"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafaaa", "INVALID_TAG_LENGTH"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa extra=1", "INVALID_TOKEN_COUNT"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=ed70d238067735a20783df5e094ccafa", "INVALID_TOKEN_COUNT"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000000 tag=ed70d238067735a20783df5e094ccafa", "ZERO_SEGMENT_INDEX"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=0001 tag=ed70d238067735a20783df5e094ccafa", "INVALID_INDEX_LENGTH"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=000000001 tag=ed70d238067735a20783df5e094ccafa", "INVALID_INDEX_LENGTH"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=0000000g tag=ed70d238067735a20783df5e094ccafa", "INVALID_INDEX_HEX"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=0000000F tag=ed70d238067735a20783df5e094ccafa", "UPPERCASE_HEX"),
        ("=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=ed70d238067735a20783df5e094ccafa", "INVALID_TOKEN_COUNT"),
    ];

    for (line, expected_err) in bad_cases {
        let res = parse_yencryption_line(line.as_bytes());
        assert!(res.is_err(), "expected error for line: {line}");
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains(expected_err),
            "expected error containing '{expected_err}', got '{msg}' for line '{line}'"
        );
    }

    // 2. Misplaced and duplicate =yencryption in full article
    let article_duplicate = b"=ybegin line=128 size=4 name=test.bin\r\n=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa\r\ntest\r\n=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa\r\n=yend size=4 crc32=d87f7e0c\r\n".to_vec();
    let res_dup = extract_and_remove_yencryption(&article_duplicate);
    assert!(res_dup.is_err());
    assert!(res_dup
        .unwrap_err()
        .to_string()
        .contains("duplicate or misplaced"));

    // Multipart missing =ypart before =yencryption
    let article_bad_multipart = b"=ybegin part=1 total=2 line=128 size=8 name=test.bin\r\n=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa\r\n=ypart begin=1 end=4\r\ntest\r\n=yend size=4 part=1 pcrc32=d87f7e0c\r\n";
    let res_bad_mp = extract_and_remove_yencryption(article_bad_multipart);
    assert!(res_bad_mp.is_err());
}

#[test]
fn test_adapter_zero_output_rejection_matrix() {
    let password = "zero-output-rejection-password";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let upload_adapter = UploadEncryptionAdapter::new(session.clone());

    let payload = b"Zero output guarantee test payload 12345";
    let spec = PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    };
    let identity = SegmentIdentity::checked(0, 1, 1, 1).unwrap();
    let mut body = Vec::new();
    let enc = upload_adapter
        .encode_article(
            "test.bin",
            payload.len() as u64,
            spec,
            payload,
            128,
            None,
            identity,
            &mut body,
        )
        .unwrap();

    let download_adapter = Arc::new(DownloadDecryptionAdapter::with_password(password));

    // 1. Calling decode_article with None succeeds because article is self-describing
    let dec_none = download_adapter
        .decode_article(&enc.body, None)
        .expect("self-describing article decodes with None segment_index");
    assert_eq!(dec_none.data, payload);

    // 2. Caller segment index mismatch fails closed
    assert!(download_adapter.decode_article(&enc.body, Some(2)).is_err());

    // 3. Wrong password fails closed
    let wrong_password_adapter = DownloadDecryptionAdapter::with_password("wrong-password");
    assert!(wrong_password_adapter
        .decode_article(&enc.body, Some(identity.segment_index))
        .is_err());

    // 4. Truncated article body fails closed
    let half = &enc.body[..enc.body.len() / 2];
    assert!(download_adapter
        .decode_article(half, Some(identity.segment_index))
        .is_err());

    // 5. Salt mismatch between line 1 and =yencryption fails closed
    let restored =
        control::decrypt_yenc_control_lines(&session, identity.segment_index, &enc.body).unwrap();
    let text = String::from_utf8_lossy(&restored);
    if let Some(idx) = text.find("salt=") {
        let mut t = text.into_owned();
        // Change one char in salt
        let replacement = if &t[idx + 5..idx + 6] == "a" {
            "b"
        } else {
            "a"
        };
        t.replace_range(idx + 5..idx + 6, replacement);
        let re_enc =
            control::encrypt_yenc_control_lines(&session, identity.segment_index, t.as_bytes())
                .unwrap();
        let err = download_adapter
            .decode_article(&re_enc, Some(identity.segment_index))
            .unwrap_err();
        assert!(err.to_string().contains("salt mismatch"));
    }

    // 6. Concurrency & idempotency test
    let mut handles = Vec::new();
    for _ in 0..10 {
        let adapter_clone = download_adapter.clone();
        let wire = enc.body.clone();
        handles.push(std::thread::spawn(move || {
            let res = adapter_clone
                .decode_article(&wire, Some(identity.segment_index))
                .unwrap();
            assert_eq!(res.data, payload);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn truncated_wire_line1_is_not_split_on_stray_newline_bytes() {
    // C2-04 regression: an encrypted wire article whose total length is shorter
    // than the 20-byte bootstrap prefix must be treated as a single truncated
    // line 1, not split at a 0x0A byte that happens to fall inside the (absent)
    // prefix. Before the fix, `split_lines_preserving_endings` skipped the
    // prefix only when `input.len() >= BOOTSTRAP_PREFIX_LEN`, so a short
    // adversarial body containing an embedded LF fragmented into multiple
    // "lines" before `extract_bootstrap_from_line1` could see it.
    let mut short_wire = vec![0x41u8; 10];
    short_wire[4] = b'\n'; // stray LF inside the truncated prefix region
    short_wire[7] = b'\r';
    short_wire[8] = b'\n';

    let lines = control::split_lines_preserving_endings(&short_wire);
    assert_eq!(
        lines.len(),
        1,
        "short wire body must yield exactly one truncated line, got {} lines",
        lines.len()
    );
    assert_eq!(lines[0].content, &short_wire[..]);

    // The decoder surfaces the truncation as a clean LINE_TRUNCATED error.
    let err = control::extract_bootstrap_from_line1(lines[0].content).unwrap_err();
    assert!(
        err.to_string().contains("LINE_TRUNCATED"),
        "expected LINE_TRUNCATED, got: {err}"
    );
}

#[test]
fn bootstrap_extraction_rejects_forbidden_segment_index_bytes() {
    // CR-02 (Control Std §4/§8): indices 10, 13, 266 (0x0000010A), 269
    // (0x0000010D) contain 0x0A/0x0D in their big-endian encoding and are
    // rejected under FORBIDDEN_SEGMENT_INDEX_BYTE (maps to PROVIDER_FAILOVER).
    for idx in [10u32, 13, 266, 269] {
        let mut line1 = vec![0x41u8; 16]; // salt placeholder (no forbidden bytes)
        line1.extend_from_slice(&idx.to_be_bytes());
        line1.extend_from_slice(b"=="); // minimal trailer past the 22-byte minimum
        let err = control::extract_bootstrap_from_line1(&line1).unwrap_err();
        assert!(
            err.to_string().contains("FORBIDDEN_SEGMENT_INDEX_BYTE"),
            "index {idx} must be rejected with FORBIDDEN_SEGMENT_INDEX_BYTE, got: {err}"
        );
    }
    // Zero still rejected with its own token.
    let mut line1 = vec![0x41u8; 16];
    line1.extend_from_slice(&0u32.to_be_bytes());
    line1.extend_from_slice(b"==");
    let err = control::extract_bootstrap_from_line1(&line1).unwrap_err();
    assert!(err.to_string().contains("ZERO_SEGMENT_INDEX"), "got: {err}");

    // Neighboring safe indices still accepted.
    for idx in [9u32, 11, 12, 14, 265, 267, 268, 270] {
        let mut line1 = vec![0x41u8; 16];
        line1.extend_from_slice(&idx.to_be_bytes());
        line1.extend_from_slice(b"==");
        let (_, extracted) = control::extract_bootstrap_from_line1(&line1).unwrap();
        assert_eq!(extracted, idx);
    }
}

#[test]
fn yencryption_line_rejects_forbidden_segment_index_bytes() {
    // CR-02 (Control Std §4/§8; Body Std §4): `parse_yencryption_line` must
    // reject an `index=` whose big-endian encoding contains 0x0A/0x0D — same
    // rule the Line-1 bootstrap enforces — with a PROVIDER_FAILOVER
    // classification (retriable, matching `extract_bootstrap_from_line1`).
    for idx in [10u32, 13, 266, 269] {
        let line = format!(
            "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index={idx:08x} tag=ed70d238067735a20783df5e094ccafa"
        );
        assert_eq!(line.len(), 128, "test line for {idx} must be canonical");
        let err = parse_yencryption_line(line.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("FORBIDDEN_SEGMENT_INDEX_BYTE"),
            "index {idx} must be rejected with FORBIDDEN_SEGMENT_INDEX_BYTE, got: {err}"
        );
        let kind = crate::crypto::crypto_error_kind_of(&err)
            .expect("forbidden-byte rejection must carry a typed kind");
        assert_eq!(
            crate::crypto::CryptoErrorKind::ProviderFailover,
            kind,
            "index {idx} must be classified as retriable provider failover"
        );
    }
    // Neighboring safe indices still parse.
    for idx in [9u32, 11, 12, 14, 265, 267, 268, 270] {
        let line = format!(
            "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index={idx:08x} tag=ed70d238067735a20783df5e094ccafa"
        );
        let params = parse_yencryption_line(line.as_bytes())
            .unwrap_or_else(|e| panic!("index {idx} must parse, got: {e}"));
        assert_eq!(params.segment_index, idx);
    }
}

#[test]
fn yencryption_whitespace_strictness() {
    // T8 (v1.2 Control Std §3): strict single-SP grammar.
    let canonical =
        b"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa";
    assert_eq!(canonical.len(), 128, "canonical line must be 128 bytes");
    parse_yencryption_line(canonical).expect("canonical line must parse");

    // Tab separated (vector header-16-tab-separated)
    let tabbed =
        b"=yencryption\tcipher=XChaCha20-Poly1305\tsalt=1a2b3c4d5e6f7890abcdef1234567890\tindex=00000001\ttag=ed70d238067735a20783df5e094ccafa";
    let err = parse_yencryption_line(tabbed).unwrap_err();
    assert!(err.to_string().contains("INVALID_WHITESPACE"), "got: {err}");

    // Double space (vector header-17-double-space)
    let double_spaced =
        b"=yencryption  cipher=XChaCha20-Poly1305  salt=1a2b3c4d5e6f7890abcdef1234567890  index=00000001  tag=ed70d238067735a20783df5e094ccafa";
    let err = parse_yencryption_line(double_spaced).unwrap_err();
    assert!(err.to_string().contains("INVALID_WHITESPACE"), "got: {err}");

    // Trailing space before the final token boundary (append one more space
    // + re-trim a tag char: still single-SP separated but ends with space).
    let err = parse_yencryption_line(
        b"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccaf ",
    )
    .unwrap_err();
    assert!(err.to_string().contains("INVALID_WHITESPACE"), "got: {err}");

    // A canonical-looking line with a 6-char index hex (wrong total length,
    // 127 bytes) is rejected by the 128-byte assertion after field checks.
    let wrong_len = b"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=000001 tag=ed70d238067735a20783df5e094ccafa";
    let err = parse_yencryption_line(wrong_len).unwrap_err();
    assert!(
        err.to_string().contains("INVALID_LINE_LENGTH")
            || err.to_string().contains("INVALID_INDEX_LENGTH"),
        "got: {err}"
    );
}

#[test]
fn header_loop_ff1_error_fails_closed_not_passthrough() {
    // T7 (v1.2 Control Std §5 step 4): an FF1 decryption error on a line in
    // the expected-header region is PROVIDER_FAILOVER — it must never be
    // committed as a data line.
    let password = "fail-closed-header-loop";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let segment_index = 7u32;

    // Build a valid encrypted article, then corrupt line 2 (the =ypart line
    // region — for multipart, line 2 is a header line) so its FF1 decryption
    // fails.
    let payload = b"fail closed payload bytes";
    let uploader = UploadEncryptionAdapter::new(session.clone());
    let mut body = Vec::new();
    let encoded = uploader
        .encode_article(
            "fc.bin",
            payload.len() as u64,
            PartSpec {
                number: 1,
                total: 1,
                offset: 0,
            },
            payload,
            128,
            None,
            SegmentIdentity::explicit(1, 1, 1, segment_index).unwrap(),
            &mut body,
        )
        .unwrap();

    let lines: Vec<Vec<u8>> = control::split_lines_preserving_endings(&encoded.body)
        .into_iter()
        .map(|l| [l.content.to_vec(), l.ending.to_vec()].concat())
        .collect();
    assert!(lines.len() >= 3, "need header + data + footer");

    // Case A: line 2 carries a byte OUTSIDE the Radix-253 Alphabet (0x00) —
    // byte_to_numeral fails inside ff1_decrypt_line, a genuine FF1 error on
    // an expected-header line. Must bail PROVIDER_FAILOVER, never become a
    // data line.
    let mut case_a = lines.clone();
    let pos = case_a[1]
        .iter()
        .position(|&b| b != b'\r' && b != b'\n')
        .unwrap();
    case_a[1][pos] = 0x00;
    let err =
        control::decrypt_yenc_control_lines(&session, segment_index, &case_a.concat()).unwrap_err();
    // The kind is recoverable from the chain (envelope at the root) even
    // though the top-line Display shows the contextual message.
    use crate::crypto::crypto_error_kind_of;
    let kind = crypto_error_kind_of(&err).expect("FF1 error must carry a typed kind");
    assert_eq!(
        crate::crypto::CryptoErrorKind::ProviderFailover,
        kind,
        "out-of-Alphabet header byte must fail closed as PROVIDER_FAILOVER, got: {err:#}"
    );

    // Case B: a bit flip in the header ciphertext decrypts "successfully" to
    // garbage (FF1 is a permutation) — the probe treats it as the first data
    // line, but the restored block then lacks its =yencryption header, so the
    // ADAPTER fails closed and releases zero output.
    let mut case_b = lines.clone();
    let flip = case_b[1]
        .iter()
        .position(|&b| b != b'\r' && b != b'\n')
        .unwrap();
    case_b[1][flip] ^= 0x01;
    let corrupted = case_b.concat();
    let adapter = DownloadDecryptionAdapter::with_password(password);
    let res = adapter.decode_article(&corrupted, Some(segment_index));
    assert!(
        res.is_err(),
        "corrupted =yencryption header must fail closed"
    );
    let msg = res.unwrap_err().to_string();
    // Zero-output: the error must not carry the decrypted data line content.
    let data_line = &lines[2];
    let probe = &data_line[..data_line.len().min(16)];
    assert!(
        !msg.as_bytes().windows(probe.len()).any(|w| w == probe),
        "error must not leak passthrough data"
    );
}

#[test]
fn manifest_drift_check_vendored_vectors_match_canonical() {
    // T11 vendoring hygiene (nyuu malformed_inputs.js:84-90 pattern): every
    // vendored vector file's SHA-256 and vector count must match the
    // canonical manifest, byte-identically.
    let dir = test_vectors_dir();
    let manifest_text =
        std::fs::read_to_string(dir.join("manifest.json")).expect("manifest.json must be vendored");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).unwrap();
    assert_eq!(
        manifest["standard_version"].as_str().unwrap(),
        "1.2",
        "vendored manifest must track the canonical standard version"
    );
    let files = manifest["files"].as_object().expect("files map");
    assert!(
        files.contains_key("index_allocation.json"),
        "manifest must index the new index_allocation.json"
    );

    use sha2::Digest;
    for (name, entry) in files {
        let path = dir.join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("vendored {name} missing: {e}"));
        let digest = sha2::Sha256::digest(&bytes);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            entry["sha256"].as_str().unwrap(),
            "vendored {name} drifted from the canonical manifest"
        );
        let count_key = "vector_count";
        if let Some(expected_count) = entry[count_key].as_u64() {
            let doc: serde_json::Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{name} is not valid JSON: {e}"));
            let actual_count = doc["vectors"]
                .as_array()
                .map(|a| a.len() as u64)
                .or_else(|| {
                    // nonce_tweak.json has multiple top-level arrays; count
                    // body_nonce + control_tweak vectors together.
                    doc.as_object().map(|o| {
                        o.values()
                            .filter_map(|v| v.as_array().map(|a| a.len() as u64))
                            .sum()
                    })
                })
                .unwrap_or(0);
            if doc.get("vectors").is_some() {
                assert_eq!(
                    actual_count, expected_count,
                    "{name} vector count drifted from manifest"
                );
            }
        }
    }
}

#[test]
fn encrypted_segments_normalize_crc_metadata_regression() {
    // T4 regression (adapter.rs:449-465 precedent): after authentication and
    // decryption, DecodedPart must NOT carry the ciphertext wire CRC into any
    // verification path — the ciphertext `crc32=`/`pcrc32=` values are
    // discarded and part_crc32 is RECOMPUTED over the authenticated plaintext
    // (Body Standard §10, recompute variant); file_crc32 is None (the
    // whole-file CRC cannot be derived from a single segment).
    let password = "crc-clearing-regression";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let payload = b"ciphertext CRC must never leak into verification";
    let uploader = UploadEncryptionAdapter::new(session.clone());
    let mut body = Vec::new();
    let identity = SegmentIdentity::explicit(1, 1, 1, 1).unwrap();
    let encoded = uploader
        .encode_article(
            "crc.bin",
            payload.len() as u64,
            PartSpec {
                number: 1,
                total: 1,
                offset: 0,
            },
            payload,
            128,
            Some(0xDEADBEEF), // wire =yend carries a (ciphertext) file CRC
            identity,
            &mut body,
        )
        .unwrap();

    let decoded = DownloadDecryptionAdapter::with_password(password)
        .decode_article(&encoded.body, Some(identity.segment_index))
        .expect("authenticated decode must succeed");
    assert_eq!(
        decoded.part_crc32,
        Some(yenc::crc32(payload)),
        "part_crc32 must be recomputed over the authenticated plaintext (T4)"
    );
    assert!(
        decoded.file_crc32.is_none(),
        "file_crc32 must be None for encrypted segments (T4)"
    );
    assert_eq!(decoded.data, payload);
}
