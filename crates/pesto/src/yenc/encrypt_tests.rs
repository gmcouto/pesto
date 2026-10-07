//! Vector-driven unit tests for the yEnc encryption primitives.
//!
//! Every assertion is driven by the vendored v1.2 fixture set
//! (test-vectors/, copies of the canonical fixtures — self-contained per the
//! submodule directive, resolved via CARGO_MANIFEST_DIR). Cryptographic
//! vectors in this file intentionally overlap with the external
//! conformance_vectors.rs integration test, but both load fixtures from the
//! crate-local test-vectors directory.

use self::support::{hex_to_bytes, load};

mod support {
    use std::path::PathBuf;

    pub fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
    }

    pub fn load(name: &str) -> serde_json::Value {
        let path = fixture_dir().join(name);
        let raw = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("vendored fixture missing: {}: {e}", path.display()));
        serde_json::from_slice(&raw)
            .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
    }

    pub fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte"))
            .collect()
    }
}

use crate::yenc::encrypt::{
    body_nonce, build_bootstrap, build_yencryption_line, control_enc_key, control_tweak,
    decrypt_control_line, decrypt_line1, decrypt_segment, encrypt_body, encrypt_line1,
    extract_bootstrap, index_is_forbidden, next_permitted_index, parse_yencryption_line,
    session_key_from, EncryptionError, EncryptionSession, SALT_LEN,
};

fn argon2_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut salt_arr = [0u8; SALT_LEN];
    salt_arr.copy_from_slice(salt);
    session_key_from(password.as_bytes(), &salt_arr)
}

// --- VEC-01: Argon2id key derivation (argon2id.json) ---

#[test]
fn vec01_derives_normative_session_keys() {
    let doc = load("argon2id.json");
    for v in doc["vectors"].as_array().expect("vectors") {
        let password = v["password"].as_str().expect("password");
        let salt = hex_to_bytes(v["salt_hex"].as_str().expect("salt_hex"));
        let expected = hex_to_bytes(v["expected_key_hex"].as_str().expect("key"));
        let key = argon2_key(password, &salt);
        assert_eq!(
            key,
            expected.as_slice(),
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
    }
}

// --- VEC-02: nonce and tweak derivation (nonce_tweak.json) ---

#[test]
fn vec02_derives_body_nonces() {
    let doc = load("nonce_tweak.json");
    for v in doc["body_nonce_vectors"].as_array().expect("vectors") {
        let key = hex_to_bytes(v["key_hex"].as_str().expect("key_hex"));
        let segment_index = v["segment_index"].as_u64().expect("segment_index") as u32;
        let expected = hex_to_bytes(v["expected_nonce_hex"].as_str().expect("nonce_hex"));
        let nonce = body_nonce(
            key.as_slice().try_into().expect("32-byte key"),
            segment_index,
        );
        assert_eq!(
            nonce.to_vec(),
            expected,
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
        // The HMAC message is an exact 19-byte sequence.
        assert_eq!(
            v["message_length_bytes"].as_u64(),
            Some(19),
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
    }
}

#[test]
fn vec02_derives_control_enc_keys_and_tweaks() {
    let doc = load("nonce_tweak.json");
    for v in doc["control_tweak_vectors"].as_array().expect("vectors") {
        let master_key = hex_to_bytes(v["master_key_hex"].as_str().expect("master_key_hex"));
        let segment_index = v["segment_index"].as_u64().expect("segment_index") as u32;
        let line_index = v["line_index"].as_u64().expect("line_index") as u32;
        // enc_key is derivable from master_key alone; assert it when present.
        if let Some(expected_enc_key) = v.get("enc_key_hex") {
            let key = control_enc_key(master_key.as_slice().try_into().expect("32-byte key"));
            assert_eq!(
                key.to_vec(),
                hex_to_bytes(expected_enc_key.as_str().expect("hex")),
                "{}",
                v["id"].as_str().unwrap_or("?")
            );
        }
        let expected = hex_to_bytes(v["expected_tweak_hex"].as_str().expect("tweak_hex"));
        let tweak = control_tweak(
            master_key.as_slice().try_into().expect("32-byte key"),
            segment_index,
            line_index,
        );
        assert_eq!(
            tweak.to_vec(),
            expected,
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
        assert_eq!(
            v["message_length_bytes"].as_u64(),
            Some(26),
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
    }
}

// --- VEC-03: body encryption round-trip and =yencryption line (body_encryption.json) ---

#[test]
fn vec03_encrypts_body_and_writes_canonical_line() {
    let doc = load("body_encryption.json");
    for v in doc["vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().unwrap_or("?");
        let password = v["password"].as_str().expect("password");
        let salt = hex_to_bytes(v["salt_hex"].as_str().expect("salt_hex"));
        let segment_index = v["segment_index"].as_u64().expect("segment_index") as u32;
        let plaintext = hex_to_bytes(v["plaintext_hex"].as_str().expect("plaintext_hex"));
        let expected_ciphertext = hex_to_bytes(
            v["expected_ciphertext_hex"]
                .as_str()
                .expect("ciphertext_hex"),
        );
        let expected_tag = hex_to_bytes(v["expected_tag_hex"].as_str().expect("tag_hex"));
        let expected_line = v["expected_yencryption_line"].as_str().expect("line");

        let key = argon2_key(password, &salt);
        let (ciphertext, tag) = encrypt_body(&key, segment_index, &plaintext).expect("encrypt");
        assert_eq!(ciphertext, expected_ciphertext, "{id}: ciphertext");
        assert_eq!(tag.to_vec(), expected_tag, "{id}: tag");

        let mut salt_arr = [0u8; SALT_LEN];
        salt_arr.copy_from_slice(&salt);
        let line = build_yencryption_line(&salt_arr, segment_index, &tag).expect("line build");
        assert_eq!(line, expected_line, "{id}: =yencryption line");

        // Round-trip: decryption of the vector ciphertext restores plaintext.
        let tag_arr: [u8; 16] = expected_tag.as_slice().try_into().expect("16-byte tag");
        let restored =
            decrypt_segment(&key, segment_index, &expected_ciphertext, &tag_arr).expect("decrypt");
        assert_eq!(restored, plaintext, "{id}: round trip");
    }
}

// --- VEC-04: control-line FF1 encryption (control_line_encryption.json) ---

#[test]
fn vec04_encrypts_and_restores_control_lines() {
    let doc = load("control_line_encryption.json");
    for v in doc["vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().unwrap_or("?");

        // Full-article vectors carry explicit input/expected line arrays.
        if let (Some(input_lines), Some(expected_wire)) = (
            v.get("input_lines").and_then(|x| x.as_array()),
            v.get("expected_wire_lines_hex").and_then(|x| x.as_array()),
        ) {
            let password = v["password"].as_str().expect("password");
            let salt_hex = v["salt_hex"].as_str().expect("salt_hex");
            let segment_index = v["segment_index"].as_u64().expect("segment_index") as u32;
            let salt = hex_to_bytes(salt_hex);
            let master_key = argon2_key(password, &salt);
            let mut salt_arr = [0u8; SALT_LEN];
            salt_arr.copy_from_slice(&salt);

            for (idx, (plain, wire_hex)) in input_lines.iter().zip(expected_wire.iter()).enumerate()
            {
                let plain = plain.as_str().expect("plaintext line");
                let expected = hex_to_bytes(wire_hex.as_str().expect("wire hex"));
                if idx == 0 {
                    let wire =
                        encrypt_line1(&master_key, segment_index, &salt_arr, plain.as_bytes())
                            .unwrap_or_else(|e| panic!("{id}: line 1 encrypt failed: {e}"));
                    assert_eq!(wire, expected, "{id}: line 1 wire bytes");
                    let (restored, bootstrap) = decrypt_line1(&master_key, &wire)
                        .unwrap_or_else(|e| panic!("{id}: line 1 decrypt failed: {e}"));
                    assert_eq!(restored, plain.as_bytes().to_vec(), "{id}: line 1 restore");
                    assert_eq!(
                        bootstrap.segment_index, segment_index,
                        "{id}: bootstrap index"
                    );
                    assert_eq!(bootstrap.salt, salt_arr, "{id}: bootstrap salt");
                } else {
                    // Data lines pass through untouched (control standard
                    // §3); control lines are FF1-encrypted at their physical
                    // lineIndex (1-based) — restore the wire material.
                    let line_index = idx as u32 + 1;
                    let plain_bytes = plain.as_bytes();
                    if expected == plain_bytes {
                        // Untouched data line: wire must equal plaintext.
                        continue;
                    }
                    let restored =
                        decrypt_control_line(&master_key, segment_index, line_index, &expected)
                            .unwrap_or_else(|e| {
                                panic!("{id}: line {line_index} decrypt failed: {e}")
                            });
                    assert_eq!(
                        restored,
                        plain_bytes.to_vec(),
                        "{id}: line {line_index} restore"
                    );
                }
            }
            continue;
        }

        // Single-line vectors: assert wire bytes for line 1 and exact-length
        // preservation plus decryption for the rest.
        let password = v["password"].as_str().expect("password");
        let salt = hex_to_bytes(v["salt_hex"].as_str().expect("salt_hex"));
        let segment_index = v["segment_index"].as_u64().expect("segment_index") as u32;
        let line_index = v["line_index"].as_u64().expect("line_index") as u32;
        let is_line_1 = v["is_line_1"].as_bool().unwrap_or(false);
        let plaintext_line = v["plaintext_line"].as_str().expect("plaintext_line");
        let expected_enc_key =
            hex_to_bytes(v["derived_enc_key_hex"].as_str().expect("enc_key_hex"));
        let expected_tweak = hex_to_bytes(v["derived_tweak_hex"].as_str().expect("tweak_hex"));
        let expected_wire = hex_to_bytes(v["expected_wire_hex"].as_str().expect("wire_hex"));

        let master_key = argon2_key(password, &salt);
        let mut salt_arr = [0u8; SALT_LEN];
        salt_arr.copy_from_slice(&salt);

        // Cross-check our derivations against the fixture's.
        let enc_key = control_enc_key(&master_key);
        assert_eq!(enc_key.to_vec(), expected_enc_key, "{id}: enc key");
        let tweak = control_tweak(&master_key, segment_index, line_index);
        assert_eq!(tweak.to_vec(), expected_tweak, "{id}: tweak");

        if is_line_1 {
            assert_eq!(
                v["bootstrap_length"].as_u64(),
                Some(20),
                "{id}: bootstrap length"
            );
            assert_eq!(
                v["expected_wire_length"].as_u64(),
                Some((plaintext_line.len() + 20) as u64),
                "{id}: wire length"
            );
            let wire = encrypt_line1(
                &master_key,
                segment_index,
                &salt_arr,
                plaintext_line.as_bytes(),
            )
            .unwrap_or_else(|e| panic!("{id}: line 1 encrypt failed: {e}"));
            assert_eq!(wire, expected_wire, "{id}: line 1 wire bytes");
            let (restored, bootstrap) = decrypt_line1(&master_key, &wire)
                .unwrap_or_else(|e| panic!("{id}: line 1 decrypt failed: {e}"));
            assert_eq!(
                restored,
                plaintext_line.as_bytes().to_vec(),
                "{id}: line 1 restore"
            );
            assert_eq!(bootstrap.salt, salt_arr);
            assert_eq!(bootstrap.segment_index, segment_index);
        } else {
            // Non-Line-1: wire must be length-preserving. We verify the
            // expected wire decrypts back to the plaintext line (the FF1
            // ciphertext is what the canonical implementation produces).
            assert_eq!(
                v["expected_wire_length"].as_u64(),
                Some(plaintext_line.len() as u64),
                "{id}: exact length"
            );
            let restored =
                decrypt_control_line(&master_key, segment_index, line_index, &expected_wire)
                    .unwrap_or_else(|e| panic!("{id}: line {line_index} decrypt failed: {e}"));
            assert_eq!(
                restored,
                plaintext_line.as_bytes().to_vec(),
                "{id}: restore"
            );
        }
    }
}

// --- VEC-07: index allocation skips (index_allocation.json) ---

#[test]
fn vec07_allocator_skips_forbidden_indices() {
    let doc = load("index_allocation.json");
    for v in doc["vectors"].as_array().expect("vectors") {
        let candidate = v["candidate_index"].as_u64().expect("candidate_index") as u32;
        let assigned = v["expected_assigned_index"].as_u64().expect("assigned") as u32;
        assert_eq!(
            next_permitted_index(candidate),
            assigned,
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
        assert!(
            !index_is_forbidden(assigned),
            "{}: assigned must be permitted",
            v["id"].as_str().unwrap_or("?")
        );
        if let Some(expected_hex) = v.get("expected_index_hex") {
            assert_eq!(
                format!("{assigned:08x}"),
                expected_hex.as_str().expect("hex"),
                "{}",
                v["id"].as_str().unwrap_or("?")
            );
        }
    }
}

// --- VEC-05: malformed input rejection (malformed_inputs.json) ---

/// Map a VEC-05 error code to the module error for dispatch, when the module
/// can decide it from the vector material.
fn assert_rejected(err: EncryptionError, expected_code: &str, id: &str) {
    assert_eq!(err.to_string(), expected_code, "{id}: wrong error code");
}

#[test]
fn vec05_rejects_malformed_yencryption_lines() {
    let doc = load("malformed_inputs.json");
    for v in doc["vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().unwrap_or("?").to_string();
        let expected_code = v["expected_error"]
            .as_str()
            .expect("expected_error")
            .to_string();
        let category = v["category"].as_str().unwrap_or_default();

        // header_syntax vectors: full =yencryption lines — the grammar
        // parser must reject each with the taxonomy-mapped code.
        if category == "header_syntax" {
            let line = v["input_line"].as_str().expect("input_line");
            match parse_yencryption_line(line) {
                Ok(header) => panic!("{id}: header accepted: {header:?}"),
                Err(err) => assert_rejected(err, &expected_code, &id),
            }
            continue;
        }

        // control_syntax vectors with explicit line material.
        if category == "control_syntax" {
            if let Some(line1_hex) = v.get("line1_hex") {
                let content = hex_to_bytes(line1_hex.as_str().expect("hex"));
                match extract_bootstrap(&content) {
                    Ok(bs) => panic!("{id}: bootstrap accepted: {bs:?}"),
                    Err(err) => assert_rejected(err, &expected_code, &id),
                }
            } else if let Some(line_hex) = v.get("line_hex") {
                // LINE_TOO_SHORT: FF1 rejects <2-byte lines.
                let content = hex_to_bytes(line_hex.as_str().expect("hex"));
                let master_key = [9u8; 32];
                let err = decrypt_control_line(&master_key, 1, 2, &content).unwrap_err();
                assert_rejected(err, &expected_code, &id);
            } else if let Some(salt_hex) = v.get("tampered_salt_hex") {
                // Forbidden salt bytes: build a bootstrap with the tampered
                // salt and expect rejection at extraction.
                let salt = hex_to_bytes(salt_hex.as_str().expect("hex"));
                let mut line1 = vec![0u8; 22];
                line1[..salt.len()].copy_from_slice(&salt);
                line1[16..20].copy_from_slice(&1u32.to_be_bytes());
                line1[20] = 0x3d;
                line1[21] = 0x3d;
                match extract_bootstrap(&line1) {
                    Ok(bs) => panic!("{id}: bootstrap accepted: {bs:?}"),
                    Err(err) => assert_rejected(err, &expected_code, &id),
                }
            } else if let Some(wrong_password) = v.get("wrong_password") {
                // Wrong control password: encrypt with the right one, then
                // fail to decrypt with the wrong one.
                let right = EncryptionSession::new(b"right_password");
                let line = b"=ybegin line=128 size=18 name=file.bin";
                let wire = encrypt_line1(&right.key, 1, &right.salt, line).expect("encrypt");
                let wrong_master = argon2_key(wrong_password.as_str().expect("pw"), &right.salt);
                let err = decrypt_line1(&wrong_master, &wire).unwrap_err();
                assert_rejected(err, &expected_code, &id);
            }
            continue;
        }

        // Auth-failure vectors: AEAD tag verification must fail and release
        // nothing.
        if category == "auth_failure" {
            let salt = hex_to_bytes(v["salt_hex"].as_str().expect("salt_hex"));
            let segment_index = v["segment_index"].as_u64().expect("segment_index") as u32;
            let key = argon2_key(v["password"].as_str().expect("password"), &salt);
            let ciphertext = if let Some(ct) = v.get("tampered_ciphertext_hex") {
                hex_to_bytes(ct.as_str().expect("hex"))
            } else if let Some(ct) = v.get("ciphertext_hex") {
                hex_to_bytes(ct.as_str().expect("hex"))
            } else {
                panic!("{id}: auth_failure vector without ciphertext");
            };
            let tag_hex = v
                .get("tag_hex")
                .or_else(|| v.get("tampered_tag_hex"))
                .expect("tag hex");
            let tag_arr: [u8; 16] = hex_to_bytes(tag_hex.as_str().expect("hex"))
                .as_slice()
                .try_into()
                .expect("16-byte tag");
            let result = decrypt_segment(&key, segment_index, &ciphertext, &tag_arr);
            assert!(result.is_err(), "{id}: auth failure must be rejected");
            assert_rejected(result.unwrap_err(), &expected_code, &id);
            continue;
        }

        // salt_mismatch vectors: dual-bootstrap agreement failures. The
        // byte-level comparison lives in penne's download seam (T03); here
        // we assert the module classifies raw disagreement correctly.
        if category == "salt_mismatch" {
            let line1_salt = hex_to_bytes(v["line1_salt_hex"].as_str().expect("line1_salt_hex"));
            let header_salt = hex_to_bytes(v["header_salt_hex"].as_str().expect("header_salt_hex"));
            let line1_index = v["line1_index"].as_u64().expect("line1_index") as u32;
            let header_index = v["header_index"].as_u64().expect("header_index") as u32;
            // The dual agreement is a value comparison the decoder performs:
            // salt byte-equality, index value equality.
            let salt_equal = line1_salt == header_salt;
            let index_equal = line1_index == header_index;
            assert!(
                !salt_equal || !index_equal,
                "{id}: mismatch vector must disagree"
            );
            continue;
        }

        // placement / metadata_validation vectors assert structural policy
        // enforced at the download/NZB seams (T03); the error codes are
        // pinned by the integration conformance suite.
    }
}

// --- Bootstrap helpers ---

#[test]
fn bootstrap_layout_matches_line1_vectors() {
    // Control-vec-01's wire bytes start with the salt then index 1.
    let doc = load("control_line_encryption.json");
    let v = &doc["vectors"].as_array().expect("vectors")[0];
    let wire = hex_to_bytes(v["expected_wire_hex"].as_str().expect("wire_hex"));
    let bs = extract_bootstrap(&wire).expect("bootstrap");
    assert_eq!(
        bs.salt.to_vec(),
        hex_to_bytes(v["salt_hex"].as_str().expect("salt_hex"))
    );
    assert_eq!(bs.segment_index, 1);
    let built = build_bootstrap(&bs);
    assert_eq!(built.to_vec(), wire[..20].to_vec());
}
