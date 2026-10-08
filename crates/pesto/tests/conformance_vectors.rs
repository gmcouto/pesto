//! Conformance test over the vendored v1.2 fixture set (test-vectors/).
//!
//! These are byte-identical copies of the canonical fixtures from the
//! yenc-encryption-standards v1.2 repository, vendored per the submodule
//! self-containment directive — this test reads only files inside this
//! crate's own tree via CARGO_MANIFEST_DIR.
//!
//! Coverage (S02): fixture integrity (manifest sha256 sync), VEC-01
//! Argon2id session-key derivation, VEC-02 body-nonce/control-key/tweak
//! derivation, VEC-03 XChaCha20-Poly1305 ciphertext/tag and `=yencryption`
//! wire-line assertions with full encrypt->decrypt round-trips, VEC-04 FF1
//! control-line wire bytes (incl. the 20-byte Line-1 bootstrap), VEC-05
//! malformed-input rejection through the module's parse/decrypt seams, and
//! VEC-07 index-allocation skips via the module allocator, plus a yEnc
//! encode/decode round-trip of each body-encryption vector's plaintext
//! through the existing codec.

use std::path::PathBuf;

use pesto::yenc::encrypt::{
    body_nonce, build_yencryption_line, control_enc_key, control_tweak, decrypt_body,
    decrypt_control_line, decrypt_line1, decrypt_segment, encrypt_body, encrypt_control_line,
    encrypt_line1, extract_bootstrap, index_is_forbidden, next_permitted_index,
    parse_yencryption_line, session_key_from, EncryptionError, EncryptionSession,
    SegmentIndexAllocator, SALT_LEN,
};
use sha2::{Digest, Sha256};

/// Locate a vendored fixture. Integration tests run with CWD set to the
/// crate root, but resolve via CARGO_MANIFEST_DIR for robustness; the `../`
/// stays inside the pesto/ submodule (crates/<crate> -> crates/) and never
/// escapes it.
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

fn load(name: &str) -> serde_json::Value {
    let path = fixture_dir().join(name);
    let raw = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("vendored fixture missing: {}: {e}", path.display()));
    serde_json::from_slice(&raw)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

#[test]
fn manifest_sha256_sync() {
    let manifest = load("manifest.json");
    let files = manifest["files"]
        .as_object()
        .expect("manifest.files object");
    assert_eq!(
        manifest["standard_version"], "1.2",
        "fixture set must be v1.2"
    );
    assert_eq!(files.len(), 7, "v1.2 canonical set has 7 vector files");
    for (name, entry) in files {
        let expected = entry["sha256"].as_str().expect("sha256 string");
        let raw = std::fs::read(fixture_dir().join(name))
            .unwrap_or_else(|e| panic!("manifest lists {name} but it is missing: {e}"));
        let actual = hex(&Sha256::digest(&raw));
        assert_eq!(actual, expected, "sha256 drift for {name}");
    }
}

/// VEC-07: a candidate segmentIndex whose uint32 big-endian encoding
/// contains 0x0A or 0x0D is forbidden; the uploader must skip forward to the
/// next permitted index.
#[test]
fn index_allocation_skip_rules() {
    let doc = load("index_allocation.json");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert_eq!(doc["requirement"], "VEC-07");
    assert_eq!(vectors.len(), 4, "canonical VEC-07 set has 4 vectors");
    for v in vectors {
        let candidate = v["candidate_index"].as_u64().expect("candidate_index") as u32;
        let assigned = v["expected_assigned_index"].as_u64().expect("assigned") as u32;
        // By design (vector 04): candidate 269 is itself forbidden — the
        // uploader must never assign it — so only the *assigned* index is
        // required to be permitted.
        assert!(
            !forbidden(assigned),
            "{}: assigned {assigned} must be permitted",
            v["id"].as_str().unwrap_or("?")
        );
        assert_eq!(
            assigned,
            next_permitted(candidate),
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
        assert_eq!(
            format!("{:08x}", assigned),
            v["expected_index_hex"].as_str().expect("index hex"),
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
    }
}

fn forbidden(index: u32) -> bool {
    let be = index.to_be_bytes();
    be.contains(&0x0A) || be.contains(&0x0D)
}

fn next_permitted(candidate: u32) -> u32 {
    let mut i = candidate;
    while forbidden(i) {
        i += 1;
    }
    i
}

/// Argon2id derivation via the module's public API (normative parameters
/// are pinned inside the module; the vectors assert the resulting bytes).
fn argon2_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut salt_arr = [0u8; SALT_LEN];
    salt_arr.copy_from_slice(salt);
    session_key_from(password.as_bytes(), &salt_arr)
}

// --- VEC-01: Argon2id session-key derivation (argon2id.json) ---

#[test]
fn vec01_derives_normative_session_keys() {
    let doc = load("argon2id.json");
    let params = &doc["parameters"];
    assert_eq!(params["time_cost"], 1);
    assert_eq!(params["memory_cost_kib"], 65536);
    assert_eq!(params["parallelism"], 4);
    assert_eq!(params["output_length_bytes"], 32);
    for v in doc["vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().unwrap_or("?");
        let password = v["password"].as_str().expect("password");
        let salt = hex_to_bytes(v["salt_hex"].as_str().expect("salt_hex"));
        let expected = hex_to_bytes(v["expected_key_hex"].as_str().expect("key_hex"));
        let key = argon2_key(password, &salt);
        assert_eq!(key.to_vec(), expected, "{id}: Argon2id derivation");
    }
}

// --- VEC-02: nonce and control-key/tweak derivation (nonce_tweak.json) ---

#[test]
fn vec02_derives_body_nonces() {
    let doc = load("nonce_tweak.json");
    for v in doc["body_nonce_vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().unwrap_or("?");
        let key: [u8; 32] = hex_to_bytes(v["key_hex"].as_str().expect("key_hex"))
            .as_slice()
            .try_into()
            .expect("32-byte key");
        let segment_index = v["segment_index"].as_u64().expect("segment_index") as u32;
        // The normative HMAC message is "yenc-body nonce" || uint32_be(index).
        let mut expected_message = b"yenc-body nonce".to_vec();
        expected_message.extend_from_slice(&segment_index.to_be_bytes());
        let message = hex_to_bytes(v["message_hex"].as_str().expect("message_hex"));
        assert_eq!(message, expected_message, "{id}: HMAC message layout");
        assert_eq!(
            message.len() as u64,
            v["message_length_bytes"].as_u64().expect("message length"),
            "{id}"
        );
        let expected_nonce = hex_to_bytes(v["expected_nonce_hex"].as_str().expect("nonce_hex"));
        assert_eq!(expected_nonce.len(), 24, "{id}: nonce length");
        assert_eq!(
            body_nonce(&key, segment_index).to_vec(),
            expected_nonce,
            "{id}: body nonce"
        );
    }
}

#[test]
fn vec02_derives_control_enc_keys_and_tweaks() {
    let doc = load("nonce_tweak.json");
    for v in doc["control_tweak_vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().unwrap_or("?");
        let master_key: [u8; 32] = hex_to_bytes(v["master_key_hex"].as_str().expect("key_hex"))
            .as_slice()
            .try_into()
            .expect("32-byte master key");
        let expected_enc_key = hex_to_bytes(v["enc_key_hex"].as_str().expect("enc_key_hex"));
        assert_eq!(
            control_enc_key(&master_key).to_vec(),
            expected_enc_key,
            "{id}: control enc key"
        );
        let segment_index = v["segment_index"].as_u64().expect("segment_index") as u32;
        let line_index = v["line_index"].as_u64().expect("line_index") as u32;
        let expected_tweak = hex_to_bytes(v["expected_tweak_hex"].as_str().expect("tweak_hex"));
        assert_eq!(expected_tweak.len(), 8, "{id}: tweak length");
        assert_eq!(
            control_tweak(&master_key, segment_index, line_index).to_vec(),
            expected_tweak,
            "{id}: control tweak"
        );
    }
}

// --- VEC-03: body encryption, =yencryption line, AEAD round-trip (body_encryption.json) ---

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
        let expected_line = v["expected_yencryption_line"]
            .as_str()
            .expect("yencryption line");

        // Derived key/nonce cross-check against the fixture's own fields.
        let key = argon2_key(password, &salt);
        assert_eq!(
            key.to_vec(),
            hex_to_bytes(v["derived_key_hex"].as_str().expect("derived_key_hex")),
            "{id}: derived key"
        );
        assert_eq!(
            body_nonce(&key, segment_index).to_vec(),
            hex_to_bytes(v["derived_nonce_hex"].as_str().expect("derived_nonce_hex")),
            "{id}: derived nonce"
        );

        // Encryption must reproduce the canonical ciphertext and tag.
        let (ciphertext, tag) = encrypt_body(&key, segment_index, &plaintext)
            .unwrap_or_else(|e| panic!("{id}: encrypt failed: {e}"));
        assert_eq!(ciphertext, expected_ciphertext, "{id}: ciphertext");
        assert_eq!(tag.to_vec(), expected_tag, "{id}: tag");

        // The canonical =yencryption line is reproduced byte-for-byte.
        let mut salt_arr = [0u8; SALT_LEN];
        salt_arr.copy_from_slice(&salt);
        let line = build_yencryption_line(&salt_arr, segment_index, &tag)
            .unwrap_or_else(|e| panic!("{id}: line build failed: {e}"));
        assert_eq!(line, expected_line, "{id}: =yencryption line");

        // Parsing the canonical line restores salt/index/tag exactly.
        let header = parse_yencryption_line(expected_line)
            .unwrap_or_else(|e| panic!("{id}: line parse failed: {e}"));
        assert_eq!(header.salt, salt_arr, "{id}: parsed salt");
        assert_eq!(header.segment_index, segment_index, "{id}: parsed index");
        assert_eq!(header.tag.to_vec(), expected_tag, "{id}: parsed tag");

        // Full encrypt -> decrypt round-trip over the vector's plaintext.
        let restored = decrypt_segment(&key, segment_index, &ciphertext, &tag)
            .unwrap_or_else(|e| panic!("{id}: decrypt failed: {e}"));
        assert_eq!(restored, plaintext, "{id}: round trip");

        // The vector's own ciphertext/tag pair decrypts to the plaintext.
        let tag_arr: [u8; 16] = expected_tag.as_slice().try_into().expect("16-byte tag");
        let decrypted = decrypt_body(&key, segment_index, &expected_ciphertext, &tag_arr)
            .unwrap_or_else(|e| panic!("{id}: vector decrypt failed: {e}"));
        assert_eq!(decrypted, plaintext, "{id}: vector ciphertext round trip");
    }
}

// --- VEC-04: FF1 control-line wire bytes and Line-1 bootstrap (control_line_encryption.json) ---

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
            let salt = hex_to_bytes(v["salt_hex"].as_str().expect("salt_hex"));
            let segment_index = v["segment_index"].as_u64().expect("segment_index") as u32;
            let master_key = argon2_key(password, &salt);
            let mut salt_arr = [0u8; SALT_LEN];
            salt_arr.copy_from_slice(&salt);

            for (idx, (plain, wire_hex)) in input_lines.iter().zip(expected_wire.iter()).enumerate()
            {
                let plain = plain.as_str().expect("plaintext line");
                let expected = hex_to_bytes(wire_hex.as_str().expect("wire hex"));
                if idx == 0 {
                    // Line 1 carries the 20-byte bootstrap prefix.
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
                    // Data lines pass through untouched (control standard §3);
                    // control lines are FF1-encrypted at their physical
                    // lineIndex (1-based) — restore the wire material.
                    let line_index = idx as u32 + 1;
                    let plain_bytes = plain.as_bytes();
                    if expected == plain_bytes {
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

        // Single-line vectors: assert exact wire bytes for line 1 (bootstrap
        // + FF1 ciphertext) and length-preserving decryption for the rest.
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

        // Cross-check our derivations against the fixture's.
        let master_key = argon2_key(password, &salt);
        let enc_key = control_enc_key(&master_key);
        assert_eq!(enc_key.to_vec(), expected_enc_key, "{id}: enc key");
        let tweak = control_tweak(&master_key, segment_index, line_index);
        assert_eq!(tweak.to_vec(), expected_tweak, "{id}: tweak");

        if is_line_1 {
            // Bootstrap expansion: 16 salt bytes || 4-byte index prefix.
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
            let mut salt_arr = [0u8; SALT_LEN];
            salt_arr.copy_from_slice(&salt);
            let wire = encrypt_line1(
                &master_key,
                segment_index,
                &salt_arr,
                plaintext_line.as_bytes(),
            )
            .unwrap_or_else(|e| panic!("{id}: line 1 encrypt failed: {e}"));
            assert_eq!(wire, expected_wire, "{id}: line 1 wire bytes");
            // The first 20 wire bytes are the bootstrap: salt || index.
            assert_eq!(
                &wire[..20],
                &build_bootstrap_prefix(&salt_arr, segment_index)[..],
                "{id}: bootstrap prefix"
            );
            let (restored, bootstrap) = decrypt_line1(&master_key, &wire)
                .unwrap_or_else(|e| panic!("{id}: line 1 decrypt failed: {e}"));
            assert_eq!(
                restored,
                plaintext_line.as_bytes().to_vec(),
                "{id}: line 1 restore"
            );
            assert_eq!(bootstrap.salt, salt_arr, "{id}: bootstrap salt");
            assert_eq!(
                bootstrap.segment_index, segment_index,
                "{id}: bootstrap index"
            );
        } else {
            // Non-Line-1: FF1 is deterministic and length-preserving, so the
            // encrypted line reproduces the canonical wire bytes exactly.
            assert_eq!(
                v["expected_wire_length"].as_u64(),
                Some(plaintext_line.len() as u64),
                "{id}: exact length"
            );
            let wire = encrypt_control_line(
                &master_key,
                segment_index,
                line_index,
                plaintext_line.as_bytes(),
            )
            .unwrap_or_else(|e| panic!("{id}: line {line_index} encrypt failed: {e}"));
            assert_eq!(wire, expected_wire, "{id}: line {line_index} wire bytes");
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

// --- VEC-05: malformed-input rejection through the module surface (malformed_inputs.json) ---

fn assert_rejected(err: EncryptionError, expected_code: &str, id: &str) {
    assert_eq!(err.to_string(), expected_code, "{id}: wrong error code");
}

#[test]
fn vec05_module_rejects_all_malformed_vectors() {
    let doc = load("malformed_inputs.json");
    let vectors = doc["vectors"].as_array().expect("vectors");
    assert_eq!(vectors.len(), 46, "v1.2 malformed set has 46 vectors");
    let mut module_exercised = 0usize;
    for v in vectors {
        let id = v["id"].as_str().unwrap_or("?").to_string();
        let expected_code = v["expected_error"]
            .as_str()
            .expect("expected_error")
            .to_string();
        let category = v["category"].as_str().unwrap_or_default();

        // header_syntax vectors: full =yencryption lines — the strict grammar
        // parser must reject each with the taxonomy-mapped code.
        if category == "header_syntax" {
            let line = v["input_line"].as_str().expect("input_line");
            match parse_yencryption_line(line) {
                Ok(header) => panic!("{id}: header accepted: {header:?}"),
                Err(err) => assert_rejected(err, &expected_code, &id),
            }
            module_exercised += 1;
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
            module_exercised += 1;
            continue;
        }

        // Auth-failure vectors: AEAD tag verification must fail and release
        // nothing (zero-output guarantee).
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
            module_exercised += 1;
            continue;
        }

        // salt_mismatch vectors: dual-bootstrap agreement failures. The
        // byte-level comparison lives in penne's download seam (T03); here
        // we assert the vector material genuinely disagrees.
        if category == "salt_mismatch" {
            let line1_salt = hex_to_bytes(v["line1_salt_hex"].as_str().expect("line1_salt_hex"));
            let header_salt = hex_to_bytes(v["header_salt_hex"].as_str().expect("header_salt_hex"));
            let line1_index = v["line1_index"].as_u64().expect("line1_index") as u32;
            let header_index = v["header_index"].as_u64().expect("header_index") as u32;
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
        // pinned by the shape assertions in
        // `malformed_vectors_shapes_and_families` and
        // `placement_vectors_pin_line2`.
    }
    // 23 header_syntax + 11 control_syntax + 4 auth_failure = 38 exercised
    // through the module surface; the remaining 8 (2 salt_mismatch, 2
    // placement, 4 metadata_validation) are structural/seam-level and are
    // covered by the categorical assertions in this file.
    assert_eq!(module_exercised, 38, "module-surface vector accounting");
}

// --- VEC-07: module allocator matches the vectors (index_allocation.json) ---

#[test]
fn vec07_module_allocator_matches_vectors() {
    let doc = load("index_allocation.json");
    for v in doc["vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().unwrap_or("?");
        let candidate = v["candidate_index"].as_u64().expect("candidate_index") as u32;
        let assigned = v["expected_assigned_index"].as_u64().expect("assigned") as u32;
        // Every non-null candidate is forbidden by the module's predicate.
        if v["expected_error"].is_null() {
            assert!(
                index_is_forbidden(candidate),
                "{id}: candidate must be forbidden"
            );
            assert!(
                !index_is_forbidden(assigned),
                "{id}: assigned must be permitted"
            );
        }
        assert_eq!(next_permitted_index(candidate), assigned, "{id}");
        // A fresh allocator started at the candidate assigns the same index.
        let mut allocator = SegmentIndexAllocator::new(candidate);
        let allocated = allocator
            .allocate()
            .unwrap_or_else(|e| panic!("{id}: allocate failed: {e}"));
        assert_eq!(allocated, assigned, "{id}: allocator assignment");
        assert_eq!(
            format!("{assigned:08x}"),
            v["expected_index_hex"].as_str().expect("index hex"),
            "{id}: assigned index hex"
        );
    }
}

/// Every malformed vector must carry the fields downstream implementations
/// assert against: a stable error code, the zero-output guarantee, and a
/// rejection stage. Categorical checks per family.
#[test]
fn malformed_vectors_shapes_and_families() {
    let doc = load("malformed_inputs.json");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 46, "v1.2 malformed set has 46 vectors");
    for v in vectors {
        let id = v["id"].as_str().expect("vector id");
        assert!(
            !v["expected_error"].as_str().unwrap_or_default().is_empty(),
            "{id}: expected_error"
        );
        assert_eq!(
            v["zero_output_required"], true,
            "{id}: zero-output guarantee"
        );
        let stage = v["expected_rejection_stage"].as_str().expect("stage");
        assert!(
            stage == "PROVIDER_FAILOVER" || stage == "METADATA_VALIDATION",
            "{id}: unexpected rejection stage {stage}"
        );
    }

    // header_syntax vectors carry a full =yencryption line to reject.
    // (header-16/header-17 deliberately start "=yencryption\t" / "=yencryption  "
    // — invalid whitespace is the very thing they assert.)
    for v in vectors.iter().filter(|v| v["category"] == "header_syntax") {
        let line = v["input_line"].as_str().unwrap_or_default();
        assert!(
            line.starts_with("=yencryption")
                && line.len() > "=yencryption".len()
                && !line.as_bytes()["=yencryption".len()].is_ascii_alphanumeric(),
            "{}: header_syntax vector missing input_line",
            v["id"].as_str().unwrap_or("?")
        );
    }

    // control_syntax vectors carry hex-encoded line material.
    for v in vectors.iter().filter(|v| v["category"] == "control_syntax") {
        let has_line = v.get("line_hex").is_some()
            || v.get("line1_hex").is_some()
            || v.get("tampered_salt_hex").is_some()
            || v.get("password").is_some()
            || v.get("wrong_password").is_some();
        assert!(
            has_line,
            "{}: control_syntax vector missing line material",
            v["id"].as_str().unwrap_or("?")
        );
    }

    // Auth-failure vectors must be marked zero-output (no plaintext or
    // ciphertext may be released when Poly1305 verification fails).
    for v in vectors.iter().filter(|v| v["category"] == "auth_failure") {
        assert_eq!(
            v["expected_error"],
            "AUTHENTICATION_FAILURE",
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
    }

    // Index-allocation forbidden-byte cases in the control-syntax family.
    for v in vectors
        .iter()
        .filter(|v| v["expected_error"] == "FORBIDDEN_SEGMENT_INDEX_BYTE")
    {
        let line1 = hex_to_bytes(v["line1_hex"].as_str().expect("line1_hex"));
        assert_eq!(
            line1.len(),
            22,
            "{}: bootstrap line must be 22 bytes",
            v["id"].as_str().unwrap_or("?")
        );
        let index = u32::from_be_bytes([line1[16], line1[17], line1[18], line1[19]]);
        assert!(
            forbidden(index),
            "{}: index {index} should be forbidden",
            v["id"].as_str().unwrap_or("?")
        );
    }
}

/// VEC-05's placement contract: the encryption header belongs on physical
/// line 2 of a single-part article (and after =ypart for multi-part).
#[test]
fn placement_vectors_pin_line2() {
    let doc = load("malformed_inputs.json");
    let vectors = doc["vectors"].as_array().unwrap();
    let placements: Vec<_> = vectors
        .iter()
        .filter(|v| v["category"] == "placement")
        .collect();
    assert_eq!(placements.len(), 2, "two placement vectors in v1.2");
    // Single-part: header must be on physical line 2, so line 3 is invalid.
    assert_eq!(placements[0]["line_index"], 3);
    assert_eq!(placements[0]["multipart"], false);
    // Multi-part: header must come before the data lines, so after-data (line 4) is invalid.
    assert_eq!(placements[1]["line_index"], 4);
    assert_eq!(placements[1]["multipart"], true);
    assert!(placements
        .iter()
        .all(|v| v["expected_error"] == "MISPLACED_ENCRYPTION_HEADER"));
}

/// Sanity anchor independent of the malformed set: every body vector's
/// plaintext must round-trip through the existing yEnc codec unchanged —
/// encryption is a pre-transform, so the codec itself must stay lossless.
/// The cryptographic assertions (ciphertext/tag/nonce derivation and the
/// =yencryption line bytes) live in the VEC-01..05 tests above.
#[test]
fn body_vectors_plaintext_round_trips_through_yenc() {
    let doc = load("body_encryption.json");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(
        !vectors.is_empty(),
        "body_encryption fixture must not be empty"
    );
    for v in vectors {
        let id = v["id"].as_str().unwrap_or("?");
        let plaintext = hex_to_bytes(v["plaintext_hex"].as_str().expect("plaintext_hex"));
        assert_eq!(
            plaintext.len() as u64,
            v["plaintext_length"].as_u64().unwrap_or(0),
            "{id}"
        );
        let part = pesto::yenc::decode_part(
            &pesto::yenc::encode_part(
                id,
                plaintext.len() as u64,
                pesto::yenc::PartSpec {
                    number: 1,
                    total: 1,
                    offset: 0,
                },
                &plaintext,
                pesto::yenc::DEFAULT_LINE_LENGTH,
                None,
            )
            .body,
        )
        .unwrap_or_else(|e| panic!("{id}: yEnc round-trip failed: {e}"));
        assert_eq!(
            part.data, plaintext,
            "{id}: yEnc round-trip must be lossless"
        );
        assert!(part.crc_matches(), "{id}: CRC must match after round-trip");
    }
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Local 20-byte bootstrap layout check (16 salt bytes || uint32_be index),
/// mirroring the module's `build_bootstrap` without importing it.
fn build_bootstrap_prefix(salt: &[u8; SALT_LEN], segment_index: u32) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[..16].copy_from_slice(salt);
    out[16..].copy_from_slice(&segment_index.to_be_bytes());
    out
}
