//! Conformance test over the vendored v1.2 fixture set (test-vectors/).
//!
//! These are byte-identical copies of the canonical fixtures from the
//! yenc-encryption-standards v1.2 repository, vendored per the submodule
//! self-containment directive — this test reads only files inside this
//! crate's own tree via CARGO_MANIFEST_DIR.
//!
//! Coverage at this stage (S01): fixture integrity (manifest sha256 sync),
//! the VEC-07 index-allocation skip rules, malformed-input grammar
//! assertions, and a yEnc encode/decode round-trip of each body-encryption
//! vector's plaintext through the existing codec. Cryptographic assertion
//! of the XChaCha20-Poly1305 ciphertexts/tags and `=yencryption` header
//! parsing lands with the crypto modules in S02 (TODO(S02)).

use std::path::PathBuf;

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
    serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

#[test]
fn manifest_sha256_sync() {
    let manifest = load("manifest.json");
    let files = manifest["files"].as_object().expect("manifest.files object");
    assert_eq!(manifest["standard_version"], "1.2", "fixture set must be v1.2");
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
        assert_eq!(assigned, next_permitted(candidate), "{}", v["id"].as_str().unwrap_or("?"));
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
        assert!(!v["expected_error"].as_str().unwrap_or_default().is_empty(), "{id}: expected_error");
        assert_eq!(v["zero_output_required"], true, "{id}: zero-output guarantee");
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
        assert!(has_line, "{}: control_syntax vector missing line material", v["id"].as_str().unwrap_or("?"));
    }

    // Auth-failure vectors must be marked zero-output (no plaintext or
    // ciphertext may be released when Poly1305 verification fails).
    for v in vectors.iter().filter(|v| v["category"] == "auth_failure") {
        assert_eq!(
            v["expected_error"], "AUTHENTICATION_FAILURE",
            "{}",
            v["id"].as_str().unwrap_or("?")
        );
    }

    // Index-allocation forbidden-byte cases in the control-syntax family.
    for v in vectors.iter().filter(|v| {
        v["expected_error"] == "FORBIDDEN_SEGMENT_INDEX_BYTE"
    }) {
        let line1 = hex_to_bytes(v["line1_hex"].as_str().expect("line1_hex"));
        assert_eq!(line1.len(), 22, "{}: bootstrap line must be 22 bytes", v["id"].as_str().unwrap_or("?"));
        let index = u32::from_be_bytes([line1[16], line1[17], line1[18], line1[19]]);
        assert!(forbidden(index), "{}: index {index} should be forbidden", v["id"].as_str().unwrap_or("?"));
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
    assert!(placements.iter().all(|v| v["expected_error"] == "MISPLACED_ENCRYPTION_HEADER"));
}

/// Sanity anchor independent of the malformed set: every body vector's
/// plaintext must round-trip through the existing yEnc codec unchanged —
/// encryption is a pre-transform, so the codec itself must stay lossless.
/// TODO(S02): also assert ciphertext/tag/nonce derivation and the
/// =yencryption line bytes once pesto gains the crypto modules.
#[test]
fn body_vectors_plaintext_round_trips_through_yenc() {
    let doc = load("body_encryption.json");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "body_encryption fixture must not be empty");
    for v in vectors {
        let id = v["id"].as_str().unwrap_or("?");
        let plaintext = hex_to_bytes(v["plaintext_hex"].as_str().expect("plaintext_hex"));
        assert_eq!(plaintext.len() as u64, v["plaintext_length"].as_u64().unwrap_or(0), "{id}");
        let part = pesto::yenc::decode_part(
            &pesto::yenc::encode_part(
                id,
                plaintext.len() as u64,
                pesto::yenc::PartSpec { number: 1, total: 1, offset: 0 },
                &plaintext,
                pesto::yenc::DEFAULT_LINE_LENGTH,
                None,
            )
            .body,
        )
        .unwrap_or_else(|e| panic!("{id}: yEnc round-trip failed: {e}"));
        assert_eq!(part.data, plaintext, "{id}: yEnc round-trip must be lossless");
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
