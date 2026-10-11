//! Consolidated NZB encryption-metadata tests (audit P9): the former
//! near-identical generate/parse round-trips collapsed into one writer test,
//! one fail-closed reader test, one archive-password test, one mixed-release
//! test, and the two vector runners.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::ObfuscateMode;
use crate::crypto::body::decrypt_body;
use crate::crypto::kdf::EncryptionSession;
use crate::nzb::{generate, parse, NzbMeta};
use crate::poster::PostedSegment;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Generated segments carry only NZB 1.1 `bytes`/`number` attributes (Body Std v1.2 §8).
fn assert_plain_segments(xml: &str) {
    for t in xml.split("<segment ").skip(1) {
        let tag = &t[..t.find('>').unwrap()];
        let attrs = tag.matches('=').count();
        let ok = attrs == 2 && tag.starts_with("bytes=") && tag.contains(" number=");
        assert!(ok, "non-standard segment: {tag}");
    }
}

fn test_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

fn make_segment(file_name: &str, part: u32, total: u32, msg_id: &str, bytes: u64) -> PostedSegment {
    PostedSegment {
        file_name: file_name.to_string(),
        file_path: Arc::from(Path::new(file_name)),
        subject_name: Arc::from(file_name),
        wire_name: Arc::from(""),
        wire_yenc_name: Arc::from(""),
        file_size: bytes * total as u64,
        part,
        total,
        message_id: format!("<{msg_id}>"),
        bytes,
        from: Arc::from("poster@example.com"),
        date: (None, Some(1774300000)),
        full_crc32: 0,
        server_idx: 0,
        file_index: 0,
        total_files: 0,
        segment_index: 0,
    }
}

/// Encrypted-meta emission and re-parse: the writer emits `yenc_encrypted`
/// (plus the optional version/cipher provenance metas) and only standard
/// NZB 1.1 `bytes`/`number` segment attributes — under full obfuscation too
/// — and the reader round-trips the provenance flag (Body Std v1.2 §8).
#[test]
fn encrypted_nzb_writer_emits_provenance_and_plain_segments() {
    let s1 = make_segment("f1.bin", 1, 1, "id1@x", 100);
    let s2 = make_segment("f2.bin", 1, 1, "id2@x", 200);

    let meta = NzbMeta {
        name: Some("test-release".into()),
        password: Some("secret123".into()),
        yenc_encrypted: true,
        ..Default::default()
    };
    for obfuscate in [ObfuscateMode::None, ObfuscateMode::Full] {
        let xml = generate(
            &["alt.binaries.test".into()],
            &[s1.clone(), s2.clone()],
            &meta,
            obfuscate,
        );

        assert_plain_segments(&xml);
        assert!(
            xml.contains("<meta type=\"yenc_encrypted\">true</meta>"),
            "XML must contain yenc_encrypted meta element, got:\n{xml}"
        );
        assert!(xml.contains("<meta type=\"password\">secret123</meta>"));
        assert!(xml.contains(&format!(
            "<meta type=\"yenc_version\">{}</meta>",
            super::YENC_SPEC_VERSION
        )));
        assert!(xml.contains("<meta type=\"yenc_cipher\">XChaCha20-Poly1305</meta>"));

        let parsed = parse(&xml).unwrap();
        assert!(parsed.meta.yenc_encrypted);
        assert_eq!(parsed.segments.len(), 2);
    }
}

/// Fail-closed provenance gating (Body Std v1.2 §8): a declared-encrypted
/// NZB with an unsupported `yenc_version` or `yenc_cipher` is a structural
/// parse failure, never a silent fallback to ordinary yEnc.
#[test]
fn encrypted_nzb_reader_rejects_unsupported_version_and_cipher() {
    let base_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">fixture-value</meta>
    <meta type="yenc_encrypted">true</meta>
    VERSION_TAG
    CIPHER_TAG
  </head>
  <file poster="poster@example.com" date="1774300000" subject="[1/1] - &quot;file.bin&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="750000" number="1">art1@example.com</segment>
    </segments>
  </file>
</nzb>"#;

    // Any version other than the current one fails closed.
    for bad_version in ["1", "1.3", "2.0"] {
        let bad_ver_xml = base_xml
            .replace(
                "VERSION_TAG",
                &format!("<meta type=\"yenc_version\">{bad_version}</meta>"),
            )
            .replace(
                "CIPHER_TAG",
                "<meta type=\"yenc_cipher\">XChaCha20-Poly1305</meta>",
            );
        let err = parse(&bad_ver_xml).unwrap_err();
        assert!(
            err.to_string().contains("unsupported yenc_version"),
            "version {bad_version} must be rejected"
        );
    }

    let version_tag = format!(
        "<meta type=\"yenc_version\">{}</meta>",
        super::YENC_SPEC_VERSION
    );

    // Bad cipher
    let bad_cipher_xml = base_xml
        .replace("VERSION_TAG", &version_tag)
        .replace("CIPHER_TAG", "<meta type=\"yenc_cipher\">AES-GCM</meta>");
    let err2 = parse(&bad_cipher_xml).unwrap_err();
    assert!(err2.to_string().contains("unsupported yenc_cipher"));

    // Current version and cipher are accepted.
    let valid_xml = base_xml.replace("VERSION_TAG", &version_tag).replace(
        "CIPHER_TAG",
        "<meta type=\"yenc_cipher\">XChaCha20-Poly1305</meta>",
    );
    let parsed = parse(&valid_xml).unwrap();
    assert!(parsed.meta.yenc_encrypted);
}

/// A `<meta type="password">` without the `yenc_encrypted` provenance marker
/// is an archive-extraction password: the NZB is not encrypted, nothing
/// infers transport identity from it, and regenerating from the parsed
/// content emits no encryption metadata (Body Std v1.2 §8).
#[test]
fn archive_password_only_nzb_is_not_encrypted() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">rarpassword</meta>
  </head>
  <file poster="poster@example.com" date="1774300000" subject="arbitrary subject 1">
    <groups>
      <group>alt.binaries.test</group>
    </groups>
    <segments>
      <segment bytes="750000" number="1">art-42@example.com</segment>
    </segments>
  </file>
  <file poster="poster@example.com" date="1774300000" subject="[1/1] - &quot;archive.rar&quot; yEnc (1/1)">
    <groups>
      <group>alt.binaries.test</group>
    </groups>
    <segments>
      <segment bytes="750000" number="1">art-rar-1@example.com</segment>
    </segments>
  </file>
</nzb>"#;

    let parsed = parse(xml).expect("archive password NZB must parse cleanly");
    assert_eq!(parsed.meta.password.as_deref(), Some("rarpassword"));
    assert!(!parsed.meta.yenc_encrypted);
    assert_eq!(parsed.segments.len(), 2);

    let regen_xml = generate(
        &["alt.binaries.test".to_string()],
        &parsed.segments,
        &parsed.meta,
        ObfuscateMode::None,
    );
    assert_plain_segments(&regen_xml);
    assert!(!regen_xml.contains("yenc_encrypted"));

    let parsed2 = parse(&regen_xml).unwrap();
    assert_eq!(parsed2.segments.len(), parsed.segments.len());
    assert!(!parsed2.meta.yenc_encrypted);
}

/// Bootstrap-only identity: an NZB may mix encrypted and ordinary files
/// under one provenance flag — the XML parses cleanly and per-segment
/// validation happens post-fetch, on the article bytes themselves.
#[test]
fn mixed_encrypted_and_ordinary_files_parse_without_identity() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">transport-password</meta>
    <meta type="yenc_encrypted">true</meta>
  </head>
  <file poster="poster@example.com" date="1774300000" subject="encrypted.bin">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="100" number="1">encrypted@example.com</segment>
    </segments>
  </file>
  <file poster="poster@example.com" date="1774300000" subject="ordinary.bin">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="100" number="1">ordinary@example.com</segment>
    </segments>
  </file>
</nzb>"#;

    let parsed = parse(xml).expect("mixed release parses under bootstrap-only identity");
    assert!(parsed.meta.yenc_encrypted);
    assert_eq!(parsed.segments.len(), 2);
}

/// VEC-06 (nzb_segment_identity.json): valid-identity vectors parse with
/// their declared segments intact regardless of subject/obfuscation/order;
/// unencrypted-compatibility vectors parse without the provenance flag;
/// index-tampering vectors fail body authentication against the production
/// `decrypt_body` (zero output — nonce derived from the tampered index).
#[test]
fn nzb_segment_identity_vectors_run_against_reader_and_decrypt_body() {
    let path = test_vectors_dir().join("nzb_segment_identity.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let fixture: serde_json::Value = serde_json::from_str(&content).unwrap();
    let vectors = fixture["vectors"].as_array().expect("vectors array");

    assert_eq!(vectors.len(), 10, "expected exactly 10 test vectors");
    let mut count = 0;

    for vec in vectors {
        let id = vec["id"].as_str().unwrap();
        let category = vec["category"].as_str().unwrap();

        match category {
            "valid_identity" => {
                assert!(vec["is_encrypted"].as_bool().unwrap());
                let parsed = parse(vec["nzb_xml"].as_str().unwrap())
                    .unwrap_or_else(|e| panic!("vector {id} failed valid parsing: {e}"));
                assert!(parsed.meta.yenc_encrypted, "vector {id} must be encrypted");

                let expected_segs = vec["expected_segments"].as_array().unwrap();
                assert_eq!(
                    parsed.segments.len(),
                    expected_segs.len(),
                    "vector {id} segment count mismatch"
                );

                for exp in expected_segs {
                    let exp_mid = exp["message_id"].as_str().unwrap();
                    let canonical_mid = if exp_mid.starts_with('<') {
                        exp_mid.to_string()
                    } else {
                        format!("<{exp_mid}>")
                    };
                    let seg = parsed
                        .segments
                        .iter()
                        .find(|s| s.message_id == canonical_mid)
                        .unwrap_or_else(|| panic!("missing segment {canonical_mid}"));
                    assert_eq!(seg.bytes, exp["bytes"].as_u64().unwrap());
                    assert_eq!(seg.part, exp["part"].as_u64().unwrap() as u32);
                }
            }
            "unencrypted_compatibility" => {
                let parsed = parse(vec["nzb_xml"].as_str().unwrap())
                    .unwrap_or_else(|e| panic!("vector {id} failed unencrypted parse: {e}"));
                assert!(
                    !parsed.meta.yenc_encrypted,
                    "vector {id} must not be marked encrypted"
                );
                let expected_segs = vec["expected_segments"].as_array().unwrap();
                assert_eq!(parsed.segments.len(), expected_segs.len());
            }
            "index_tampering" => {
                let parsed = parse(vec["nzb_xml"].as_str().unwrap())
                    .unwrap_or_else(|e| panic!("vector {id} failed parse: {e}"));
                assert!(parsed.meta.yenc_encrypted);

                let pwd = vec
                    .get("transport_kdf_input")
                    .or_else(|| vec.get("password"))
                    .unwrap()
                    .as_str()
                    .unwrap();
                let salt_vec = hex_decode(vec["salt_hex"].as_str().unwrap());
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&salt_vec);

                let session = EncryptionSession::new(pwd, salt).unwrap();

                let decrypt_tampered = |t_index: u32, ct: Vec<u8>, tag: [u8; 16]| {
                    let nonce = session.derive_body_nonce(t_index);
                    decrypt_body(&ct, &tag, session.master_key(), &nonce)
                };

                if let Some(tampered_segs) = vec.get("tampered_segments").and_then(|v| v.as_array())
                {
                    for t_seg in tampered_segs {
                        let t_index = t_seg["tampered_segment_index"].as_u64().unwrap() as u32;
                        let ct = hex_decode(t_seg["ciphertext_hex"].as_str().unwrap());
                        let tag_vec = hex_decode(t_seg["tag_hex"].as_str().unwrap());
                        let mut tag = [0u8; 16];
                        tag.copy_from_slice(&tag_vec);

                        let res = decrypt_tampered(t_index, ct, tag);
                        assert!(
                            res.is_err(),
                            "vector {id} tampered segment {t_index} succeeded but must fail"
                        );
                    }
                } else {
                    let t_index = vec["tampered_segment_index"].as_u64().unwrap() as u32;
                    let ct = hex_decode(vec["ciphertext_hex"].as_str().unwrap());
                    let tag_vec = hex_decode(vec["tag_hex"].as_str().unwrap());
                    let mut tag = [0u8; 16];
                    tag.copy_from_slice(&tag_vec);

                    let res = decrypt_tampered(t_index, ct, tag);
                    assert!(
                        res.is_err(),
                        "vector {id} tampered index {t_index} succeeded but must fail"
                    );
                }
            }
            other => panic!("unknown category {other}"),
        }
        count += 1;
    }

    assert_eq!(count, 10, "must process exactly 10 vectors");
}

/// VEC-07 (index_allocation.json): uploader-skip vectors exercised against
/// the real allocator — the candidate's rank maps to the expected assigned
/// safe index (not just a predicate), which skips forward past forbidden
/// 0x0A/0x0D bytes.
#[test]
fn index_allocation_vectors_exercise_the_allocator() {
    let path = test_vectors_dir().join("index_allocation.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let fixture: serde_json::Value = serde_json::from_str(&content).unwrap();
    let vectors = fixture["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 4, "expected exactly 4 allocation vectors");

    for vec in vectors {
        let id = vec["id"].as_str().unwrap();
        assert_eq!(vec["category"].as_str().unwrap(), "index_allocation");
        let candidate = vec["candidate_index"].as_u64().unwrap() as u32;
        let assigned = vec["expected_assigned_index"].as_u64().unwrap() as u32;
        let expected_hex = vec["expected_index_hex"].as_str().unwrap();
        let expected_error = vec["expected_error"].as_null();
        assert!(expected_error.is_some(), "vector {id} must be a skip case");

        // Candidate is forbidden (uint32_be contains 0x0A/0x0D).
        assert!(
            candidate
                .to_be_bytes()
                .iter()
                .any(|&b| b == 0x0A || b == 0x0D),
            "vector {id}: candidate {candidate} bytes must contain 0x0A/0x0D"
        );
        let rank = crate::poster::safe_index_rank(candidate);
        assert_eq!(
            crate::poster::nth_safe_segment_index(rank),
            Some(assigned),
            "vector {id}: allocator must assign {assigned} at rank {rank}"
        );
        assert!(assigned > candidate, "vector {id}: must skip forward");
        assert_eq!(
            format!("{assigned:08x}"),
            expected_hex,
            "vector {id}: hex formatting mismatch"
        );
    }
}
