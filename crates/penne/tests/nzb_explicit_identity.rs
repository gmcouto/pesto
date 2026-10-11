//! Bootstrap-only segment identity at the penne queue boundary.
//!
//! Body Encryption Standard v1.2 §8: encrypted NZBs carry plain NZB 1.1
//! segments (`bytes`, `number`) and no encryption-specific segment data.
//! Identity derives exclusively from each article's bootstrap post-fetch.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use penne::nzb::load;
use penne::queue::build;
use tempfile::NamedTempFile;

fn test_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

fn write_temp_nzb(xml: &str) -> NamedTempFile {
    let mut temp = NamedTempFile::new().expect("failed to create temp file");
    temp.write_all(xml.as_bytes()).expect("failed to write XML");
    temp
}

#[test]
fn encrypted_nzb_queues_plain_segments_without_identity() {
    // An obfuscated encrypted release: nothing in the NZB identifies the
    // segment index; the queue carries only Message-ID, part and bytes.
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">tracer_secret</meta>
    <meta type="yenc_encrypted">true</meta>
  </head>
  <file poster="uploader@example.com" date="1774300000" subject="completely-obfuscated-subject-no-counters">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="750000" number="1">tracer-msg-01@example.com</segment>
      <segment bytes="250000" number="2">tracer-msg-02@example.com</segment>
    </segments>
  </file>
</nzb>"#;

    let temp = write_temp_nzb(xml);
    let parsed = load(temp.path()).expect("Penne NZB load must succeed");
    assert!(parsed.meta.yenc_encrypted, "must be marked yenc_encrypted");

    let queue = build(&parsed);
    assert_eq!(queue.files.len(), 1);
    let queued_file = &queue.files[0];
    assert_eq!(queued_file.segments.len(), 2);
    assert_eq!(queued_file.segments[0].part, 1);
    assert_eq!(queued_file.segments[0].bytes, 750000);
    assert_eq!(queued_file.segments[1].part, 2);
    assert_eq!(queued_file.segments[1].bytes, 250000);
}

#[test]
fn test_conformance_vectors_penne_nzb_segment_identity() {
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
        let nzb_xml = vec["nzb_xml"].as_str().unwrap();

        let temp = write_temp_nzb(nzb_xml);
        let parsed = load(temp.path()).unwrap_or_else(|e| panic!("vector {id} failed load: {e}"));
        let queue = build(&parsed);

        match category {
            "valid_identity" | "unencrypted_compatibility" => {
                let expect_encrypted = vec["is_encrypted"].as_bool().unwrap();
                assert_eq!(
                    parsed.meta.yenc_encrypted, expect_encrypted,
                    "vector {id} encryption flag mismatch"
                );

                let actual: HashMap<&str, (u32, u64)> = queue
                    .files
                    .iter()
                    .flat_map(|f| &f.segments)
                    .map(|s| (s.message_id.as_str(), (s.part, s.bytes)))
                    .collect();

                let expected_segs = vec["expected_segments"].as_array().unwrap();
                assert_eq!(
                    actual.len(),
                    expected_segs.len(),
                    "vector {id} segment count mismatch"
                );

                for exp in expected_segs {
                    let msg_id = exp["message_id"].as_str().unwrap();
                    let canonical_mid = if msg_id.starts_with('<') {
                        msg_id.to_string()
                    } else {
                        format!("<{msg_id}>")
                    };
                    let &(part, bytes) = actual
                        .get(canonical_mid.as_str())
                        .unwrap_or_else(|| panic!("vector {id} missing message {canonical_mid}"));
                    assert_eq!(
                        u64::from(part),
                        exp["part"].as_u64().unwrap(),
                        "vector {id} part mismatch for {canonical_mid}"
                    );
                    assert_eq!(
                        bytes,
                        exp["bytes"].as_u64().unwrap(),
                        "vector {id} bytes mismatch for {canonical_mid}"
                    );
                }
            }
            "index_tampering" => {
                // Tampering is only detectable post-fetch (Poly1305); the NZB
                // itself parses as an ordinary encrypted release.
                assert!(
                    parsed.meta.yenc_encrypted,
                    "vector {id} must be marked encrypted"
                );
                assert!(!queue.files.is_empty(), "vector {id} must queue segments");
            }
            other => panic!("unknown category {other}"),
        }
        count += 1;
    }

    assert_eq!(count, 10, "must process exactly 10 vectors");
}

#[test]
fn test_compatibility_archive_password_only() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">rarpassword</meta>
  </head>
  <file poster="poster@example.com" date="1774300000" subject="[1/1] - &quot;archive.rar&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="750000" number="1">archive-msg-01@example.com</segment>
    </segments>
  </file>
</nzb>"#;

    let temp = write_temp_nzb(xml);
    let parsed = load(temp.path()).expect("load must succeed");
    assert!(
        !parsed.meta.yenc_encrypted,
        "must NOT be marked yenc_encrypted"
    );
    assert_eq!(parsed.meta.password.as_deref(), Some("rarpassword"));

    let queue = build(&parsed);
    assert_eq!(queue.files.len(), 1);
    assert_eq!(queue.files[0].segments.len(), 1);
}
