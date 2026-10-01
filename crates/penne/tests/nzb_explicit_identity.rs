use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use penne::download::validate_queue_identity;
use penne::nzb::load;
use penne::queue::{build, DownloadQueue, QueuedFile, QueuedSegment};
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
fn test_tracer_penne_queue_explicit_identity() {
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
      <segment bytes="750000" number="1" segmentIndex="42">tracer-msg-01@example.com</segment>
      <segment bytes="250000" number="2" segmentIndex="43">tracer-msg-02@example.com</segment>
    </segments>
  </file>
</nzb>"#;

    let temp = write_temp_nzb(xml);
    let parsed = load(temp.path()).expect("Penne NZB load must succeed");
    assert!(parsed.meta.yenc_encrypted, "must be marked yenc_encrypted");

    // Cryptographic segment identity in reader must have uncounted (0, 0) geometry
    let identities = parsed
        .segment_identities
        .as_ref()
        .expect("segment_identities must be present");
    let id1 = identities
        .get("<tracer-msg-01@example.com>")
        .expect("identity for msg 1");
    assert_eq!(id1.segment_index, 42);
    assert_eq!(id1.file_ordinal, 0, "file_ordinal must be 0 (uncounted)");
    assert_eq!(id1.total_files, 0, "total_files must be 0 (uncounted)");

    let id2 = identities
        .get("<tracer-msg-02@example.com>")
        .expect("identity for msg 2");
    assert_eq!(id2.segment_index, 43);
    assert_eq!(id2.file_ordinal, 0, "file_ordinal must be 0 (uncounted)");
    assert_eq!(id2.total_files, 0, "total_files must be 0 (uncounted)");

    // Queue build must propagate explicit indices directly
    let queue = build(&parsed);
    assert_eq!(queue.files.len(), 1);
    let queued_file = &queue.files[0];
    assert_eq!(queued_file.segments.len(), 2);

    assert_eq!(
        queued_file.segments[0].message_id,
        "<tracer-msg-01@example.com>"
    );
    assert_eq!(queued_file.segments[0].segment_index, Some(42));

    assert_eq!(
        queued_file.segments[1].message_id,
        "<tracer-msg-02@example.com>"
    );
    assert_eq!(queued_file.segments[1].segment_index, Some(43));
}

#[test]
fn test_conformance_vectors_penne_nzb_segment_identity() {
    let path = test_vectors_dir().join("nzb_segment_identity.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let fixture: serde_json::Value = serde_json::from_str(&content).unwrap();
    let vectors = fixture["vectors"].as_array().expect("vectors array");

    assert_eq!(vectors.len(), 33, "expected exactly 33 test vectors");
    let mut count = 0;

    for vec in vectors {
        let id = vec["id"].as_str().unwrap();
        let category = vec["category"].as_str().unwrap();
        let nzb_xml = vec["nzb_xml"].as_str().unwrap();

        match category {
            "valid_identity" => {
                let temp = write_temp_nzb(nzb_xml);
                let parsed =
                    load(temp.path()).unwrap_or_else(|e| panic!("vector {id} failed load: {e}"));
                assert!(parsed.meta.yenc_encrypted, "vector {id} must be encrypted");
                assert!(
                    parsed.segment_identities.is_none(),
                    "vector {id} clean NZB 1.1 must have segment_identities: None"
                );

                let queue = build(&parsed);
                let actual: HashMap<&str, Option<u32>> = queue
                    .files
                    .iter()
                    .flat_map(|f| &f.segments)
                    .map(|s| (s.message_id.as_str(), s.segment_index))
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

                    let &actual_index = actual
                        .get(canonical_mid.as_str())
                        .unwrap_or_else(|| panic!("vector {id} missing message {canonical_mid}"));
                    assert_eq!(
                        actual_index, None,
                        "vector {id} clean NZB 1.1 queued segment must have None segment_index"
                    );
                }
                validate_queue_identity(&queue, true).unwrap();
            }
            "legacy_attribute_ignored" => {
                let temp = write_temp_nzb(nzb_xml);
                let parsed = load(temp.path())
                    .unwrap_or_else(|e| panic!("vector {id} failed legacy load: {e}"));
                assert!(parsed.meta.yenc_encrypted, "vector {id} must be encrypted");
                assert!(parsed.segment_identities.is_none());
                let queue = build(&parsed);
                for file in &queue.files {
                    for seg in &file.segments {
                        assert_eq!(seg.segment_index, None);
                    }
                }
                validate_queue_identity(&queue, true).unwrap();
            }
            "invalid_identity" => {
                let temp = write_temp_nzb(nzb_xml);
                let parsed = load(temp.path())
                    .expect("vector invalid_identity standard load succeeds as clean NZB 1.1");
                assert!(parsed.meta.password.is_some());
                let queue = build(&parsed);
                validate_queue_identity(&queue, false).unwrap();
            }
            "unencrypted_compatibility" => {
                let temp = write_temp_nzb(nzb_xml);
                let parsed = load(temp.path())
                    .unwrap_or_else(|e| panic!("vector {id} failed unencrypted parse: {e}"));
                assert!(
                    !parsed.meta.yenc_encrypted,
                    "vector {id} must not be marked encrypted"
                );
                assert!(
                    parsed.segment_identities.is_none(),
                    "vector {id} segment_identities must be None"
                );

                let queue = build(&parsed);
                for file in &queue.files {
                    for seg in &file.segments {
                        assert_eq!(
                            seg.segment_index, None,
                            "vector {id} queued segment must have None segment_index"
                        );
                    }
                }
                validate_queue_identity(&queue, false).unwrap();
            }
            "index_tampering" => {
                let temp = write_temp_nzb(nzb_xml);
                let parsed = load(temp.path()).expect("parse clean nzb 1.1");
                assert!(
                    parsed.meta.yenc_encrypted,
                    "vector {id} must be marked encrypted"
                );
                assert!(parsed.segment_identities.is_none());

                let queue = build(&parsed);
                for file in &queue.files {
                    for seg in &file.segments {
                        assert_eq!(seg.segment_index, None);
                    }
                }
                validate_queue_identity(&queue, true).unwrap();
            }
            other => panic!("unknown category {other}"),
        }
        count += 1;
    }

    assert_eq!(count, 33, "must process exactly 33 vectors");
}

#[test]
fn test_queue_rejects_conflicting_message_id_indices() {
    let queue = DownloadQueue {
        files: vec![QueuedFile {
            name: "conflict.bin".to_string(),
            file_ordinal: Some(1),
            total_files: Some(1),
            segments: vec![
                QueuedSegment {
                    message_id: "same-message@test".to_string(),
                    part: 1,
                    bytes: 100,
                    segment_index: Some(1),
                },
                QueuedSegment {
                    message_id: "same-message@test".to_string(),
                    part: 2,
                    bytes: 100,
                    segment_index: Some(2),
                },
            ],
        }],
    };

    let err = validate_queue_identity(&queue, true).unwrap_err();
    assert!(err.to_string().contains("CONFLICTING_MESSAGE_ID_INDEX"));
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
    assert!(parsed.segment_identities.is_none());

    let queue = build(&parsed);
    assert_eq!(queue.files.len(), 1);
    assert_eq!(queue.files[0].segments[0].segment_index, None);
}
