//! T10 integration coverage: fail-closed gating on NZB encryption provenance
//! metadata (Body Encryption Standard v1.2 §8).
//!
//! A declared-encrypted NZB whose `yenc_version`/`yenc_cipher` metadata names
//! an unsupported version/cipher must fail as a STRUCTURAL
//! `MetadataValidation` error (terminal — no provider rotation), and must
//! release no plaintext: no final file, no temp file, no resume-cache entry.

mod support;

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use penne::config::ServerTier;
use penne::nzb::{download_decryptor, load};
use penne::queue::build;
use pesto::crypto::kdf::EncryptionSession;
use pesto::crypto::{crypto_error_kind_of, CryptoErrorKind, UploadEncryptionAdapter};
use pesto::poster::SegmentIdentity;
use pesto::yenc::PartSpec;
use tempfile::NamedTempFile;

use support::{server_entry, spawn_mock_nntp_server};

fn write_temp_nzb(xml: &str) -> NamedTempFile {
    let mut temp = NamedTempFile::new().expect("failed to create temp file");
    temp.write_all(xml.as_bytes()).expect("failed to write XML");
    temp
}

/// NZB with encryption provenance plus one unsupported metadata line.
fn gated_nzb_xml(version_tag: &str, cipher_tag: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">t10-gating-password</meta>
    <meta type="yenc_encrypted">true</meta>
    {version_tag}
    {cipher_tag}
  </head>
  <file poster="uploader@example.com" date="1774300000" subject="[1/1] - &quot;gated.bin&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      <segment bytes="64" number="1">gated-msg-01@example.com</segment>
    </segments>
  </file>
</nzb>"#
    )
}

fn valid_article(password: &str) -> Vec<u8> {
    let salt = pesto::crypto::control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let uploader = UploadEncryptionAdapter::new(session);
    let identity = SegmentIdentity::checked(0, 1, 1, 1)
        .expect("prefix 0 + ordinal 1 + part 1 must form a valid identity");
    let payload = b"T10 gating payload that must never reach disk";
    let mut encoded_body = Vec::new();
    let encoded = uploader
        .encode_article(
            "gated.bin",
            payload.len() as u64,
            PartSpec {
                number: 1,
                total: 1,
                offset: 0,
            },
            payload,
            128,
            None,
            identity,
            &mut encoded_body,
        )
        .expect("encode article failed");
    encoded.body
}

/// Run the penne NZB-load path for an NZB whose `yenc_version`/`yenc_cipher`
/// metadata is expected to fail the reader's T10 gate, and assert the
/// failure is terminal `MetadataValidation`. The mock server exists to prove
/// the gate fires before any network fetch could matter.
async fn assert_gated_download_rejected(
    version_tag: &str,
    cipher_tag: &str,
    dest: &std::path::Path,
) {
    let password = "t10-gating-password";
    let mut known = HashMap::new();
    known.insert(
        "gated-msg-01@example.com".to_string(),
        valid_article(password),
    );
    let addr = spawn_mock_nntp_server(known, None);

    let xml = gated_nzb_xml(version_tag, cipher_tag);
    let nzb_file = write_temp_nzb(&xml);

    // The gate is the NZB reader itself: loading fails closed before any
    // queue, decryptor, or NNTP connection exists.
    let err = load(nzb_file.path()).expect_err("unsupported metadata must fail the T10 gate");
    let kind = crypto_error_kind_of(&err).expect("gate failure must carry a typed kind");
    assert_eq!(
        CryptoErrorKind::MetadataValidation,
        kind,
        "unsupported metadata must be classified MetadataValidation, got: {err:#}"
    );
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("unsupported yenc_version")
            || rendered.contains("unsupported yenc_cipher"),
        "gate failure must name the unsupported metadata, got: {rendered}"
    );

    // Zero-output: no article was ever fetched for a gated NZB, so no
    // plaintext file or temp sibling can exist in the destination.
    assert!(
        !dest.join("gated.bin").exists(),
        "no plaintext file may exist for a gated NZB"
    );
    assert!(
        !dest.join("gated.bin.penne-part").exists(),
        "no temp file may exist for a gated NZB"
    );
    let _ = addr; // server never contacted for article data by the gated path
}

#[tokio::test]
async fn unsupported_yenc_version_fails_as_metadata_validation_releasing_no_plaintext() {
    let dest = tempfile::tempdir().unwrap();
    assert_gated_download_rejected(
        r#"<meta type="yenc_version">2.0</meta>"#,
        r#"<meta type="yenc_cipher">XChaCha20-Poly1305</meta>"#,
        dest.path(),
    )
    .await;
}

#[tokio::test]
async fn unsupported_yenc_cipher_fails_as_metadata_validation_releasing_no_plaintext() {
    let dest = tempfile::tempdir().unwrap();
    assert_gated_download_rejected(
        r#"<meta type="yenc_version">1.2</meta>"#,
        r#"<meta type="yenc_cipher">AES-256-GCM</meta>"#,
        dest.path(),
    )
    .await;
}

#[tokio::test]
async fn supported_metadata_passes_the_gate_and_downloads() {
    // Control: the same harness with supported metadata downloads the
    // plaintext normally (the gate fires on unsupported values only).
    let password = "t10-gating-password";
    let mut known = HashMap::new();
    known.insert(
        "gated-msg-01@example.com".to_string(),
        valid_article(password),
    );
    let addr = spawn_mock_nntp_server(known, None);

    let xml = gated_nzb_xml(
        r#"<meta type="yenc_version">1.2</meta>"#,
        r#"<meta type="yenc_cipher">XChaCha20-Poly1305</meta>"#,
    );
    let nzb_file = write_temp_nzb(&xml);
    let parsed = load(nzb_file.path()).expect("supported metadata must pass the gate");
    let queue = build(&parsed);
    let decryptor = download_decryptor(&parsed.meta)
        .expect("decryptor construction must succeed")
        .expect("encrypted NZB must yield a decryptor");

    let dest = tempfile::tempdir().unwrap();
    let outcome = penne::download::download_queue_with_decryptor(
        &queue,
        &[ServerTier::solo(server_entry(addr))],
        dest.path(),
        0,
        None,
        Some(decryptor),
    )
    .await
    .expect("download must succeed for supported metadata");

    assert!(
        outcome.corrupt.is_empty(),
        "no corrupt segments expected, got: {:?}",
        outcome.corrupt
    );
    let disk = std::fs::read(dest.path().join("gated.bin")).unwrap();
    assert_eq!(
        disk,
        b"T10 gating payload that must never reach disk".to_vec(),
        "plaintext must match for the control case"
    );
}
