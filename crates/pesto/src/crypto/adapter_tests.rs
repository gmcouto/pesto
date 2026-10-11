//! Tests for `DownloadDecryptionAdapter` and `UploadEncryptionAdapter`.

use super::super::{control, kdf::EncryptionSession};
use super::*;
use crate::yenc::{self, PartSpec};
use std::sync::Arc;

#[test]
fn test_multi_salt_session_caching() {
    let password = "multi-salt-cache-password";
    let adapter = DownloadDecryptionAdapter::with_password(password);

    let salt1 = [0x11u8; 16];
    let salt2 = [0x22u8; 16];

    let s1 = adapter.get_or_create_session(salt1).unwrap();
    let s2 = adapter.get_or_create_session(salt2).unwrap();
    assert_eq!(s1.salt(), salt1);
    assert_eq!(s2.salt(), salt2);
    assert!(!Arc::ptr_eq(&s1, &s2));

    // Re-request salt1: must return cached instance (same Arc pointer)
    let s1_again = adapter.get_or_create_session(salt1).unwrap();
    assert!(Arc::ptr_eq(&s1, &s1_again));

    // Re-request salt2: must return cached instance (same Arc pointer)
    let s2_again = adapter.get_or_create_session(salt2).unwrap();
    assert!(Arc::ptr_eq(&s2, &s2_again));
}

#[test]
fn decryption_session_cache_evicts_oldest_entry_at_capacity() {
    let adapter = DownloadDecryptionAdapter::with_password("bounded-session-cache");
    let mut first = None;
    for value in 1u8..=17 {
        let session = adapter.get_or_create_session([value; 16]).unwrap();
        if value == 1 {
            first = Some(session);
        }
    }

    let guard = adapter.cached_sessions.lock().unwrap();
    assert_eq!(guard.0.len(), 16);
    assert!(!guard.0.contains_key(&[1; 16]));
    assert!(guard.0.contains_key(&[17; 16]));
    drop(guard);

    let first_again = adapter.get_or_create_session([1; 16]).unwrap();
    assert!(!Arc::ptr_eq(&first.unwrap(), &first_again));
}

#[test]
fn encrypted_control_lines_round_trip_with_lf_endings() {
    let password = "lf-only-control-lines";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let upload_adapter = UploadEncryptionAdapter::new(session);
    let payload = b"LF-only encrypted control framing";
    let _segment_index = 1u32;
    let mut body = Vec::new();
    let encoded = upload_adapter
        .encode_article(
            "lf.bin",
            payload.len() as u64,
            PartSpec {
                number: 1,
                total: 1,
                offset: 0,
            },
            payload,
            128,
            None,
            1u32,
            &mut body,
        )
        .unwrap();
    let mut lf_wire = encoded.body;
    let mut index = 0;
    while index + 1 < lf_wire.len() {
        if lf_wire[index..].starts_with(b"\r\n") {
            lf_wire.remove(index);
        }
        index += 1;
    }

    let decoded = DownloadDecryptionAdapter::with_password(password)
        .decode_article(&lf_wire)
        .unwrap();
    assert_eq!(decoded.data, payload);
}

#[test]
fn adapter_rejects_unencrypted_article_fail_closed() {
    // A caller that configured transport decryption must never accept a
    // plain `=ybegin` article: that would release unauthenticated plaintext
    // (Zero-Output Guarantee, Body Std v1.2 §7).
    let payload = b"plain unencrypted payload";
    let encoded = yenc::encode_part(
        "plain.bin",
        payload.len() as u64,
        PartSpec {
            number: 1,
            total: 1,
            offset: 0,
        },
        payload,
        128,
        None,
    );
    let err = DownloadDecryptionAdapter::with_password("unused-password")
        .decode_article(&encoded.body)
        .expect_err("unencrypted article must fail closed under a decryptor");
    assert!(
        err.to_string().contains("UNAUTHENTICATED_ARTICLE"),
        "got: {err}"
    );
}

#[test]
fn zero_length_encrypted_body_round_trips() {
    let password = "zero-length-body";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let upload_adapter = UploadEncryptionAdapter::new(session);
    let _segment_index = 1u32;
    let mut body = Vec::new();
    let encoded = upload_adapter
        .encode_article(
            "empty.bin",
            0,
            PartSpec {
                number: 1,
                total: 1,
                offset: 0,
            },
            b"",
            128,
            None,
            1u32,
            &mut body,
        )
        .unwrap();

    let decoded = DownloadDecryptionAdapter::with_password(password)
        .decode_article(&encoded.body)
        .unwrap();
    assert!(decoded.data.is_empty());
    assert_eq!(decoded.file_size, 0);
}

#[test]
fn test_single_part_filename_containing_part_equals() {
    let password = "test-part-equals-password";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let upload_adapter = UploadEncryptionAdapter::new(session);

    let payload = b"Content for file named ep_part=pilot.mkv";
    let spec = PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    };
    let _segment_index = 1u32;
    let mut body = Vec::new();
    let encoded = upload_adapter
        .encode_article(
            "ep_part=pilot.mkv",
            payload.len() as u64,
            spec,
            payload,
            128,
            None,
            1u32,
            &mut body,
        )
        .expect("encode single-part file with part= in filename");

    let download_adapter = DownloadDecryptionAdapter::with_password(password);
    let decoded = download_adapter
        .decode_article(&encoded.body)
        .expect("decode single-part file with part= in filename must succeed");

    assert_eq!(decoded.data, payload);
    assert_eq!(decoded.name, "ep_part=pilot.mkv");
}

#[test]
fn test_multipart_filename_containing_ypart() {
    let password = "test-multipart-ypart-password";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let upload_adapter = UploadEncryptionAdapter::new(session);

    let payload = vec![0x33u8; 1024];
    let spec = PartSpec {
        number: 1,
        total: 2,
        offset: 0,
    };
    let _segment_index = 1u32;
    let mut body = Vec::new();
    let encoded = upload_adapter
        .encode_article(
            "movie=ypart1.mkv",
            2048,
            spec,
            &payload,
            128,
            None,
            1u32,
            &mut body,
        )
        .expect("encode multipart file with =ypart in filename");

    let download_adapter = DownloadDecryptionAdapter::with_password(password);
    let decoded = download_adapter
        .decode_article(&encoded.body)
        .expect("decode multipart file with =ypart in filename must succeed");

    assert_eq!(decoded.data, payload);
    assert_eq!(decoded.name, "movie=ypart1.mkv");
    assert_eq!(decoded.part, 1);
    assert_eq!(decoded.total, 2);
}
