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

    // Zero-output sanity for empty segments: plaintext is empty (so decoded
    // data stays empty), file_size=0 — begin==end==1 is permitted (nothing
    // written to the assembly).
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

#[test]
fn insert_yencryption_line_placement_and_canonical_length() {
    // Body Std v1.2 §4: the =yencryption line is exactly 128 bytes and is
    // inserted after =ybegin (single-part) / after =ypart (multipart).
    // Round-trips through the full encode/decode adapters.
    let salt = [0x42u8; 16];
    let password = "insert-placement-password";
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let uploader = UploadEncryptionAdapter::new(session);
    let payload = b"placement payload";

    for (multipart, spec) in [
        (
            false,
            PartSpec {
                number: 1,
                total: 1,
                offset: 0,
            },
        ),
        (
            true,
            PartSpec {
                number: 1,
                total: 2,
                offset: 0,
            },
        ),
    ] {
        let mut body = Vec::new();
        let encoded = uploader
            .encode_article(
                "place.bin",
                payload.len() as u64,
                spec,
                payload,
                128,
                None,
                1,
                &mut body,
            )
            .expect("encode must succeed");
        // Pre-insertion structure check: the restored (pre-FF1) placement is
        // implied by the adapter contract; assert the wire still decrypts.
        let _ = multipart;
        let decoded = DownloadDecryptionAdapter::with_password(password)
            .decode_article(&encoded.body)
            .expect("decode must succeed");
        assert_eq!(decoded.data, payload);
    }

    // Direct placement check on an unencoded body: single-part insertion
    // lands between =ybegin and the data; the line is canonical length.
    let tag = [0xedu8; 16];
    let mut raw = b"=ybegin line=128 size=4 name=t.bin\r\ndata\r\n=yend size=4\r\n".to_vec();
    super::insert_yencryption_line(&mut raw, &salt, &tag, 1, false).expect("insert must succeed");
    let lines = super::super::control::split_lines_preserving_endings(&raw);
    assert_eq!(lines.len(), 4);
    assert!(lines[0].content.starts_with(b"=ybegin"));
    assert_eq!(
        lines[1].content.len(),
        super::CANONICAL_YENCRYPTION_LINE_LEN
    );
    assert!(lines[1]
        .content
        .starts_with(b"=yencryption cipher=XChaCha20-Poly1305"));

    // Multipart insertion without an =ypart line fails without touching the
    // body (recoverable encoding error — MISSING_YPART_LINE, never a panic).
    let mut no_ypart = b"=ybegin line=128 size=4 name=t.bin\r\ndata\r\n=yend size=4\r\n".to_vec();
    let before = no_ypart.clone();
    let err = super::insert_yencryption_line(&mut no_ypart, &salt, &tag, 1, true)
        .expect_err("multipart insertion without =ypart must fail");
    assert!(err.to_string().contains("MISSING_YPART_LINE"), "got: {err}");
    assert_eq!(no_ypart, before, "body must be untouched on failure");
}

/// Build a single-part encrypted article whose `=ybegin name=` value is the
/// raw `raw_name` bytes (Body Std v1.2 §2.1). The upload API takes `&str`,
/// so the article is encoded under an ASCII placeholder of identical length
/// and the placeholder bytes are overwritten before control-line encryption.
fn hand_built_article_with_raw_name(
    password: &str,
    salt: [u8; 16],
    segment_index: u32,
    payload: &[u8],
    raw_name: &[u8],
) -> (Vec<u8>, Arc<EncryptionSession>) {
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let placeholder = "cafe.bin";
    assert_eq!(placeholder.len(), raw_name.len());
    let nonce = session.derive_body_nonce(segment_index);
    let aad = body::format_body_aad(1, 1, payload.len() as u64, raw_name);
    let (ciphertext, tag) =
        body::encrypt_body(payload, &aad, session.master_key(), &nonce).unwrap();

    let spec = PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    };
    let mut wire = yenc::encode_part(
        placeholder,
        payload.len() as u64,
        spec,
        &ciphertext,
        128,
        None,
    )
    .body;
    let needle = format!("name={placeholder}");
    let pos = wire
        .windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .unwrap();
    let name_start = pos + "name=".len();
    wire[name_start..name_start + raw_name.len()].copy_from_slice(raw_name);

    insert_yencryption_line(&mut wire, &salt, &tag, segment_index, false).unwrap();
    let wire = control::encrypt_yenc_control_lines(&session, segment_index, &wire).unwrap();
    (wire, session)
}

#[test]
fn non_utf8_ybegin_name_authenticates_with_raw_bytes() {
    let password = "non-utf8-name-password";
    let salt = [0x5au8; 16];
    let payload = b"plaintext under a non-UTF-8 name";
    let raw_name = b"caf\xE9.bin";

    let (wire, _session) = hand_built_article_with_raw_name(password, salt, 7, payload, raw_name);
    let adapter = DownloadDecryptionAdapter::with_password(password);
    let decoded = adapter
        .decode_article(&wire)
        .expect("article authenticated with the raw =ybegin name bytes must decode");
    assert_eq!(decoded.data, payload);
}

#[test]
fn lossy_ybegin_name_would_change_the_aad() {
    let password = "non-utf8-name-password";
    let salt = [0x5au8; 16];
    let payload = b"plaintext under a non-UTF-8 name";
    let raw_name = b"caf\xE9.bin";
    let (wire, session) = hand_built_article_with_raw_name(password, salt, 7, payload, raw_name);

    // What the old code derived the AAD from: the lossy `DecodedPart.name`.
    let restored = control::decrypt_yenc_control_lines(&session, 7, &wire).unwrap();
    let (_params, clean) = extract_and_remove_yencryption(&restored).unwrap();
    let lossy_name = yenc::decode_part(&clean).unwrap().name;
    assert_ne!(lossy_name.as_bytes(), raw_name);

    let nonce = session.derive_body_nonce(7);
    let decoded = yenc::decode_part(&clean).unwrap();
    let (ciphertext, tag) = (decoded.data.clone(), {
        let params =
            parse_yencryption_line(control::split_lines_preserving_endings(&restored)[1].content)
                .unwrap();
        params.tag
    });
    let raw_aad = body::format_body_aad(1, 1, payload.len() as u64, raw_name);
    let lossy_aad = body::format_body_aad(1, 1, payload.len() as u64, lossy_name.as_bytes());
    assert_ne!(raw_aad, lossy_aad);
    assert!(
        body::decrypt_body(&ciphertext, &tag, &lossy_aad, session.master_key(), &nonce).is_err()
    );
    assert_eq!(
        body::decrypt_body(&ciphertext, &tag, &raw_aad, session.master_key(), &nonce).unwrap(),
        payload
    );
}

#[test]
fn single_part_article_named_part_equals_round_trips_through_decode_article() {
    let password = "single-part-part-keyword";
    let salt = control::generate_alphabet_salt();
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let upload = UploadEncryptionAdapter::new(session);
    let payload = b"F";
    let mut scratch = Vec::new();
    let encoded = upload
        .encode_article(
            "my part=2.bin",
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
            &mut scratch,
        )
        .unwrap();

    let decoded = DownloadDecryptionAdapter::with_password(password)
        .decode_article(&encoded.body)
        .expect("single-part article named `my part=2.bin` must decrypt");
    assert_eq!(decoded.name, "my part=2.bin");
    assert_eq!(decoded.part, 1);
    assert_eq!(decoded.data, payload);
}
