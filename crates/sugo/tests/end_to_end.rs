//! Full pipeline test: a fake NNTP server, the real background job worker,
//! and the pipeline (`crates/sugo/src/job/pipeline.rs`) — a job staged
//! into the queue is actually fetched, assembled, and lands in history,
//! mirroring `crates/penne/tests/cli_download_end_to_end.rs`'s coverage of
//! `penne download` itself but through this crate's job engine instead of
//! the CLI.

mod support;

use std::collections::HashMap;
use std::time::Duration;

use pesto::nzb::NzbMeta;
use pesto::poster::PostedSegment;
use pesto::yenc::{encode_part, PartSpec};

#[tokio::test]
async fn a_staged_job_downloads_and_lands_in_history() {
    let data = b"hello from sugo end-to-end test".to_vec();
    let encoded = encode_part(
        "greeting.txt",
        data.len() as u64,
        PartSpec {
            number: 1,
            total: 1,
            offset: 0,
        },
        &data,
        128,
        None,
    );
    let article_len = encoded.body.len() as u64;

    let mut known = HashMap::new();
    known.insert("art1@test", encoded.body);
    let addr = support::spawn_fake_server(known);

    let dir = tempfile::tempdir().unwrap();
    let download_dir = dir.path().join("downloads");
    let config = support::test_web_config(&download_dir, addr.port(), "secret");
    let state = support::build_state(dir.path().join("data"), config);
    sugo::job::worker::spawn(state.clone());

    let groups = vec!["alt.binaries.test".to_string()];
    let segments = vec![PostedSegment {
        file_name: "greeting.txt".into(),
        file_path: std::path::Path::new("greeting.txt").into(),
        subject_name: "greeting.txt".into(),
        wire_name: "greeting.txt".into(),
        wire_yenc_name: "greeting.txt".into(),
        file_size: article_len.max(data.len() as u64),
        part: 1,
        total: 1,
        message_id: "<art1@test>".into(),
        bytes: article_len.max(data.len() as u64),
        from: "poster <p@x>".into(),
        date: (None, None),
        full_crc32: 0,
        server_idx: 0,
        file_index: 0,
        total_files: 0,
        segment_index: 0,
    }];
    let nzb_bytes = pesto::nzb::generate(
        &groups,
        &segments,
        &NzbMeta::default(),
        pesto::config::ObfuscateMode::None,
    )
    .into_bytes();

    let job = sugo::job::stage_and_create(&state, "greeting.nzb", None, nzb_bytes)
        .await
        .unwrap();
    state.jobs.write().await.enqueue(job);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        {
            let store = state.jobs.read().await;
            if let Some(finished) = store.history.first() {
                assert_eq!(
                    finished.status,
                    sugo::job::JobStatus::Completed,
                    "job finished with an unexpected status: {:?} ({:?})",
                    finished.status,
                    finished.message
                );
                assert_eq!(
                    finished.files.len(),
                    1,
                    "expected one per-file progress entry"
                );
                assert!(
                    finished
                        .files
                        .iter()
                        .all(|f| f.done && f.bytes_done == f.bytes_total),
                    "every file should be marked done with bytes_done == bytes_total: {:?}",
                    finished.files
                );
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "job did not reach history within the timeout"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // `stage_and_create` gives each job its own subdirectory
    // (`download_dir/<job name>/`), named after the `.nzb`'s file stem.
    let written = std::fs::read(download_dir.join("greeting").join("greeting.txt")).unwrap();
    assert_eq!(written, data);
}

#[tokio::test]
async fn encrypted_nzb_sugo_job_round_trip() {
    let password = "sugo-secret-password-12345";
    let salt = pesto::crypto::generate_alphabet_salt();
    let session =
        std::sync::Arc::new(pesto::crypto::EncryptionSession::new(password, salt).unwrap());
    let adapter = pesto::crypto::UploadEncryptionAdapter::new(session);

    let original = b"Plaintext content payload for encrypted Sugo job test!";
    let spec = PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    };
    let mut body = Vec::new();
    let encoded = adapter
        .encode_article(
            "sugo_secret.bin",
            original.len() as u64,
            spec,
            original,
            128,
            None,
            1,
            &mut body,
        )
        .unwrap();

    let mut known = HashMap::new();
    known.insert("sugo_enc1@test", encoded.body);
    let addr = support::spawn_fake_server(known);

    let dir = tempfile::tempdir().unwrap();
    let download_dir = dir.path().join("downloads");
    let config = support::test_web_config(&download_dir, addr.port(), "secret");
    let state = support::build_state(dir.path().join("data"), config);
    sugo::job::worker::spawn(state.clone());

    let groups = vec!["alt.binaries.test".to_string()];
    let segments = vec![PostedSegment {
        file_name: "sugo_secret.bin".into(),
        file_path: std::path::Path::new("sugo_secret.bin").into(),
        subject_name: "sugo_secret.bin".into(),
        wire_name: "sugo_secret.bin".into(),
        wire_yenc_name: "sugo_secret.bin".into(),
        file_size: original.len() as u64,
        part: 1,
        total: 1,
        message_id: "<sugo_enc1@test>".into(),
        bytes: original.len() as u64,
        from: "poster <p@x>".into(),
        date: (None, None),
        full_crc32: 0,
        server_idx: 0,
        file_index: 1,
        total_files: 1,
        segment_index: 0,
    }];
    let meta = NzbMeta {
        password: Some(password.to_string()),
        yenc_encrypted: true,
        ..Default::default()
    };
    let nzb_bytes = pesto::nzb::generate(
        &groups,
        &segments,
        &meta,
        pesto::config::ObfuscateMode::None,
    )
    .into_bytes();

    let job = sugo::job::stage_and_create(&state, "sugo_secret.nzb", None, nzb_bytes)
        .await
        .unwrap();
    state.jobs.write().await.enqueue(job);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        {
            let store = state.jobs.read().await;
            if let Some(finished) = store.history.first() {
                assert_eq!(
                    finished.status,
                    sugo::job::JobStatus::Completed,
                    "job finished with unexpected status: {:?}",
                    finished.status
                );
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "job did not reach history within the timeout"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let written = std::fs::read(download_dir.join("sugo_secret").join("sugo_secret.bin")).unwrap();
    assert_eq!(written, original);
}

#[tokio::test]
async fn encrypted_nzb_sugo_tampered_job_fails_cleanly() {
    let password = "sugo-tamper-canary-pass-999";
    let salt = pesto::crypto::generate_alphabet_salt();
    let session =
        std::sync::Arc::new(pesto::crypto::EncryptionSession::new(password, salt).unwrap());
    let adapter = pesto::crypto::UploadEncryptionAdapter::new(session);

    let original = b"Plaintext content that must never be committed when tampered!";
    let spec = PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    };
    let mut body = Vec::new();
    let encoded = adapter
        .encode_article(
            "tampered.bin",
            original.len() as u64,
            spec,
            original,
            128,
            None,
            1,
            &mut body,
        )
        .unwrap();

    // Mutate data line in ciphertext
    let mut lines: Vec<Vec<u8>> = encoded
        .body
        .split_inclusive(|&b| b == b'\n')
        .map(|l| l.to_vec())
        .collect();
    lines[2][0] ^= 0x01;
    let tampered_body: Vec<u8> = lines.into_iter().flatten().collect();

    let mut known = HashMap::new();
    known.insert("sugo_tamper@test", tampered_body);
    let addr = support::spawn_fake_server(known);

    let dir = tempfile::tempdir().unwrap();
    let download_dir = dir.path().join("downloads");
    let config = support::test_web_config(&download_dir, addr.port(), "secret");
    let state = support::build_state(dir.path().join("data"), config);
    sugo::job::worker::spawn(state.clone());

    let groups = vec!["alt.binaries.test".to_string()];
    let segments = vec![PostedSegment {
        file_name: "tampered.bin".into(),
        file_path: std::path::Path::new("tampered.bin").into(),
        subject_name: "tampered.bin".into(),
        wire_name: "tampered.bin".into(),
        wire_yenc_name: "tampered.bin".into(),
        file_size: original.len() as u64,
        part: 1,
        total: 1,
        message_id: "<sugo_tamper@test>".into(),
        bytes: original.len() as u64,
        from: "poster <p@x>".into(),
        date: (None, None),
        full_crc32: 0,
        server_idx: 0,
        file_index: 1,
        total_files: 1,
        segment_index: 0,
    }];
    let meta = NzbMeta {
        password: Some(password.to_string()),
        yenc_encrypted: true,
        ..Default::default()
    };
    let nzb_bytes = pesto::nzb::generate(
        &groups,
        &segments,
        &meta,
        pesto::config::ObfuscateMode::None,
    )
    .into_bytes();

    let job = sugo::job::stage_and_create(&state, "tampered.nzb", None, nzb_bytes)
        .await
        .unwrap();
    state.jobs.write().await.enqueue(job);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        {
            let store = state.jobs.read().await;
            if let Some(finished) = store.history.first() {
                assert_eq!(
                    finished.status,
                    sugo::job::JobStatus::Failed,
                    "expected JobStatus::Failed for tampered job, got: {:?}",
                    finished.status
                );
                // Canary must not be in error message
                if let Some(ref msg) = finished.message {
                    assert!(
                        !msg.contains(password),
                        "error message leaked password canary"
                    );
                }
                break;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "job did not reach history within the timeout"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Zero-output guarantee: final file and temp sibling must not exist
    // (penne's temp suffix is `.penne-part`, not `.tmp`).
    let output_file = download_dir.join("tampered").join("tampered.bin");
    assert!(!output_file.exists(), "unauthenticated file must not exist");
    let tmp_file = download_dir
        .join("tampered")
        .join("tampered.bin.penne-part");
    assert!(!tmp_file.exists(), "temp file must not exist");
}
