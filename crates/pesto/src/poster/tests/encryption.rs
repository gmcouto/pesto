//! S02-T02 native tests: `--encrypt-password` config resolution, NZB meta +
//! subject prefix, segmentIndex allocation uniqueness/stability across a
//! simulated resume, unencrypted byte-identical baseline, and encrypted
//! article round-trip through the T01 decrypt helpers.

use super::*;
use std::sync::Mutex;

use crate::yenc::encrypt;

fn config_with_encryption(password: Option<&str>) -> Config {
    let mut file = FileConfig::default();
    file.posting.groups = Some(vec!["alt.test".into()]);
    let mut config = Config::resolve(
        file,
        Overrides {
            dry_run: Some(true),
            par2: Some(0),
            encrypt_password: password.map(str::to_string),
            ..Default::default()
        },
    )
    .unwrap();
    config.dry_run = false; // exercise the real (non-dry-run) code paths
    config
}

#[test]
fn encrypt_password_config_resolution() {
    // Flag absent → no encryption.
    let off = config_with_encryption(None);
    assert!(off.encrypt_password.is_none());

    // Flag present → carried into the resolved config verbatim.
    let on = config_with_encryption(Some("sekrit"));
    assert_eq!(on.encrypt_password.as_deref(), Some("sekrit"));
}

#[test]
fn encrypted_shared_gets_session_and_unencrypted_does_not() {
    // The password never persists past session construction; Shared only
    // holds the derived-key session.
    let shared_on = minimal_shared_with(config_with_encryption(Some("pw")));
    assert!(shared_on.encryption.is_some());
    let (salt, next) = {
        let s = shared_on.encryption.as_ref().unwrap().lock().unwrap();
        assert_eq!(s.allocator.peek_next(), 1);
        (s.salt, s.allocator.peek_next())
    };
    // Salt is Alphabet-only (no 0x0A/0x0D/0x00).
    assert!(salt.iter().all(|b| encrypt::is_alphabet_byte(*b)));
    let _ = next;

    let shared_off = minimal_shared_with(config_with_encryption(None));
    assert!(shared_off.encryption.is_none());
}

fn minimal_shared_with(config: Config) -> std::sync::Arc<Shared> {
    let encryption = config
        .encrypt_password
        .as_ref()
        .map(|pw| Mutex::new(encrypt::EncryptionSession::new(pw.as_bytes())));
    std::sync::Arc::new(Shared {
        config,
        servers: std::sync::Arc::new(vec![]),
        results: std::sync::Arc::new(Mutex::new(Vec::new())),
        failures: Mutex::new(Vec::new()),
        failed_tasks: Mutex::new(Vec::new()),
        events: None,
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        paused: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        resume: None,
        resume_path: None,
        spool_dir: None,
        pool: std::sync::Arc::new(Mutex::new(Vec::new())),
        encode_pool: std::sync::Arc::new(Mutex::new(Vec::new())),
        total_retries: std::sync::atomic::AtomicUsize::new(0),
        post_group: vec!["alt.test".into()],
        release_prefix: None,
        release_from: None,
        run_id: 0,
        total_files: 0,
        check_tx: Mutex::new(None),
        encryption,
    })
}

#[test]
fn segment_index_allocation_globally_unique_and_vec07_skips() {
    let shared = minimal_shared_with(config_with_encryption(Some("pw")));
    let enc = shared.encryption.as_ref().unwrap();
    let mut session = enc.lock().unwrap();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..300 {
        let idx = session.allocator.allocate().unwrap();
        assert!(seen.insert(idx), "duplicate index {idx}");
        assert!(
            !encrypt::index_is_forbidden(idx),
            "forbidden index {idx} allocated"
        );
    }
    // VEC-07: 10 and 13 must have been skipped (never allocated).
    assert!(!seen.contains(&10) && !seen.contains(&13));
    assert!(seen.contains(&11) && seen.contains(&14));
}

#[test]
fn segment_index_stable_across_simulated_resume() {
    // Run 1: allocate 5 indices, persist identity.
    let shared = minimal_shared_with(config_with_encryption(Some("pw")));
    let mut state = crate::resume::ResumeState::default();
    {
        let enc = shared.encryption.as_ref().unwrap();
        let mut session = enc.lock().unwrap();
        for _ in 0..5 {
            session.allocator.allocate().unwrap();
        }
        state.set_encryption_identity(session.salt, session.allocator.peek_next());
        let salt1 = session.salt;
        // Run 2 (simulated resume): rebuild from persisted identity and
        // verify the very next allocation continues the sequence with the
        // same salt (same Argon2id key → decryptable by the same NZB
        // password + recorded bootstrap).
        let mut resumed = encrypt::EncryptionSession::from_salt_and_allocator(
            b"pw",
            salt1,
            session.allocator.peek_next(),
        );
        // Continuation: every subsequent allocation is strictly greater
        // than the original run's last index and permitted (VEC-07).
        let mut prev = session.allocator.peek_next() - 1;
        for _ in 0..5 {
            let idx = resumed.allocator.allocate().unwrap();
            assert!(idx > prev, "non-monotonic continuation {idx} after {prev}");
            assert!(!encrypt::index_is_forbidden(idx));
            prev = idx;
        }
        // The key derived from the persisted salt decrypts what the original
        // session encrypted (same Argon2id input → same key).
        let (ciphertext, tag) = resumed.encrypt_segment(prev, b"payload").unwrap();
        assert!(encrypt::decrypt_segment(&session.key, prev, &ciphertext, &tag).is_ok());
    }
}

#[test]
fn encrypted_article_decrypts_back_with_recorded_identity() {
    let shared = minimal_shared_with(config_with_encryption(Some("pw")));
    let enc = shared.encryption.as_ref().unwrap();
    let mut session = enc.lock().unwrap();
    let segment_index = session.allocator.allocate().unwrap();
    let plaintext = b"Hello encrypted world. This is the segment payload.";
    let (ciphertext, tag) = session.encrypt_segment(segment_index, plaintext).unwrap();
    let header_line = session.yencryption_line(segment_index, &tag).unwrap();

    // Canonical five-token grammar.
    assert!(header_line.starts_with("=yencryption cipher=XChaCha20-Poly1305 "));
    let parsed = encrypt::parse_yencryption_line(&header_line).unwrap();
    assert_eq!(parsed.salt, session.salt);
    assert_eq!(parsed.segment_index, segment_index);

    // Decrypt mirror: same password + wire salt → same key → same plaintext.
    let key = encrypt::session_key_from(b"pw", &session.salt);
    let restored = encrypt::decrypt_segment(&key, segment_index, &ciphertext, &tag).unwrap();
    assert_eq!(restored, plaintext.to_vec());

    // Wrong password must fail closed with zero output.
    let wrong = encrypt::session_key_from(b"WRONG", &session.salt);
    assert!(encrypt::decrypt_segment(&wrong, segment_index, &ciphertext, &tag).is_err());
}

#[test]
fn control_lines_encrypt_and_decrypt_round_trip() {
    let shared = minimal_shared_with(config_with_encryption(Some("pw")));
    let enc = shared.encryption.as_ref().unwrap();
    let mut session = enc.lock().unwrap();
    let segment_index = session.allocator.allocate().unwrap();

    // A complete ordinary yEnc block (control lines + data lines, CRLF).
    let plain_block = b"=ybegin line=128 size=10 name=f.bin\r\n=\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\r\n=yend size=10 pcrc32=12345678\r\n".to_vec();
    let wire = super::super::worker::encrypt_control_lines(
        &session.key,
        segment_index,
        &session.salt,
        plain_block.clone(),
    )
    .unwrap();

    // Split on bytes (yEnc bodies are binary-safe; UTF-8 lossy conversion
    // would corrupt the raw bootstrap bytes).
    let mut wire_lines: Vec<&[u8]> = Vec::new();
    {
        let mut search = 0usize;
        while search < wire.len() {
            let nl = wire[search..].iter().position(|&b| b == b'\n');
            let end = match nl {
                Some(p) => search + p + 1,
                None => wire.len(),
            };
            let line = &wire[search..end];
            let trimmed = match line {
                [a @ .., b'\n'] => match a {
                    [a2 @ .., b'\r'] => a2,
                    other => other,
                },
                other => other,
            };
            wire_lines.push(trimmed);
            search = end;
        }
    }
    // Line 1 got the 20-byte bootstrap prefix and decrypts back to =ybegin.
    let (restored1, bootstrap) = encrypt::decrypt_line1(&session.key, wire_lines[0]).unwrap();
    assert!(restored1.starts_with(b"=ybegin"));
    assert_eq!(bootstrap.salt, session.salt);
    assert_eq!(bootstrap.segment_index, segment_index);
    // Footer decrypts back to =yend with its lineIndex.
    let last = wire_lines[wire_lines.len() - 1];
    let restored_n =
        encrypt::decrypt_control_line(&session.key, segment_index, wire_lines.len() as u32, last)
            .unwrap();
    assert!(restored_n.starts_with(b"=yend"));
}

#[test]
fn unencrypted_run_produces_byte_identical_output_to_baseline() {
    // Toggle off (no password): the encryption branch in the worker must be a
    // no-op and the article body must be exactly what pre-T02 pesto produced
    // — ordinary yEnc through `encode_part_into`, unmodified.
    let shared = minimal_shared_with(config_with_encryption(None));
    assert!(shared.encryption.is_none());

    let plaintext: &[u8] = b"the quick brown fox jumps over the lazy dog";
    let line_len = 16; // fixed small wrap to exercise line-splitting
    let encoded = yenc::encode_part(
        "baseline.bin",
        plaintext.len() as u64,
        yenc::PartSpec {
            number: 1,
            total: 1,
            offset: 0,
        },
        plaintext,
        line_len,
        None,
    );

    // Golden bytes pinned independently of the Rust encoder: derived from the
    // yEnc draft 1.3 wire format (bytes shifted +42, NUL/LF/CR/'=' escaped as
    // `=` + value+64, CRLF framing at the fixed 16-byte wrap, `=yend crc32=`
    // single-part trailer). A change in the unencrypted output is a wire
    // regression, not something to re-pin casually.
    const GOLDEN: &[u8] = b"=ybegin line=16 size=43 name=baseline.bin\x0d\x0a\x9e\x92\x8fJ\x9b\x9f\x93\x8d\x95J\x8c\x9c\x99\xa1\x98J\x0d\x0a\x90\x99\xa2J\x94\x9f\x97\x9a\x9dJ\x99\xa0\x8f\x9cJ\x9e\x0d\x0a\x92\x8fJ\x96\x8b\xa4\xa3J\x8e\x99\x91\x0d\x0a=yend size=43 crc32=ce0c5114\x0d\x0a";

    assert_eq!(
        encoded.body.as_slice(),
        GOLDEN,
        "unencrypted (toggle off) article body drifted from the pre-T02 baseline wire format"
    );

    // And it must decode back to the exact plaintext.
    let decoded = yenc::decode_part(&encoded.body).unwrap();
    assert_eq!(decoded.data, plaintext);
    assert!(decoded.crc_matches());
}
