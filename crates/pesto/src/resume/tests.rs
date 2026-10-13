use super::*;

fn fp(article_size: u64) -> RunFingerprint {
    RunFingerprint {
        article_size,
        obfuscate: ObfuscateMode::None,
        compress_format: None,
        par2_percent: 0,
        file_counter: false,
        par2_slice_size: None,
        par2_slice_count: None,
        par2_recovery_count: None,
        compress_volume_size: None,
        compress_password: None,
        encrypt_password: None,
        line_length: 128,
    }
}

#[test]
fn round_trip() {
    let mut s = ResumeState::default();
    s.record("file.bin", 1, "abc@example.com", 100);
    s.record("file.bin", 2, "def@example.com", 200);
    assert_eq!(s.get("file.bin", 1).unwrap().message_id, "abc@example.com");
    assert_eq!(s.get("file.bin", 1).unwrap().bytes, 100);
    assert!(s.get("file.bin", 3).is_none());
    assert_eq!(s.len(), 2);
}

#[test]
fn remove_forgets_a_recorded_segment() {
    let mut s = ResumeState::default();
    s.record("file.bin", 1, "abc@example.com", 100);
    s.record("file.bin", 2, "def@example.com", 200);
    s.remove("file.bin", 1);
    assert!(s.get("file.bin", 1).is_none());
    assert_eq!(s.get("file.bin", 2).unwrap().message_id, "def@example.com");
    assert_eq!(s.len(), 1);
}

#[test]
fn remove_of_an_unrecorded_segment_is_a_no_op() {
    let mut s = ResumeState::default();
    s.record("file.bin", 1, "abc@example.com", 100);
    s.remove("file.bin", 99);
    assert_eq!(s.len(), 1);
}

#[test]
fn save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let mut s = ResumeState::default();
    s.record("a.bin", 1, "id1@x", 100);
    s.save(&path).unwrap();
    let loaded = ResumeState::load(&path).unwrap();
    assert_eq!(loaded.get("a.bin", 1).unwrap().message_id, "id1@x");
    assert_eq!(loaded.get("a.bin", 1).unwrap().bytes, 100);
}

#[test]
fn missing_file_returns_empty() {
    let state = ResumeState::load(Path::new("/nonexistent/path.json")).unwrap();
    assert!(state.is_empty());
}

#[test]
fn fresh_state_accepts_any_fingerprint() {
    let mut s = ResumeState::default();
    assert!(s.validate_run(&fp(768_000)));
}

#[test]
fn matching_fingerprint_keeps_segments() {
    let mut s = ResumeState::default();
    assert!(s.validate_run(&fp(768_000)));
    s.record("a.bin", 1, "id1@x", 100);
    assert!(s.validate_run(&fp(768_000)));
    assert_eq!(s.len(), 1, "matching fingerprint must not clear segments");
}

#[test]
fn mismatched_fingerprint_discards_everything() {
    let mut s = ResumeState::default();
    assert!(s.validate_run(&fp(768_000)));
    s.record_file(
        "a.bin",
        FileFingerprint {
            size: 10,
            mtime: Some(1),
        },
    );
    s.record("a.bin", 1, "id1@x", 100);
    s.set_archive_stem("Xk3mQp".to_string());
    // A resume run using a different --article-size than the original.
    assert!(!s.validate_run(&fp(384_000)));
    assert_eq!(s.len(), 0, "mismatched fingerprint must discard segments");
    assert!(
        s.file_matches(
            "a.bin",
            &FileFingerprint {
                size: 10,
                mtime: Some(1)
            }
        ),
        "per-file fingerprints must be cleared too"
    );
    assert_eq!(
        s.archive_stem(),
        None,
        "archive stem must be cleared too — reusing it for incompatible parameters is unsafe"
    );
}

#[test]
fn archive_stem_survives_a_matching_fingerprint() {
    let mut s = ResumeState::default();
    assert!(s.validate_run(&fp(768_000)));
    s.set_archive_stem("Xk3mQp".to_string());
    assert!(s.validate_run(&fp(768_000)));
    assert_eq!(s.archive_stem(), Some("Xk3mQp"));
}

#[test]
fn encrypt_password_fingerprint_invalidation() {
    let mut s = ResumeState::default();
    let mut fp1 = fp(768_000);
    fp1.encrypt_password = Some(hash_secret("pw1"));
    assert!(s.validate_run(&fp1));
    assert!(s.validate_run(&fp1));

    let mut fp2 = fp(768_000);
    fp2.encrypt_password = Some(hash_secret("pw2"));
    assert!(!s.validate_run(&fp2));
}

#[test]
fn fingerprint_mismatch_invalidates_session_identity_and_salt() {
    use crate::poster::ReleaseLayout;

    let mut s = ResumeState::default();
    let fp1 = fp(768_000);
    assert!(s.validate_run(&fp1));

    let salt = [0x55u8; 16];
    let layout = ReleaseLayout::from_parts(1, &[(1, 2)]).unwrap();
    s.set_session_identity(UploadSessionIdentity::new(salt, layout));
    s.record("a.bin", 1, "id1@x", 100);
    assert_eq!(s.session_salt(), Some(&salt));

    // Matching fingerprint preserves salt and identity.
    assert!(s.validate_run(&fp1));
    assert_eq!(s.session_salt(), Some(&salt));
    assert_eq!(s.len(), 1);

    // Parameter change (e.g. article size changed 768k -> 384k):
    // even if layout part count could stay the same on another file,
    // a fingerprint mismatch MUST invalidate the session salt to prevent nonce reuse .
    let fp2 = fp(384_000);
    assert!(!s.validate_run(&fp2));
    assert!(
        s.session_salt().is_none(),
        "salt must be cleared on fingerprint change"
    );
    assert!(
        s.take_session_invalidated(),
        "session_invalidated flag must be set for spool cleanup"
    );
    assert_eq!(s.len(), 0, "segments must be cleared");
}

#[test]
fn file_matches_is_permissive_when_nothing_was_recorded() {
    let s = ResumeState::default();
    assert!(s.file_matches(
        "new.bin",
        &FileFingerprint {
            size: 5,
            mtime: Some(1)
        }
    ));
}

#[test]
fn file_matches_detects_content_change() {
    let mut s = ResumeState::default();
    s.record_file(
        "a.bin",
        FileFingerprint {
            size: 100,
            mtime: Some(1000),
        },
    );
    assert!(s.file_matches(
        "a.bin",
        &FileFingerprint {
            size: 100,
            mtime: Some(1000)
        }
    ));
    assert!(!s.file_matches(
        "a.bin",
        &FileFingerprint {
            size: 200,
            mtime: Some(1000)
        }
    ));
    assert!(!s.file_matches(
        "a.bin",
        &FileFingerprint {
            size: 100,
            mtime: Some(2000)
        }
    ));
}

#[test]
fn forget_file_only_removes_that_files_segments() {
    let mut s = ResumeState::default();
    s.record("a.bin", 1, "id1@x", 10);
    s.record("a.bin", 2, "id2@x", 10);
    s.record("b.bin", 1, "id3@x", 10);
    s.forget_file("a.bin");
    assert!(s.get("a.bin", 1).is_none());
    assert!(s.get("a.bin", 2).is_none());
    assert!(s.get("b.bin", 1).is_some());
}

#[test]
fn forget_all_segments_clears_everything_including_par2_volumes() {
    let mut s = ResumeState::default();
    s.record("movie.mkv", 1, "id1@x", 10);
    s.record("movie.mkv.vol000+001.par2", 1, "id2@x", 10);
    s.record_file(
        "movie.mkv",
        FileFingerprint {
            size: 100,
            mtime: Some(1),
        },
    );
    s.forget_all_segments();
    assert!(s.get("movie.mkv", 1).is_none());
    assert!(s.get("movie.mkv.vol000+001.par2", 1).is_none());
    assert_eq!(s.len(), 0);
    // Per-file fingerprints survive — an unrelated file's identity is
    // still worth remembering.
    assert!(s.file_matches(
        "movie.mkv",
        &FileFingerprint {
            size: 100,
            mtime: Some(1)
        }
    ));
}

#[test]
fn corrupt_state_file_loads_as_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, "this is not json {").unwrap();
    let loaded = ResumeState::load(&path).unwrap();
    assert!(loaded.is_empty());
}

#[test]
fn save_is_readable_after_replace() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let mut s = ResumeState::default();
    s.record("a.bin", 1, "id1@x", 100);
    s.save(&path).unwrap();
    assert!(!path.with_file_name("state.json.tmp").exists());
    let loaded = ResumeState::load(&path).unwrap();
    assert_eq!(loaded.get("a.bin", 1).unwrap().message_id, "id1@x");
}

#[test]
fn each_new_fingerprint_field_changes_identity() {
    let base = fp(768_000);
    let mut slice = base.clone();
    slice.par2_slice_size = Some(4096);
    assert_ne!(base, slice);

    let mut count = base.clone();
    count.par2_slice_count = Some(100);
    assert_ne!(base, count);

    let mut rec = base.clone();
    rec.par2_recovery_count = Some(20);
    assert_ne!(base, rec);

    let mut vol = base.clone();
    vol.compress_volume_size = Some("500m".into());
    assert_ne!(base, vol);

    let mut pw = base.clone();
    pw.compress_password = Some(hash_secret("secret"));
    assert_ne!(base, pw);

    let mut ll = base.clone();
    ll.line_length = 256;
    assert_ne!(base, ll);
}

#[test]
fn pre_schema_json_defaults_new_fields() {
    let json = r#"{"files":{},"segments":{"a.bin\u00001":{"message_id":"id1@x","bytes":100}}}"#;
    let loaded: ResumeState = serde_json::from_str(json).unwrap();
    let rec = loaded.get("a.bin", 1).unwrap();
    assert_eq!(rec.message_id, "id1@x");
    assert_eq!(rec.bytes, 100);
    assert!(!rec.confirmed);
    assert!(!rec.check_disabled);
    assert_eq!(rec.server_idx, 0);
}

#[test]
fn mark_confirmed_flips_only_that_record() {
    let mut s = ResumeState::default();
    s.record_with(
        "a.bin",
        1,
        SegmentRecord {
            message_id: "id1@x".into(),
            bytes: 100,
            confirmed: false,
            check_disabled: true,
            server_idx: 2,
            wire_identity: None,
        },
    );
    s.record("a.bin", 2, "id2@x", 50);
    s.mark_confirmed("a.bin", 1);
    let rec = s.get("a.bin", 1).unwrap();
    assert!(rec.confirmed);
    assert!(!rec.check_disabled);
    assert_eq!(rec.server_idx, 2);
    assert!(!s.get("a.bin", 2).unwrap().confirmed);
}

#[test]
fn resume_action_three_arms() {
    let confirmed = SegmentRecord {
        message_id: "id@x".into(),
        bytes: 1,
        confirmed: true,
        check_disabled: false,
        server_idx: 0,
        wire_identity: None,
    };
    let unconfirmed = SegmentRecord {
        confirmed: false,
        ..confirmed.clone()
    };
    let check_off = SegmentRecord {
        confirmed: false,
        check_disabled: true,
        ..confirmed.clone()
    };
    assert_eq!(resume_action(true, None), ResumeAction::Post);
    assert_eq!(resume_action(false, None), ResumeAction::Post);
    assert_eq!(resume_action(false, Some(&unconfirmed)), ResumeAction::Skip);
    assert_eq!(resume_action(false, Some(&check_off)), ResumeAction::Skip);
    assert_eq!(resume_action(false, Some(&confirmed)), ResumeAction::Skip);
    assert_eq!(resume_action(true, Some(&confirmed)), ResumeAction::Skip);
    assert_eq!(
        resume_action(true, Some(&unconfirmed)),
        ResumeAction::ReStatStoredId
    );
    assert_eq!(
        resume_action(true, Some(&check_off)),
        ResumeAction::ReStatStoredId
    );
}

#[test]
fn no_check_record_never_sets_confirmed() {
    let mut s = ResumeState::default();
    s.record_with(
        "a.bin",
        1,
        SegmentRecord {
            message_id: "id@x".into(),
            bytes: 10,
            confirmed: false,
            check_disabled: true,
            server_idx: 0,
            wire_identity: None,
        },
    );
    let rec = s.get("a.bin", 1).unwrap();
    assert!(!rec.confirmed && rec.check_disabled);
}

#[test]
fn session_identity_round_trip() {
    use crate::poster::ReleaseLayout;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session_state.json");
    let mut state = ResumeState::default();

    let salt = [0x5au8; 16];
    let layout = ReleaseLayout::from_parts(2, &[(1, 2), (2, 3)]).unwrap();
    state.set_session_identity(UploadSessionIdentity::new(salt, layout.clone()));

    state.record_with(
        "file1.bin",
        1,
        SegmentRecord {
            message_id: "msg1@example.com".into(),
            bytes: 1024,
            confirmed: true,
            check_disabled: false,
            server_idx: 1,
            wire_identity: None,
        },
    );

    state.save(&path).unwrap();

    // Serialized state contains no plaintext password.
    let serialized = std::fs::read_to_string(&path).unwrap();
    assert!(!serialized.contains("password"));
    assert!(!serialized.contains("secret"));

    // Load back: salt/layout/record identity all survive.
    let loaded = ResumeState::load(&path).unwrap();
    assert_eq!(loaded.session_salt(), Some(&salt));
    assert_eq!(
        loaded.session_identity.as_ref().map(|s| &s.layout),
        Some(&layout)
    );
    let rec = loaded.get("file1.bin", 1).unwrap();
    assert_eq!(rec.message_id, "msg1@example.com");
    assert_eq!(rec.bytes, 1024);

    // Repeated save/load is idempotent.
    let path2 = dir.path().join("session_state_2.json");
    loaded.save(&path2).unwrap();
    let mut loaded2 = ResumeState::load(&path2).unwrap();
    assert_eq!(loaded.session_salt(), loaded2.session_salt());
    assert_eq!(loaded.get("file1.bin", 1), loaded2.get("file1.bin", 1));

    // The unchanged layout still validates on the loaded state, and a
    // pre-schema record (no session identity) loads with identity unset.
    assert!(loaded2.validate_session(&layout));
    let json = r#"{"files":{},"segments":{"a.bin\u00001":{"message_id":"id1@x","bytes":100}}}"#;
    let loaded: ResumeState = serde_json::from_str(json).unwrap();
    assert!(loaded.session_salt().is_none());
    assert_eq!(loaded.get("a.bin", 1).unwrap().message_id, "id1@x");
}

#[test]
fn session_validation_invalidates_all_state_on_layout_mismatches() {
    use crate::poster::ReleaseLayout;

    let base_parts = &[(1, 2), (2, 3)];
    let base_layout = ReleaseLayout::from_parts(2, base_parts).unwrap();
    let salt = [0xabu8; 16];

    let make_state = || {
        let mut s = ResumeState::default();
        s.set_session_identity(UploadSessionIdentity::new(salt, base_layout.clone()));
        s.set_archive_stem("arch_stem".into());
        s.set_release_identity("rel_prefix".into(), "rel_from".into());
        s.record_file(
            "a.bin",
            FileFingerprint {
                size: 200,
                mtime: Some(100),
            },
        );
        s.record_file(
            "b.bin",
            FileFingerprint {
                size: 300,
                mtime: Some(100),
            },
        );
        s
    };

    // Added file (total_files: 3 instead of 2)
    let mut s = make_state();
    let added_layout = ReleaseLayout::from_parts(3, &[(1, 2), (2, 3), (3, 1)]).unwrap();
    assert!(!s.validate_session(&added_layout));
    assert!(s.session_salt().is_none());
    assert!(s.archive_stem().is_none());
    assert!(s.release_identity().is_none());
    assert_eq!(s.len(), 0);
    assert!(s.file_matches(
        "a.bin",
        &FileFingerprint {
            size: 999,
            mtime: None
        }
    )); // files cleared

    // Removed file (total_files: 1 instead of 2)
    let mut s = make_state();
    let removed_layout = ReleaseLayout::from_parts(1, &[(1, 2)]).unwrap();
    assert!(!s.validate_session(&removed_layout));
    assert!(s.session_salt().is_none());
    assert_eq!(s.len(), 0);

    // Resized file (parts for file 1: 5 instead of 2)
    let mut s = make_state();
    let resized_layout = ReleaseLayout::from_parts(2, &[(1, 5), (2, 3)]).unwrap();
    assert!(!s.validate_session(&resized_layout));
    assert!(s.session_salt().is_none());
    assert_eq!(s.len(), 0);
}
