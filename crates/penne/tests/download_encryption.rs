//! Consolidated Penne encrypted-download integration tests:
//! multipart decrypt round trip, tamper failover, zero output/no cache on
//! authentication failure, spoof rejection, cache resume, boundary segment
//! indices, real-PAR2 verify/repair assertions, and the negative-case
//! failures with true causes (wrong password, truncation, malformed
//! `=yencryption`, true Poly1305 tag failure).

mod support;

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use pesto::config::ServerEntry;
use pesto::crypto::{DownloadDecryptionAdapter, EncryptionSession, UploadEncryptionAdapter};
use pesto::yenc::{encode_part, PartSpec};
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};

use penne::config::ServerTier;
use penne::download::{download_queue, download_queue_with_decryptor, DownloadOutcome};
use penne::nzb::{download_decryptor, load};
use penne::queue::build;
use penne::repair::{verify_and_repair, RepairOutcome};

use support::{build_fixture_set, FixtureFile};

/// Spawn a fake NNTP server that only understands `BODY` and `QUIT` — the
/// commands `download_queue_with_decryptor` actually sends.
fn spawn_fake_server(known: HashMap<String, Vec<u8>>) -> SocketAddr {
    spawn_fake_server_counting(known, None)
}

/// Same, with an optional BODY-request counter (used to prove a cached run
/// makes zero network requests).
fn spawn_fake_server_counting(
    known: HashMap<String, Vec<u8>>,
    counter: Option<Arc<AtomicUsize>>,
) -> SocketAddr {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    let listener = TcpListener::from_std(std_listener).unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(handle_connection(stream, known.clone(), counter.clone()));
        }
    });

    addr
}

async fn handle_connection(
    stream: TcpStream,
    known: HashMap<String, Vec<u8>>,
    counter: Option<Arc<AtomicUsize>>,
) {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    if w.write_all(b"200 mock ready\r\n").await.is_err() {
        return;
    }

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let cmd = line.trim_end();

        if let Some(rest) = cmd.strip_prefix("BODY ") {
            if let Some(ref c) = counter {
                c.fetch_add(1, Ordering::SeqCst);
            }
            let id = rest.trim_start_matches('<').trim_end_matches('>');
            match known.get(id) {
                Some(body) => {
                    let header = format!("222 0 <{id}> body\r\n");
                    if w.write_all(header.as_bytes()).await.is_err()
                        || write_dot_stuffed(&mut w, body).await.is_err()
                        || w.write_all(b".\r\n").await.is_err()
                    {
                        return;
                    }
                }
                None => {
                    if w.write_all(b"430 No such article\r\n").await.is_err() {
                        return;
                    }
                }
            }
        } else if cmd == "QUIT" {
            let _ = w.write_all(b"205 bye\r\n").await;
            return;
        } else if w.write_all(b"500 unknown command\r\n").await.is_err() {
            return;
        }
    }
}

async fn write_dot_stuffed(w: &mut OwnedWriteHalf, body: &[u8]) -> std::io::Result<()> {
    for line in body.split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b".") {
            w.write_all(b".").await?;
        }
        w.write_all(line).await?;
    }
    Ok(())
}

fn server_entry(addr: SocketAddr) -> ServerEntry {
    ServerEntry {
        host: addr.ip().to_string(),
        port: addr.port(),
        ssl: false,
        connections: 1,
        username: None,
        password: None,
        retry_delay: 0,
        timeout: 5,
        proxy: None,
    }
}

fn write_temp_nzb(xml: &str) -> NamedTempFile {
    let mut temp = NamedTempFile::new().expect("failed to create temp file");
    temp.write_all(xml.as_bytes()).expect("failed to write XML");
    temp
}

fn encrypted_nzb_xml(password: &str, file_subject: &str, segments: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">{password}</meta>
    <meta type="yenc_encrypted">true</meta>
  </head>
  <file poster="uploader@example.com" date="1774300000" subject="{file_subject}">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      {segments}
    </segments>
  </file>
</nzb>"#
    )
}

/// Encrypt one article segment with the supplied segment index (Body Std
/// v1.2 §8: every article in a fixture uses a distinct index).
fn encode_article(
    session: &Arc<EncryptionSession>,
    file_name: &str,
    file_size: u64,
    spec: PartSpec,
    payload: &[u8],
    segment_index: u32,
) -> Vec<u8> {
    let uploader = UploadEncryptionAdapter::new(session.clone());
    let mut body = Vec::new();
    let encoded = uploader
        .encode_article(
            file_name,
            file_size,
            spec,
            payload,
            128,
            segment_index,
            &mut body,
        )
        .expect("encode article failed");
    encoded.body
}

async fn run_download_nzb(
    xml: &str,
    tiers: &[ServerTier],
    dest: &std::path::Path,
) -> DownloadOutcome {
    let nzb_file = write_temp_nzb(xml);
    let parsed = load(nzb_file.path()).unwrap();
    let queue = build(&parsed);
    let decryptor = download_decryptor(&parsed.meta).unwrap();
    download_queue_with_decryptor(&queue, tiers, dest, 0, None, decryptor)
        .await
        .unwrap()
}

/// Flip one byte in an article's data line, keeping the FF1 control lines
/// intact so the failure lands in AEAD authentication.
fn tamper_data_line(article: &[u8], data_line_index: usize) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = article
        .split_inclusive(|&b| b == b'\n')
        .map(|l| l.to_vec())
        .collect();
    assert!(lines.len() > data_line_index + 1);
    lines[data_line_index][0] ^= 0x01;
    lines.into_iter().flatten().collect()
}

fn tamper_footer_crc(
    session: &EncryptionSession,
    segment_index: u32,
    wire_article: &[u8],
) -> Vec<u8> {
    let restored =
        pesto::crypto::decrypt_yenc_control_lines(session, segment_index, wire_article).unwrap();
    let text = String::from_utf8_lossy(&restored);
    let tampered_text = if let Some(idx) = text.find("pcrc32=") {
        let mut t = text.into_owned();
        let replacement = if &t[idx + 7..idx + 8] == "f" {
            "0"
        } else {
            "f"
        };
        t.replace_range(idx + 7..idx + 8, replacement);
        t
    } else if let Some(idx) = text.find("crc32=") {
        let mut t = text.into_owned();
        let replacement = if &t[idx + 6..idx + 7] == "f" {
            "0"
        } else {
            "f"
        };
        t.replace_range(idx + 6..idx + 7, replacement);
        t
    } else {
        panic!("neither pcrc32 nor crc32 found in yend");
    };
    pesto::crypto::encrypt_yenc_control_lines(session, segment_index, tampered_text.as_bytes())
        .unwrap()
}

/// Multipart encrypted round trip through the production download path:
/// an obfuscated subject with misleading counters must not impair decryption
/// (subjects have no cryptographic meaning, Body Std v1.2 §8); the assembled
/// file on disk must equal the original plaintext.
#[tokio::test]
async fn encrypted_multipart_download_round_trip() {
    let password = "multipart-roundtrip-password";
    let salt = [0x31u8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());

    let payload_p1 = b"First half of the multipart encrypted payload.";
    let payload_p2 = b"Second half of the multipart encrypted payload.";
    let mut original = Vec::new();
    original.extend_from_slice(payload_p1);
    original.extend_from_slice(payload_p2);
    let total_len = original.len() as u64;

    let art1 = encode_article(
        &session,
        "multi.bin",
        total_len,
        PartSpec {
            number: 1,
            total: 2,
            offset: 0,
        },
        payload_p1,
        1,
    );
    let art2 = encode_article(
        &session,
        "multi.bin",
        total_len,
        PartSpec {
            number: 2,
            total: 2,
            offset: payload_p1.len() as u64,
        },
        payload_p2,
        2,
    );

    let mut known = HashMap::new();
    known.insert("mp-msg-01@test".to_string(), art1);
    known.insert("mp-msg-02@test".to_string(), art2);
    let addr = spawn_fake_server(known);

    let segments = format!(
        "<segment bytes=\"{}\" number=\"1\">mp-msg-01@test</segment>\n\
         <segment bytes=\"{}\" number=\"2\">mp-msg-02@test</segment>",
        payload_p1.len(),
        payload_p2.len()
    );
    let xml = encrypted_nzb_xml(
        password,
        // A misleading [N/M] counter and an obfuscated subject prefix have
        // no cryptographic meaning: the subject still names the assembled
        // file, but decryption is driven by the article bootstrap alone.
        "[7/9] - &quot;multi.bin&quot; yEnc (1/1)",
        &segments,
    );
    let dest = tempfile::tempdir().unwrap();
    let outcome =
        run_download_nzb(&xml, &[ServerTier::solo(server_entry(addr))], dest.path()).await;

    assert!(outcome.missing.is_empty(), "missing: {:?}", outcome.missing);
    assert!(outcome.corrupt.is_empty(), "corrupt: {:?}", outcome.corrupt);
    assert_eq!(
        std::fs::read(dest.path().join("multi.bin")).unwrap(),
        original
    );
}

/// A tampered copy on the primary tier fails authentication and the segment
/// is retried on the backup tier, which holds the intact article.
#[tokio::test]
async fn tampered_primary_fails_over_to_backup_tier() {
    let password = "tier-failover-password";
    let salt = [0x66u8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());

    let payload = b"Payload for multi-tier failover verification under provider tampering!";
    let encoded = encode_article(
        &session,
        "failover.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );
    // Single-part: line 0 =ybegin, line 1 =yencryption, line 2 data.
    let tampered = tamper_data_line(&encoded, 2);

    let mut s1_known = HashMap::new();
    s1_known.insert("failover-msg-01".to_string(), tampered);
    let s1_addr = spawn_fake_server(s1_known);

    let mut s2_known = HashMap::new();
    s2_known.insert("failover-msg-01".to_string(), encoded.clone());
    let s2_addr = spawn_fake_server(s2_known);

    let queue = queue_with_segments(
        "failover.bin",
        vec![penne::queue::QueuedSegment {
            message_id: "failover-msg-01".to_string(),
            part: 1,
            bytes: payload.len() as u64,
        }],
    );

    let dest_dir = tempfile::tempdir().unwrap();
    let decryptor = Arc::new(DownloadDecryptionAdapter::with_password(password));
    let tiers = vec![
        ServerTier::solo(server_entry(s1_addr)),
        ServerTier::solo(server_entry(s2_addr)),
    ];

    let outcome =
        download_queue_with_decryptor(&queue, &tiers, dest_dir.path(), 0, None, Some(decryptor))
            .await
            .expect("download should succeed on failover");

    assert!(outcome.segments.contains("failover-msg-01"));
    assert!(outcome.missing.is_empty());
    assert!(outcome.corrupt.is_empty());
    assert_eq!(
        std::fs::read(dest_dir.path().join("failover.bin")).unwrap(),
        payload
    );

    // Cache holds the intact body fetched from tier 2.
    assert_eq!(
        penne::cache::load(dest_dir.path(), "failover-msg-01").unwrap(),
        encoded
    );
}

fn single_segment_queue(name: &str, message_id: &str, bytes: u64) -> penne::queue::DownloadQueue {
    queue_with_segments(
        name,
        vec![penne::queue::QueuedSegment {
            message_id: message_id.to_string(),
            part: 1,
            bytes,
        }],
    )
}

fn queue_with_segments(
    name: &str,
    segments: Vec<penne::queue::QueuedSegment>,
) -> penne::queue::DownloadQueue {
    penne::queue::DownloadQueue {
        files: vec![penne::queue::QueuedFile {
            name: name.to_string(),
            segments,
        }],
    }
}

fn single_part() -> PartSpec {
    PartSpec {
        number: 1,
        total: 1,
        offset: 0,
    }
}

/// Body Std v1.2 §2.1: an NZB `bytes` value that disagrees with the
/// authenticated plaintext length marks the copy corrupt. Every tier is
/// tried before the segment is reported corrupt, and nothing is written.
#[tokio::test]
async fn segment_bytes_mismatch_tries_every_tier_then_reports_corrupt() {
    let password = "bytes-mismatch-password";
    let session = Arc::new(EncryptionSession::new(password, [0x67u8; 16]).unwrap());
    let payload = b"Plaintext whose declared NZB length is deliberately wrong.";
    let encoded = encode_article(
        &session,
        "mismatch.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );

    let counters = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let tiers: Vec<ServerTier> = counters
        .iter()
        .map(|counter| {
            let mut known = HashMap::new();
            known.insert("mismatch-msg-01".to_string(), encoded.clone());
            ServerTier::solo(server_entry(spawn_fake_server_counting(
                known,
                Some(counter.clone()),
            )))
        })
        .collect();

    let queue = single_segment_queue("mismatch.bin", "mismatch-msg-01", payload.len() as u64 + 1);
    let dest_dir = tempfile::tempdir().unwrap();
    let decryptor = Arc::new(DownloadDecryptionAdapter::with_password(password));
    let outcome =
        download_queue_with_decryptor(&queue, &tiers, dest_dir.path(), 0, None, Some(decryptor))
            .await
            .expect("download call should complete");

    assert_eq!(counters[0].load(Ordering::SeqCst), 1);
    assert_eq!(
        counters[1].load(Ordering::SeqCst),
        1,
        "the mismatch must move on to the next server"
    );
    assert_eq!(outcome.corrupt.len(), 1);
    assert_eq!(outcome.corrupt[0].message_id, "mismatch-msg-01");
    assert!(outcome.corrupt[0].error.contains("SEGMENT_BYTES_MISMATCH"));
    assert!(!outcome.segments.contains("mismatch-msg-01"));
    assert!(!dest_dir.path().join("mismatch.bin").exists());
    assert!(penne::cache::load(dest_dir.path(), "mismatch-msg-01").is_none());
}

/// `bytes="0"` means the NZB does not declare a length: the check is skipped.
#[tokio::test]
async fn segment_bytes_zero_skips_the_length_check() {
    let password = "bytes-zero-password";
    let session = Arc::new(EncryptionSession::new(password, [0x68u8; 16]).unwrap());
    let payload = b"Plaintext with no declared NZB length.";
    let encoded = encode_article(
        &session,
        "nolen.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );
    let mut known = HashMap::new();
    known.insert("nolen-msg-01".to_string(), encoded);
    let tiers = vec![ServerTier::solo(server_entry(spawn_fake_server(known)))];

    let queue = single_segment_queue("nolen.bin", "nolen-msg-01", 0);
    let dest_dir = tempfile::tempdir().unwrap();
    let decryptor = Arc::new(DownloadDecryptionAdapter::with_password(password));
    let outcome =
        download_queue_with_decryptor(&queue, &tiers, dest_dir.path(), 0, None, Some(decryptor))
            .await
            .expect("download should succeed");

    assert!(outcome.corrupt.is_empty());
    assert_eq!(
        std::fs::read(dest_dir.path().join("nolen.bin")).unwrap(),
        payload
    );
}

/// Zero-Output Guarantee on authentication failure: with only a tampered
/// copy available, a multipart download must report the corrupt segment and
/// commit nothing — no final file, no temp sibling, no cache entry for the
/// failed article — while successfully fetched parts stay cacheable.
#[tokio::test]
async fn auth_failure_commits_zero_output_and_no_cache() {
    let password = "zero-output-password";
    let salt = [0xAAu8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());

    let part1 = vec![0x11u8; 500];
    let part2 = vec![0x22u8; 500];

    let enc1 = encode_article(
        &session,
        "sensitive.bin",
        1000,
        PartSpec {
            number: 1,
            total: 2,
            offset: 0,
        },
        &part1,
        1,
    );
    let enc2 = encode_article(
        &session,
        "sensitive.bin",
        1000,
        PartSpec {
            number: 2,
            total: 2,
            offset: 500,
        },
        &part2,
        2,
    );
    // Multipart: line 0 =ybegin, line 1 =ypart, line 2 =yencryption, line 3 data.
    let tampered2 = tamper_data_line(&enc2, 3);

    let mut known = HashMap::new();
    known.insert("zero-msg-01".to_string(), enc1);
    known.insert("zero-msg-02".to_string(), tampered2);
    let addr = spawn_fake_server(known);

    let queue = queue_with_segments(
        "sensitive.bin",
        vec![
            penne::queue::QueuedSegment {
                message_id: "zero-msg-01".to_string(),
                part: 1,
                bytes: 500,
            },
            penne::queue::QueuedSegment {
                message_id: "zero-msg-02".to_string(),
                part: 2,
                bytes: 500,
            },
        ],
    );

    let dest_dir = tempfile::tempdir().unwrap();
    let decryptor = Arc::new(DownloadDecryptionAdapter::with_password(password));

    let outcome = download_queue_with_decryptor(
        &queue,
        &[ServerTier::solo(server_entry(addr))],
        dest_dir.path(),
        0,
        None,
        Some(decryptor),
    )
    .await
    .expect("download finishes with a corrupt segment reported");

    // Part 1 succeeded, part 2 failed authentication.
    assert!(outcome.segments.contains("zero-msg-01"));
    assert_eq!(outcome.corrupt.len(), 1);
    assert_eq!(outcome.corrupt[0].message_id, "zero-msg-02");
    assert!(
        outcome.corrupt[0].error.contains("AUTHENTICATION_FAILURE")
            || outcome.corrupt[0].error.contains("ciphertext CRC mismatch"),
        "error must indicate authentication failure: {}",
        outcome.corrupt[0].error
    );

    // ZERO-OUTPUT GUARANTEE: neither final file nor temp sibling may exist.
    assert!(
        !dest_dir.path().join("sensitive.bin").exists(),
        "final file must not exist on authentication failure"
    );
    assert!(
        !dest_dir.path().join("sensitive.bin.penne-part").exists(),
        "temp file must not exist on authentication failure"
    );

    // The failed article is not cached; the intact one is.
    assert!(
        penne::cache::load(dest_dir.path(), "zero-msg-02").is_none(),
        "cache must not store an unauthenticated body"
    );
    assert!(penne::cache::load(dest_dir.path(), "zero-msg-01").is_some());
}

/// An encrypted download (decryptor configured) must reject a spoofed
/// *unencrypted* article: accepting `=ybegin` plaintext would release
/// unauthenticated data to disk. The adapter fails closed.
#[tokio::test]
async fn unencrypted_spoof_rejected_for_encrypted_download() {
    let password = "spoof-rejection-password";

    // Adversary-supplied unauthenticated plaintext article: a normal, valid
    // yEnc body with no encryption framing whatsoever.
    let plain_payload = b"FORGED PLAINTEXT that must never reach disk";
    let spoofed_body = encode_part(
        "spoofed.bin",
        plain_payload.len() as u64,
        single_part(),
        plain_payload,
        128,
        None,
    )
    .body;
    assert!(spoofed_body.starts_with(b"=ybegin"));

    let mut known = HashMap::new();
    known.insert("spoof-msg-01".to_string(), spoofed_body);
    let addr = spawn_fake_server(known);

    let queue = queue_with_segments(
        "spoofed.bin",
        vec![penne::queue::QueuedSegment {
            message_id: "spoof-msg-01".to_string(),
            part: 1,
            bytes: plain_payload.len() as u64,
        }],
    );

    let dest_dir = tempfile::tempdir().unwrap();
    let decryptor = Arc::new(DownloadDecryptionAdapter::with_password(password));

    let outcome = download_queue_with_decryptor(
        &queue,
        &[ServerTier::solo(server_entry(addr))],
        dest_dir.path(),
        0,
        None,
        Some(decryptor),
    )
    .await
    .expect("download completes with a corrupt segment, not a hard error");

    // The spoofed plaintext must be classified as corrupt, never downloaded.
    assert!(
        outcome.segments.is_empty(),
        "spoofed unencrypted article must not be recorded as fetched"
    );
    assert_eq!(outcome.corrupt.len(), 1, "spoof must be reported corrupt");
    // There is no plaintext-prefix shortcut in the adapter (a valid salt may
    // itself begin with `=ybegin`), so the plain article fails closed through
    // control-line restoration instead — still with zero output.
    assert!(
        outcome.corrupt[0]
            .error
            .contains("CONTROL_LINE_DECRYPT_FAILURE"),
        "error must reflect the fail-closed authentication gate, got: {}",
        outcome.corrupt[0].error
    );

    // ZERO-OUTPUT GUARANTEE: no final file, no temp sibling, no cache entry.
    assert!(
        !dest_dir.path().join("spoofed.bin").exists(),
        "final file must not exist for a rejected spoof"
    );
    assert!(
        !dest_dir.path().join("spoofed.bin.penne-part").exists(),
        "temp file must not exist for a rejected spoof"
    );
    assert!(
        penne::cache::load(dest_dir.path(), "spoof-msg-01").is_none(),
        "rejected spoof must not be written to the resume cache"
    );
}

/// A bad ciphertext pcrc32 on a part=1 total=1 article (single-part
/// with explicit multipart framing) must fail with provider failover
/// (CorruptSegment) and zero output — the pcrc32 check must not be skipped
/// just because `total == 1`.
#[tokio::test]
async fn single_part_with_pcrc32_mismatch_fails_closed_with_zero_output() {
    let password = "pcrc32-single-part-password";
    let salt = [0x4Bu8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());

    let payload = b"single part with tampered ciphertext pcrc32 payload";
    let enc = encode_article(
        &session,
        "single.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );

    // The encoder emits `part=`/`=ypart`/`pcrc32=` framing only when
    // `spec.total > 1` (see `yenc::encode_part_into`), so `encode_article`
    // above produced an unframed single-part article. Rebuild it with REAL
    // `part=1 total=1` framing (nyuu-style) while the control lines are
    // restored, then re-encrypt them — per combined mode, the framing must
    // exist before control-line encryption (Body Std v1.2 §5). The good
    // pcrc32 is the ciphertext CRC the encoder already wrote as `crc32=`.
    let restored = pesto::crypto::decrypt_yenc_control_lines(&session, 1, &enc).unwrap();
    let mut lines: Vec<Vec<u8>> = restored
        .split_inclusive(|&b| b == b'\n')
        .map(|l| l.to_vec())
        .collect();
    assert!(lines[0].starts_with(b"=ybegin line="), "unframed =ybegin");
    assert!(lines[0].ends_with(b"\r\n"));
    // =ybegin gains `part=1 total=1` (before `line=`, matching the encoder).
    lines[0].splice(8..8, b"part=1 total=1 ".iter().copied());
    // Inject `=ypart` between =ybegin and =yencryption.
    lines.insert(
        1,
        format!("=ypart begin=1 end={}\r\n", payload.len()).into_bytes(),
    );
    // Footer: `crc32=<crc>` becomes `part=1 pcrc32=<crc>` (drop `crc32=`).
    let footer = lines.last_mut().unwrap();
    assert!(footer.starts_with(b"=yend size="));
    let crc_pos = footer
        .windows(6)
        .position(|w| w == b"crc32=")
        .expect("footer carries crc32=");
    footer.splice(crc_pos..crc_pos + 6, b"part=1 pcrc32=".iter().copied());

    let framed = pesto::crypto::encrypt_yenc_control_lines(&session, 1, &lines.concat()).unwrap();

    // Tamper the pcrc32 on the framed article (tamper_footer_crc hits its
    // `pcrc32=` branch now that the footer carries one).
    let tampered = tamper_footer_crc(&session, 1, &framed);

    let mut known = HashMap::new();
    known.insert("pcrc-msg-01".to_string(), tampered);
    let addr = spawn_fake_server(known);

    let queue = queue_with_segments(
        "single.bin",
        vec![penne::queue::QueuedSegment {
            message_id: "pcrc-msg-01".to_string(),
            part: 1,
            bytes: payload.len() as u64,
        }],
    );

    let dest_dir = tempfile::tempdir().unwrap();
    let decryptor = Arc::new(DownloadDecryptionAdapter::with_password(password));

    let outcome = download_queue_with_decryptor(
        &queue,
        &[ServerTier::solo(server_entry(addr))],
        dest_dir.path(),
        0,
        None,
        Some(decryptor),
    )
    .await
    .expect("download finishes with a corrupt segment reported");

    assert!(outcome.segments.is_empty(), "no segment fetched");
    assert_eq!(outcome.corrupt.len(), 1);
    assert!(
        outcome.corrupt[0].error.contains("ciphertext CRC mismatch"),
        "error must be the ciphertext CRC failure, got: {}",
        outcome.corrupt[0].error
    );

    // ZERO-OUTPUT GUARANTEE: no final file, no temp sibling, no cache entry.
    assert!(!dest_dir.path().join("single.bin").exists());
    assert!(!dest_dir.path().join("single.bin.penne-part").exists());
    assert!(penne::cache::load(dest_dir.path(), "pcrc-msg-01").is_none());
}

/// PT-06 (stronger branch): the tampered-pcrc32 copy is on the primary tier
/// and a valid copy on a secondary tier — the download must fail over to
/// the backup and reconstruct the plaintext.
#[tokio::test]
async fn single_part_with_pcrc32_mismatch_fails_over_with_zero_output() {
    let password = "pcrc32-single-part-password";
    let salt = [0x4Bu8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let payload = b"single part with tampered ciphertext pcrc32 payload";
    let enc = encode_article(
        &session,
        "single.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );
    let restored = pesto::crypto::decrypt_yenc_control_lines(&session, 1, &enc).unwrap();
    let mut lines: Vec<Vec<u8>> = restored
        .split_inclusive(|&b| b == b'\n')
        .map(|l| l.to_vec())
        .collect();
    lines[0].splice(8..8, b"part=1 total=1 ".iter().copied());
    lines.insert(
        1,
        format!("=ypart begin=1 end={}\r\n", payload.len()).into_bytes(),
    );
    let footer = lines.last_mut().unwrap();
    let crc_pos = footer
        .windows(6)
        .position(|w| w == b"crc32=")
        .expect("footer carries crc32=");
    footer.splice(crc_pos..crc_pos + 6, b"part=1 pcrc32=".iter().copied());
    let framed = pesto::crypto::encrypt_yenc_control_lines(&session, 1, &lines.concat()).unwrap();
    let tampered = tamper_footer_crc(&session, 1, &framed);

    let mut bad = HashMap::new();
    bad.insert("pcrc-msg-01".to_string(), tampered);
    let bad_addr = spawn_fake_server(bad);
    let mut good = HashMap::new();
    good.insert("pcrc-msg-01".to_string(), framed.clone());
    let good_addr = spawn_fake_server(good);

    let queue = queue_with_segments(
        "single.bin",
        vec![penne::queue::QueuedSegment {
            message_id: "pcrc-msg-01".to_string(),
            part: 1,
            bytes: payload.len() as u64,
        }],
    );
    let dest_dir = tempfile::tempdir().unwrap();
    let decryptor = Arc::new(DownloadDecryptionAdapter::with_password(password));
    let tiers = vec![
        ServerTier::solo(server_entry(bad_addr)),
        ServerTier::solo(server_entry(good_addr)),
    ];
    let outcome =
        download_queue_with_decryptor(&queue, &tiers, dest_dir.path(), 0, None, Some(decryptor))
            .await
            .expect("download must fail over to the valid backup copy");
    assert!(outcome.segments.contains("pcrc-msg-01"));
    assert!(outcome.missing.is_empty());
    assert!(outcome.corrupt.is_empty());
    assert_eq!(
        std::fs::read(dest_dir.path().join("single.bin")).unwrap(),
        payload
    );
    assert_eq!(
        penne::cache::load(dest_dir.path(), "pcrc-msg-01").unwrap(),
        framed
    );
}

/// PT-06 (real second-tier failover): the primary tier serves an
/// auth-failing (data-line tampered) copy and the secondary tier serves
/// the valid copy — the download must fail over to the backup and
/// reconstruct the identical plaintext, with no corrupt/missing record.
/// Unlike `tampered_primary_fails_over_to_backup_tier` (which builds the
/// queue directly), this drives the full NZB → queue → download path.
#[tokio::test]
async fn auth_failing_primary_fails_over_to_valid_secondary_tier() {
    let password = "pt06-second-tier-password";
    let salt = [0x4Cu8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let payload = b"PT-06 payload: primary copy is tampered, secondary is valid.";
    let encoded = encode_article(
        &session,
        "pt06.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );
    // Single-part: line 0 =ybegin, line 1 =yencryption, line 2 data.
    let tampered = tamper_data_line(&encoded, 2);

    let primary_counter = Arc::new(AtomicUsize::new(0));
    let mut primary_known = HashMap::new();
    primary_known.insert("pt06-msg-01@test".to_string(), tampered);
    let primary_addr = spawn_fake_server_counting(primary_known, Some(primary_counter.clone()));

    let secondary_counter = Arc::new(AtomicUsize::new(0));
    let mut secondary_known = HashMap::new();
    secondary_known.insert("pt06-msg-01@test".to_string(), encoded.clone());
    let secondary_addr =
        spawn_fake_server_counting(secondary_known, Some(secondary_counter.clone()));

    let segments = format!(
        "<segment bytes=\"{}\" number=\"1\">pt06-msg-01@test</segment>",
        payload.len()
    );
    let xml = encrypted_nzb_xml(password, "&quot;pt06.bin&quot; yEnc", &segments);
    let dest = tempfile::tempdir().unwrap();
    let tiers = vec![
        ServerTier::solo(server_entry(primary_addr)),
        ServerTier::solo(server_entry(secondary_addr)),
    ];
    let outcome = run_download_nzb(&xml, &tiers, dest.path()).await;

    // The primary was tried and failed authentication; the backup served
    // the valid copy — so the segment completed with identical plaintext.
    assert_eq!(
        primary_counter.load(Ordering::SeqCst),
        1,
        "primary tier must be tried first"
    );
    assert_eq!(
        secondary_counter.load(Ordering::SeqCst),
        1,
        "auth failure must fail over to the secondary tier"
    );
    assert!(outcome.missing.is_empty(), "missing: {:?}", outcome.missing);
    assert!(outcome.corrupt.is_empty(), "corrupt: {:?}", outcome.corrupt);
    assert_eq!(
        std::fs::read(dest.path().join("pt06.bin")).unwrap(),
        payload,
        "plaintext from the secondary tier must be identical"
    );
    // Cache holds the intact body fetched from the secondary tier.
    assert_eq!(
        penne::cache::load(dest.path(), "pt06-msg-01@test").unwrap(),
        encoded
    );
}

/// Cache resume: after an interrupted run, re-downloading the same release
/// (even with a reordered NZB) serves everything from the cache and makes
/// zero network requests.
#[tokio::test]
async fn download_resumes_from_cache_without_network_requests() {
    let password = "cache-resume-password";
    let salt = [0x37u8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());

    let payload_p1 = b"Part 1 for cache resume verification.";
    let payload_p2 = b"Part 2 for cache resume verification.";
    let mut original = Vec::new();
    original.extend_from_slice(payload_p1);
    original.extend_from_slice(payload_p2);
    let total_len = original.len() as u64;

    let art1 = encode_article(
        &session,
        "resume.bin",
        total_len,
        PartSpec {
            number: 1,
            total: 2,
            offset: 0,
        },
        payload_p1,
        1,
    );
    let art2 = encode_article(
        &session,
        "resume.bin",
        total_len,
        PartSpec {
            number: 2,
            total: 2,
            offset: payload_p1.len() as u64,
        },
        payload_p2,
        2,
    );

    let mut known = HashMap::new();
    known.insert("cache-msg-01@test".to_string(), art1);
    known.insert("cache-msg-02@test".to_string(), art2);
    let req_counter = Arc::new(AtomicUsize::new(0));
    let addr = spawn_fake_server_counting(known, Some(req_counter.clone()));

    let segments = |first: &str, second: &str| {
        format!(
            "<segment bytes=\"{}\" number=\"1\">{first}</segment>\n\
             <segment bytes=\"{}\" number=\"2\">{second}</segment>",
            payload_p1.len(),
            payload_p2.len()
        )
    };
    let dest = tempfile::tempdir().unwrap();

    // Run 1: download from the mock NNTP and populate the cache.
    let xml1 = encrypted_nzb_xml(
        password,
        "&quot;resume.bin&quot; yEnc",
        &segments("cache-msg-01@test", "cache-msg-02@test"),
    );
    let outcome1 =
        run_download_nzb(&xml1, &[ServerTier::solo(server_entry(addr))], dest.path()).await;
    assert!(outcome1.missing.is_empty());
    assert_eq!(outcome1.segments.len(), 2);
    assert_eq!(req_counter.load(Ordering::SeqCst), 2);
    assert!(penne::cache::load(dest.path(), "cache-msg-01@test").is_some());

    // Run 2: remove the assembled file, keep the cache, reorder the NZB.
    std::fs::remove_file(dest.path().join("resume.bin")).unwrap();
    let xml2 = encrypted_nzb_xml(
        password,
        "&quot;resume.bin&quot; yEnc",
        &segments("cache-msg-02@test", "cache-msg-01@test"),
    );
    req_counter.store(0, Ordering::SeqCst);
    let outcome2 =
        run_download_nzb(&xml2, &[ServerTier::solo(server_entry(addr))], dest.path()).await;

    assert!(outcome2.missing.is_empty());
    assert_eq!(outcome2.segments.len(), 2);
    assert_eq!(
        req_counter.load(Ordering::SeqCst),
        0,
        "second run must make zero network requests, serving 100% from cache"
    );
    assert_eq!(
        std::fs::read(dest.path().join("resume.bin")).unwrap(),
        original
    );
}

/// Segment indices are validated for the framing rule only (no 0x0A/0x0D in
/// the uint32_be representation): boundary indices including the framing
/// skips and u32::MAX must decrypt through the full production path.
#[tokio::test]
async fn boundary_segment_indices_decrypt_end_to_end() {
    let password = "boundary-indices-password";
    let salt = [0x3au8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let cases = [
        (1u32, "boundary-one.bin"),
        (9u32, "boundary-nine.bin"),
        (11u32, "boundary-eleven.bin"),
        (12u32, "boundary-twelve.bin"),
        (14u32, "boundary-fourteen.bin"),
        (u32::MAX - 1, "boundary-max-minus-one.bin"),
        (u32::MAX, "boundary-max.bin"),
    ];
    let mut known = HashMap::new();
    let mut files = String::new();

    for (index, name) in cases {
        let payload = format!("payload for segment index {index}");
        let message_id = format!("boundary-{index}@test");
        known.insert(
            message_id.clone(),
            encode_article(
                &session,
                name,
                payload.len() as u64,
                PartSpec {
                    number: 1,
                    total: 1,
                    offset: 0,
                },
                payload.as_bytes(),
                index,
            ),
        );
        files.push_str(&format!(
            "<file poster=\"uploader@example.com\" date=\"1774300000\" subject=\"&quot;{name}&quot; yEnc\">\n<groups>\n<group>alt.binaries.test</group>\n</groups>\n<segments>\n<segment bytes=\"{}\" number=\"1\">{message_id}</segment>\n</segments>\n</file>\n",
            payload.len()
        ));
    }

    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n<head>\n<meta type=\"password\">{password}</meta>\n<meta type=\"yenc_encrypted\">true</meta>\n</head>\n{files}</nzb>"
    );
    let addr = spawn_fake_server(known);
    let dest = tempfile::tempdir().unwrap();
    let outcome =
        run_download_nzb(&xml, &[ServerTier::solo(server_entry(addr))], dest.path()).await;

    assert!(outcome.missing.is_empty());
    assert!(outcome.corrupt.is_empty());
    for (index, name) in cases {
        assert_eq!(
            std::fs::read_to_string(dest.path().join(name)).unwrap(),
            format!("payload for segment index {index}")
        );
    }
}

/// Unique PAR2 assertion: decrypted plaintext files plus real on-disk PAR2
/// recovery data verify cleanly, and a damaged decrypted file is repaired
/// bit-identically from the downloaded recovery volume.
#[tokio::test]
async fn encrypted_download_verifies_and_repairs_via_real_par2() {
    let password = "encrypted-par2-password";
    let data1: Vec<u8> = (0..1024u32).map(|i| (i * 7) as u8).collect();
    let data2: Vec<u8> = (0..1536u32).map(|i| (i * 13) as u8).collect();

    // Build genuine PAR2 bytes via the real PAR2 encoder (upstream
    // test-support fixture, adapted from parmesan's internal test helper).
    let fixture_dir = build_fixture_set(
        &[
            FixtureFile {
                name: "data1.bin",
                data: data1.clone(),
            },
            FixtureFile {
                name: "data2.bin",
                data: data2.clone(),
            },
        ],
        256,
        8,
    );
    let base_par2_bytes = std::fs::read(fixture_dir.join("base.par2")).unwrap();
    let vol_par2_bytes = std::fs::read(fixture_dir.join("base.vol000+008.par2")).unwrap();
    let _ = std::fs::remove_dir_all(&fixture_dir);

    let salt = [0x5au8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());

    let mut known = HashMap::new();
    let mut next_index = 1u32;
    let mut xml_files = String::new();
    // One <file> element per release file — penne derives each file's name
    // from its subject and groups consecutive same-name segments.
    let push_file = |session: &Arc<EncryptionSession>,
                     name: &str,
                     data: &[u8],
                     parts: usize,
                     known: &mut HashMap<String, Vec<u8>>,
                     xml_files: &mut String,
                     next_index: &mut u32| {
        let part_size = data.len().div_ceil(parts);
        let mut segments = String::new();
        for p in 0..parts {
            let begin = p * part_size;
            let end = ((p + 1) * part_size).min(data.len());
            let chunk = &data[begin..end];
            let art = encode_article(
                session,
                name,
                data.len() as u64,
                PartSpec {
                    number: (p + 1) as u32,
                    total: parts as u32,
                    offset: begin as u64,
                },
                chunk,
                *next_index,
            );
            let msg = format!("par2-msg-{next_index:02}@test");
            known.insert(msg.clone(), art);
            segments.push_str(&format!(
                "<segment bytes=\"{}\" number=\"{}\">{msg}</segment>\n",
                chunk.len(),
                p + 1
            ));
            *next_index += 1;
        }
        xml_files.push_str(&format!(
            "<file poster=\"uploader@example.com\" date=\"1774300000\" subject=\"&quot;{name}&quot; yEnc\">\n<groups><group>alt.binaries.test</group></groups>\n<segments>\n{segments}</segments>\n</file>\n"
        ));
    };
    push_file(
        &session,
        "data1.bin",
        &data1,
        2,
        &mut known,
        &mut xml_files,
        &mut next_index,
    );
    push_file(
        &session,
        "data2.bin",
        &data2,
        3,
        &mut known,
        &mut xml_files,
        &mut next_index,
    );
    for (name, bytes) in [
        ("base.par2", &base_par2_bytes),
        ("base.vol000+008.par2", &vol_par2_bytes),
    ] {
        push_file(
            &session,
            name,
            bytes,
            1,
            &mut known,
            &mut xml_files,
            &mut next_index,
        );
    }

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">{password}</meta>
    <meta type="yenc_encrypted">true</meta>
  </head>
  {xml_files}</nzb>"#
    );
    let addr = spawn_fake_server(known);
    let dest = tempfile::tempdir().unwrap();
    let outcome =
        run_download_nzb(&xml, &[ServerTier::solo(server_entry(addr))], dest.path()).await;

    assert!(outcome.missing.is_empty());
    assert!(outcome.corrupt.is_empty());
    assert_eq!(outcome.assembled.len(), 4);

    let known_files: std::collections::HashSet<String> = [
        "data1.bin".to_string(),
        "data2.bin".to_string(),
        "base.par2".to_string(),
        "base.vol000+008.par2".to_string(),
    ]
    .into_iter()
    .collect();

    // Phase 1: intact decrypted files verify cleanly.
    let repair_res = verify_and_repair(dest.path(), &outcome.assembled, &known_files, None)
        .await
        .unwrap();
    assert!(
        matches!(repair_res, RepairOutcome::Ok),
        "expected RepairOutcome::Ok, got: {:?}",
        repair_res
    );

    // Phase 2: damage data1.bin on disk, then repair bit-identically.
    let d1_path = dest.path().join("data1.bin");
    let mut corrupted = std::fs::read(&d1_path).unwrap();
    for byte in corrupted.iter_mut().take(256) {
        *byte ^= 0xaa;
    }
    std::fs::write(&d1_path, &corrupted).unwrap();

    let repair_res = verify_and_repair(dest.path(), &HashMap::new(), &known_files, None)
        .await
        .unwrap();
    match repair_res {
        RepairOutcome::Repaired(plan) => {
            assert!(
                plan.repaired_files.iter().any(|f| f.name == "data1.bin"),
                "plan must report data1.bin as repaired"
            );
        }
        other => panic!("expected RepairOutcome::Repaired, got: {other:?}"),
    }
    assert_eq!(
        std::fs::read(&d1_path).unwrap(),
        data1,
        "repaired file must match original plaintext bit-identically"
    );
    assert_eq!(std::fs::read(dest.path().join("data2.bin")).unwrap(), data2);
}

/// Ordinary downloads behave exactly as before: a plain NZB 1.1 round-trips
/// without a decryptor (backward-compatibility seam for
/// `download_queue_with_decryptor`).
#[tokio::test]
async fn unencrypted_download_round_trips_without_decryptor() {
    let plain_payload = b"Unencrypted plain file content.";
    let plain_body = encode_part(
        "plain.bin",
        plain_payload.len() as u64,
        single_part(),
        plain_payload,
        128,
        None,
    )
    .body;

    let mut plain_known = HashMap::new();
    plain_known.insert("plain-msg-01".to_string(), plain_body);
    let plain_addr = spawn_fake_server(plain_known);

    let plain_queue = queue_with_segments(
        "plain.bin",
        vec![penne::queue::QueuedSegment {
            message_id: "plain-msg-01".to_string(),
            part: 1,
            bytes: plain_payload.len() as u64,
        }],
    );

    let plain_dest = tempfile::tempdir().unwrap();
    let plain_outcome = download_queue(
        &plain_queue,
        &[ServerTier::solo(server_entry(plain_addr))],
        plain_dest.path(),
        0,
        None,
    )
    .await
    .expect("unencrypted download failed");

    assert!(plain_outcome.segments.contains("plain-msg-01"));
    assert_eq!(
        std::fs::read(plain_dest.path().join("plain.bin")).unwrap(),
        plain_payload
    );
}

// --- Negative cases with TRUE failure causes (pesto-download-6) -----------
//
// The existing "auth failure" tests above flip a data byte and therefore
// trip the wire-CRC check (`ciphertext CRC mismatch`) before AEAD ever
// runs. The tests in this section build copies whose data lines and wire
// CRCs remain intact, so the failure cause is the intended one:
// - wrong password        -> CONTROL_LINE_DECRYPT_FAILURE (FF1 garbage Line 1)
// - truncation            -> LINE_TRUNCATED / LINE_TOO_SHORT
// - malformed =yencryption-> INVALID_TOKEN_COUNT / UNSUPPORTED_CIPHER / ...
// - flipped tag, valid CRC-> AUTHENTICATION_FAILURE (true Poly1305 failure)
//
// Each case asserts the three binding behaviors: the error carries its
// specific cause, the copy is retried on another server (failover), and no
// plaintext or ciphertext is committed as final output (no final file, no
// `.penne-part` temp sibling, no resume-cache entry).

/// Shared assertion block for a single bad copy served by every tier: the
/// failure must surface as `corrupt` with the given cause after all tiers
/// have been tried, and nothing may be committed anywhere.
async fn assert_bad_copy_fails_over_with_zero_output(
    password: &str,
    bad: Vec<u8>,
    file_name: &str,
    message_id: &str,
    expected_error: &str,
) {
    // Two tiers both serve the same bad copy: the failure must be retried
    // across servers (retriable provider corruption) before terminal corrupt.
    let counters = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let tiers: Vec<ServerTier> = counters
        .iter()
        .map(|counter| {
            let mut known = HashMap::new();
            known.insert(message_id.to_string(), bad.clone());
            ServerTier::solo(server_entry(spawn_fake_server_counting(
                known,
                Some(counter.clone()),
            )))
        })
        .collect();

    let queue = single_segment_queue(file_name, message_id, bad.len() as u64);
    let dest_dir = tempfile::tempdir().unwrap();
    let decryptor = Arc::new(DownloadDecryptionAdapter::with_password(password));
    let outcome =
        download_queue_with_decryptor(&queue, &tiers, dest_dir.path(), 0, None, Some(decryptor))
            .await
            .expect("download must finish with a corrupt segment, not a hard error");

    // FAILOVER: every tier was tried (retriable provider corruption).
    assert_eq!(
        counters[0].load(Ordering::SeqCst),
        1,
        "primary tier must be tried before failing over"
    );
    assert_eq!(
        counters[1].load(Ordering::SeqCst),
        1,
        "failure must move on to the next server"
    );

    // The true cause, not an incidental wire-CRC failure.
    assert_eq!(
        outcome.corrupt.len(),
        1,
        "bad copy must be reported corrupt"
    );
    assert!(
        outcome.corrupt[0].error.contains(expected_error),
        "error must contain {expected_error:?}, got: {}",
        outcome.corrupt[0].error
    );

    // ZERO-OUTPUT: no final file, no temp sibling, no resume-cache entry.
    assert!(
        !dest_dir.path().join(file_name).exists(),
        "final file must not exist"
    );
    assert!(
        !dest_dir
            .path()
            .join(format!("{file_name}.penne-part"))
            .exists(),
        "temp file must not exist"
    );
    assert!(
        penne::cache::load(dest_dir.path(), message_id).is_none(),
        "cache must not store the failed body"
    );
}

/// Single-part article whose data lines and wire CRC are intact but whose
/// `=yencryption` tag was flipped: wire CRC verifies, Poly1305 fails.
/// TRUE authentication failure (Body Std v1.2 §5, Zero-Output Guarantee).
#[tokio::test]
async fn flipped_tag_with_intact_wire_crc_fails_poly1305_then_fails_over() {
    let password = "tag-flip-password";
    let salt = [0x71u8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let payload = b"Payload whose authentication tag is tampered with valid CRC.";
    let encoded = encode_article(
        &session,
        "tagflip.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );

    // Flip one hex digit INSIDE the encrypted `=yencryption` tag, then
    // restore the FF1 control-line ciphertext so only the tag bit changes.
    // The tag is stored encrypted on the wire, so: decrypt control lines,
    // locate the restored `tag=` hex on the control line, flip a hex digit,
    // re-encrypt. Data lines are arbitrary binary bytes and untouched
    // throughout, so the wire CRC still verifies.
    let restored = pesto::crypto::decrypt_yenc_control_lines(&session, 1, &encoded).unwrap();
    let lines = pesto::crypto::split_lines_preserving_endings(&restored);
    let mut modified = Vec::new();
    for line in lines {
        if line.content.starts_with(b"=yencryption") {
            let text = std::str::from_utf8(line.content).unwrap();
            let idx = text.find("tag=").expect("restored article carries tag=");
            let mut tampered_line = text.to_string();
            let digit_pos = idx + 4; // first hex char of the 32-hex-digit tag
            let replacement = if &tampered_line[digit_pos..digit_pos + 1] == "f" {
                "0"
            } else {
                "f"
            };
            tampered_line.replace_range(digit_pos..digit_pos + 1, replacement);
            modified.extend_from_slice(tampered_line.as_bytes());
            modified.extend_from_slice(line.ending);
        } else {
            modified.extend_from_slice(line.content);
            modified.extend_from_slice(line.ending);
        }
    }
    let tampered = pesto::crypto::encrypt_yenc_control_lines(&session, 1, &modified).unwrap();

    // The data line is byte-identical between the two copies.
    let data_line = |a: &[u8]| a.split(|&b| b == b'\n').nth(2).unwrap().to_vec();
    assert_eq!(
        data_line(&encoded),
        data_line(&tampered),
        "tag flip must leave data lines intact"
    );

    assert_bad_copy_fails_over_with_zero_output(
        password,
        tampered,
        "tagflip.bin",
        "tagflip-msg-01",
        "AUTHENTICATION_FAILURE",
    )
    .await;
}

/// Wrong password on a fully valid article: the FF1 control-line decrypt
/// yields pseudorandom garbage that cannot be `=ybegin` (Control Std v1.2
/// §5 wrong-password signature), so the failure is CONTROL_LINE_DECRYPT_
/// FAILURE — not a wire-CRC failure and not Poly1305.
#[tokio::test]
async fn wrong_password_on_valid_article_fails_control_decrypt_then_fails_over() {
    let password = "right-password-for-control-lines";
    let salt = [0x72u8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let payload = b"Valid article downloaded under the wrong password.";
    let encoded = encode_article(
        &session,
        "wrongpw.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );

    assert_bad_copy_fails_over_with_zero_output(
        "totally-wrong-password",
        encoded,
        "wrongpw.bin",
        "wrongpw-msg-01",
        "CONTROL_LINE_DECRYPT_FAILURE",
    )
    .await;
}

/// A truncated encrypted body (article cut after Line 1, missing subsequent
/// header lines and footer) must fail structurally and be retried on the
/// next server, committing nothing.
#[tokio::test]
async fn truncated_encrypted_body_is_reported_corrupt_with_failover() {
    let password = "truncation-password";
    let salt = [0x73u8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let payload = b"Payload that the provider truncated in transit, deliberately.";
    let encoded = encode_article(
        &session,
        "truncated.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );
    // Cut after Line 1 while keeping its CRLF line ending intact so NNTP
    // wire framing succeeds: the article is truncated to 1 line (< 3 lines
    // required for single-part encrypted articles).
    let lines = pesto::crypto::split_lines_preserving_endings(&encoded);
    assert!(lines.len() >= 3, "valid article must have at least 3 lines");
    let truncated = [lines[0].content, lines[0].ending].concat();

    assert_bad_copy_fails_over_with_zero_output(
        password,
        truncated,
        "truncated.bin",
        "truncated-msg-01",
        "LINE_TRUNCATED",
    )
    .await;
}

/// A malformed `=yencryption` line (missing fields / bad grammar, built by
/// rewriting the restored line and re-encrypting control lines) must be
/// rejected with its grammar error and retried on the next server.
#[tokio::test]
async fn malformed_yencryption_line_is_rejected_with_failover() {
    let password = "malformed-yencryption-password";
    let salt = [0x74u8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let payload = b"Payload carried by an article with a malformed =yencryption line.";
    let encoded = encode_article(
        &session,
        "malformed.bin",
        payload.len() as u64,
        single_part(),
        payload,
        1,
    );

    // Rebuild the restored article with a `=yencryption` line missing the
    // `tag=` field (bad grammar), then re-encrypt the control lines. Data
    // lines stay intact, so this is not a wire-CRC failure.
    let restored = pesto::crypto::decrypt_yenc_control_lines(&session, 1, &encoded).unwrap();
    let lines = pesto::crypto::split_lines_preserving_endings(&restored);
    let mut modified = Vec::new();
    for line in lines {
        if line.content.starts_with(b"=yencryption") {
            let text = std::str::from_utf8(line.content).unwrap();
            let salt_str = text
                .split(" salt=")
                .nth(1)
                .unwrap()
                .split(" index=")
                .next()
                .unwrap();
            let malformed_line =
                format!("=yencryption cipher=XChaCha20-Poly1305 salt={salt_str} index=00000001");
            modified.extend_from_slice(malformed_line.as_bytes());
            modified.extend_from_slice(line.ending);
        } else {
            modified.extend_from_slice(line.content);
            modified.extend_from_slice(line.ending);
        }
    }
    let malformed = pesto::crypto::encrypt_yenc_control_lines(&session, 1, &modified).unwrap();

    assert_bad_copy_fails_over_with_zero_output(
        password,
        malformed,
        "malformed.bin",
        "malformed-msg-01",
        "INVALID_TOKEN_COUNT",
    )
    .await;
}

/// Body Std v1.2 §5 step 5 / Q-8 / X-2: the wire pcrc32 value is a hexadecimal
/// string of any width that parses as a CRC-32 value; it need not be
/// zero-padded to eight digits, and non-eight-digit widths (e.g. 10 digits
/// with leading zeros, or fewer than 8 digits) must be accepted.
#[tokio::test]
async fn multipart_pcrc32_accepts_non_eight_hex_width() {
    let password = "pcrc32-width-password";
    let salt = [0x55u8; 16];
    let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
    let payload_p1 = b"First part of payload with non-8-digit hex pcrc32.";
    let payload_p2 = b"Second part of payload with non-8-digit hex pcrc32.";
    let mut original = Vec::new();
    original.extend_from_slice(payload_p1);
    original.extend_from_slice(payload_p2);
    let total_len = original.len() as u64;

    let art1 = encode_article(
        &session,
        "width.bin",
        total_len,
        PartSpec {
            number: 1,
            total: 2,
            offset: 0,
        },
        payload_p1,
        1,
    );
    let art2 = encode_article(
        &session,
        "width.bin",
        total_len,
        PartSpec {
            number: 2,
            total: 2,
            offset: payload_p1.len() as u64,
        },
        payload_p2,
        2,
    );

    // Re-format art1's footer pcrc32 to have 10 hex digits (leading zeroes "00"),
    // which has width 10 != 8 but parses to the exact same u32 CRC.
    let restored1 = pesto::crypto::decrypt_yenc_control_lines(&session, 1, &art1).unwrap();
    let lines1 = pesto::crypto::split_lines_preserving_endings(&restored1);
    let mut modified1 = Vec::new();
    for line in lines1 {
        if line.content.starts_with(b"=yend") {
            let text = std::str::from_utf8(line.content).unwrap();
            let idx = text.find("pcrc32=").expect("footer carries pcrc32=");
            let crc_hex = &text[idx + 7..idx + 15];
            let new_footer = format!("{}00{}{}", &text[..idx + 7], crc_hex, &text[idx + 15..]);
            modified1.extend_from_slice(new_footer.as_bytes());
            modified1.extend_from_slice(line.ending);
        } else {
            modified1.extend_from_slice(line.content);
            modified1.extend_from_slice(line.ending);
        }
    }
    let art1_custom = pesto::crypto::encrypt_yenc_control_lines(&session, 1, &modified1).unwrap();

    let mut known = HashMap::new();
    known.insert("width-msg-01".to_string(), art1_custom);
    known.insert("width-msg-02".to_string(), art2);
    let addr = spawn_fake_server(known);

    let queue = queue_with_segments(
        "width.bin",
        vec![
            penne::queue::QueuedSegment {
                message_id: "width-msg-01".to_string(),
                part: 1,
                bytes: payload_p1.len() as u64,
            },
            penne::queue::QueuedSegment {
                message_id: "width-msg-02".to_string(),
                part: 2,
                bytes: payload_p2.len() as u64,
            },
        ],
    );

    let dest_dir = tempfile::tempdir().unwrap();
    let decryptor = Arc::new(DownloadDecryptionAdapter::with_password(password));
    let tiers = vec![ServerTier::solo(server_entry(addr))];

    let outcome =
        download_queue_with_decryptor(&queue, &tiers, dest_dir.path(), 0, None, Some(decryptor))
            .await
            .expect("download must succeed when pcrc32 width != 8 is valid hex");

    assert!(outcome.corrupt.is_empty(), "corrupt: {:?}", outcome.corrupt);
    assert!(outcome.missing.is_empty(), "missing: {:?}", outcome.missing);
    assert_eq!(
        std::fs::read(dest_dir.path().join("width.bin")).unwrap(),
        original
    );
}

/// PROOF TEST for pesto-upload-7: an NZB merging files from distinct upload
/// sessions (different salts), sharing one password, decrypts end-to-end.
/// Articles are self-describing (Line 1 carries salt and segmentIndex), and
/// Penne caches sessions per salt, so merged releases decrypt without issue.
#[tokio::test]
async fn merged_encrypted_release_with_multiple_salts_decrypts() {
    let password = "season-merge-shared-password";
    let salt1 = [0x11u8; 16];
    let salt2 = [0x22u8; 16];
    let session1 = Arc::new(EncryptionSession::new(password, salt1).unwrap());
    let session2 = Arc::new(EncryptionSession::new(password, salt2).unwrap());

    let payload1 = b"Episode 01 payload from session 1";
    let payload2 = b"Episode 02 payload from session 2";

    let art1 = encode_article(
        &session1,
        "Show.S01E01.mkv",
        payload1.len() as u64,
        single_part(),
        payload1,
        1,
    );
    let art2 = encode_article(
        &session2,
        "Show.S01E02.mkv",
        payload2.len() as u64,
        single_part(),
        payload2,
        1,
    );

    let mut known = HashMap::new();
    known.insert("ep1-msg-01".to_string(), art1);
    known.insert("ep2-msg-01".to_string(), art2);
    let addr = spawn_fake_server(known);

    let segments_ep1 = format!(
        "<segment bytes=\"{}\" number=\"1\">ep1-msg-01</segment>",
        payload1.len()
    );
    let segments_ep2 = format!(
        "<segment bytes=\"{}\" number=\"1\">ep2-msg-01</segment>",
        payload2.len()
    );

    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">{password}</meta>
    <meta type="yenc_encrypted">true</meta>
  </head>
  <file poster="poster@test" date="1700000000" subject="&quot;Show.S01E01.mkv&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      {segments_ep1}
    </segments>
  </file>
  <file poster="poster@test" date="1700000000" subject="&quot;Show.S01E02.mkv&quot; yEnc (1/1)">
    <groups><group>alt.binaries.test</group></groups>
    <segments>
      {segments_ep2}
    </segments>
  </file>
</nzb>"#
    );

    let dest = tempfile::tempdir().unwrap();
    let outcome =
        run_download_nzb(&xml, &[ServerTier::solo(server_entry(addr))], dest.path()).await;

    assert!(outcome.missing.is_empty(), "missing: {:?}", outcome.missing);
    assert!(outcome.corrupt.is_empty(), "corrupt: {:?}", outcome.corrupt);
    assert_eq!(
        std::fs::read(dest.path().join("Show.S01E01.mkv")).unwrap(),
        payload1
    );
    assert_eq!(
        std::fs::read(dest.path().join("Show.S01E02.mkv")).unwrap(),
        payload2
    );
}
