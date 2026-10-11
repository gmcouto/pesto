//! Regression guards (audit P0): every repost path of an encrypted upload
//! must re-post the *authenticated wire form* — re-encrypted with the same
//! salt and segment index — never plaintext yEnc.
//!
//! Covers both paths:
//! - the end-of-run blind retry (`poster::repost_failed_tasks`): the mock
//!   server rejects the first POST attempts with 441, forcing the failed
//!   task into the retry pass;
//! - the streaming STAT check's repost (`poster::check::repost_one`) and the
//!   final recovery pass (`poster::check::recover_missing`), which both run
//!   through the same `repost_one`.
//!
//! Each test captures the raw bytes of every POST the server received,
//! decrypts them through the production `DownloadDecryptionAdapter`, and
//! asserts the reconstructed plaintext equals the source file. No captured
//! article body may start with `=ybegin` (plaintext) while the upload is
//! encrypted.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use pesto::config::{Config, ObfuscateMode};
use pesto::crypto::{control, DownloadDecryptionAdapter};
use pesto::poster::post_files_with_progress;
use pesto::walk::expand_inputs;

type CapturedArticles = Arc<Mutex<Vec<Vec<u8>>>>;

/// Mock NNTP server. `post_failures` controls how many POST commands (across
/// all connections, globally) are answered with a 441 refusal before any
/// later POST succeeds. All STATs succeed, so no check-path repost
/// interferes with the blind-retry assertions.
fn spawn_mock_server(post_failures: usize) -> (SocketAddr, CapturedArticles, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let articles = Arc::new(Mutex::new(Vec::new()));
    let refused = Arc::new(AtomicUsize::new(0));

    let articles_clone = Arc::clone(&articles);
    let refused_clone = Arc::clone(&refused);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let articles = Arc::clone(&articles_clone);
            let refused = Arc::clone(&refused_clone);
            std::thread::spawn(move || {
                handle_connection(stream, articles, refused, post_failures);
            });
        }
    });

    (addr, articles, refused)
}

/// Like [`spawn_mock_server`], but the first `stat_misses` STAT commands
/// report 430 (missing) and every later STAT succeeds — the recipe that
/// drives a normal check repost plus the automatic recovery-pass repost
/// (see `check_recover_pass.rs`).
fn spawn_mock_server_with_stat_misses(
    stat_misses: usize,
) -> (SocketAddr, CapturedArticles, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let articles = Arc::new(Mutex::new(Vec::new()));
    let stat_count = Arc::new(AtomicUsize::new(0));

    let articles_clone = Arc::clone(&articles);
    let stat_count_clone = Arc::clone(&stat_count);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let articles = Arc::clone(&articles_clone);
            let stat_count = Arc::clone(&stat_count_clone);
            std::thread::spawn(move || {
                handle_connection_with_stat_misses(stream, articles, stat_count, stat_misses);
            });
        }
    });

    (addr, articles, stat_count)
}

fn handle_connection(
    stream: TcpStream,
    articles: CapturedArticles,
    refused: Arc<AtomicUsize>,
    post_failures: usize,
) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    if writer.write_all(b"200 pesto mock ready\r\n").is_err() {
        return;
    }

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let command = line.trim_end().to_string();

        if command == "POST" {
            let this_post = refused.fetch_add(1, Ordering::SeqCst);
            let accept = this_post >= post_failures;
            if writer.write_all(b"340 send article\r\n").is_err() {
                return;
            }
            let mut article = Vec::new();
            loop {
                let mut raw = Vec::new();
                match reader.read_until(b'\n', &mut raw) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                if raw == b".\r\n" {
                    break;
                }
                if raw.starts_with(b"..") {
                    raw.remove(0);
                }
                article.extend_from_slice(&raw);
            }
            if accept {
                articles.lock().unwrap().push(article);
                if writer.write_all(b"240 article received\r\n").is_err() {
                    return;
                }
            } else if writer
                .write_all(b"441 article rejected (forced test failure)\r\n")
                .is_err()
            {
                return;
            }
        } else if command.starts_with("STAT ") {
            if writer.write_all(b"223 0 <id> article exists\r\n").is_err() {
                return;
            }
        } else if command.starts_with("MODE READER") {
            if writer.write_all(b"200 reader mode\r\n").is_err() {
                return;
            }
        } else if command == "QUIT" {
            let _ = writer.write_all(b"205 bye\r\n");
            return;
        } else if writer.write_all(b"500 unknown command\r\n").is_err() {
            return;
        }
    }
}

fn handle_connection_with_stat_misses(
    stream: TcpStream,
    articles: CapturedArticles,
    stat_count: Arc<AtomicUsize>,
    stat_misses: usize,
) {
    let mut writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    if writer.write_all(b"200 pesto mock ready\r\n").is_err() {
        return;
    }

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let command = line.trim_end().to_string();

        if command == "POST" {
            if writer.write_all(b"340 send article\r\n").is_err() {
                return;
            }
            let mut article = Vec::new();
            loop {
                let mut raw = Vec::new();
                match reader.read_until(b'\n', &mut raw) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                if raw == b".\r\n" {
                    break;
                }
                if raw.starts_with(b"..") {
                    raw.remove(0);
                }
                article.extend_from_slice(&raw);
            }
            articles.lock().unwrap().push(article);
            if writer.write_all(b"240 article received\r\n").is_err() {
                return;
            }
        } else if command.starts_with("STAT ") {
            let seen = stat_count.fetch_add(1, Ordering::SeqCst);
            let resp: &[u8] = if seen < stat_misses {
                b"430 no such article found\r\n"
            } else {
                b"223 0 <id> article exists\r\n"
            };
            if writer.write_all(resp).is_err() {
                return;
            }
        } else if command.starts_with("MODE READER") {
            if writer.write_all(b"200 reader mode\r\n").is_err() {
                return;
            }
        } else if command == "QUIT" {
            let _ = writer.write_all(b"205 bye\r\n");
            return;
        } else if writer.write_all(b"500 unknown command\r\n").is_err() {
            return;
        }
    }
}

fn config(addr: SocketAddr, encrypt_password: Option<String>) -> Config {
    Config {
        host: addr.ip().to_string(),
        port: addr.port(),
        ssl: false,
        connections: 2,
        username: None,
        password: None,
        from: "tester <t@pesto.test>".to_string(),
        groups: vec!["alt.binaries.test".to_string()],
        article_size: 1_000_000,
        line_length: 128,
        retries: 1,
        retry_delay: 0,
        timeout: pesto::config::DEFAULT_TIMEOUT_SECS,
        proxy: None,
        proxy_check_ip: false,
        obfuscate: ObfuscateMode::None,
        dry_run: false,
        par2: 0,
        par2_slice_size: None,
        par2_slice_count: None,
        par2_recovery_count: None,
        par2_memory_limit: Some(1_000_000_000),
        memory_limit: None,
        par2_temp_dir: None,
        compress_temp_dir: None,
        par2_only: false,
        par2_before_upload: false,
        threads: 0,
        simd: pesto::par2::SimdPath::Auto,
        extra_servers: vec![],
        resume: false,
        upload_rate: 0,
        compress_format: None,
        compress_password: None,
        compress_volume_size: None,
        nzb_title: None,
        nzb_password: None,
        encrypt_password,
        nzb_category: None,
        nzb_tags: vec![],
        tmdb_id: None,
        tmdb_kind: None,
        imdb_id: None,
        tvdb_id: None,
        tvdb_kind: None,
        mal_id: None,
        indexer_url: None,
        indexer_api_key: None,
        notify_webhook: None,
        notify_ntfy: None,
        notify: None,
        history: false,
        history_dir: None,
        nzb_dir: None,
        date: None,
        no_archive: false,
        file_counter: false,
        message_id_domain: None,
        pre_hooks: vec![],
        post_hooks: vec![],
        no_hooks: false,
        nfo: false,
        nzb_conflict: pesto::config::NzbConflict::Overwrite,
        quiet: false,
        bell: false,
        check: true,
        check_delay_secs: 0,
        check_retries: 1,
        check_connections: 1,
        check_post_retries: 1,
        allow_incomplete_nzb: false,
        check_recover_percent: 15,
        check_recover_max: 5,
        pipeline_depth: 1,
        keepalive_interval: 0,
    }
}

fn article_body(article: &[u8]) -> &[u8] {
    let marker = b"\r\n\r\n";
    let start = article
        .windows(marker.len())
        .position(|window| window == marker)
        .expect("article headers must end with CRLF CRLF")
        + marker.len();
    &article[start..]
}

/// Assert every captured article is an authenticated encrypted wire article
/// whose decrypted bytes equal `plaintext` (single-segment uploads: the
/// original post and every repost each carry the whole file), and return the
/// bootstrap segment indices in capture order.
fn assert_all_articles_decrypt_to(
    articles: &[Vec<u8>],
    password: &str,
    plaintext: &[u8],
) -> Vec<u32> {
    assert!(!articles.is_empty(), "no articles were captured");
    let decryptor = DownloadDecryptionAdapter::with_password(password);
    let mut indices = Vec::new();
    for (i, article) in articles.iter().enumerate() {
        let body = article_body(article);
        assert!(
            !body.starts_with(b"=ybegin"),
            "article #{i} was posted as PLAINTEXT yEnc during an encrypted upload"
        );
        let (salt, index) = control::extract_bootstrap_from_line1(body)
            .unwrap_or_else(|e| panic!("article #{i} lacks a valid bootstrap: {e}"));
        assert_eq!(salt.len(), 16);
        indices.push(index);
        let decoded = decryptor
            .decode_article(body)
            .unwrap_or_else(|e| panic!("article #{i} failed to decrypt: {e}"));
        assert_eq!(
            decoded.data, plaintext,
            "article #{i} must decrypt to the original plaintext"
        );
    }
    indices
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_blind_retry_reposts_encrypted_wire_with_same_identity() {
    // Refuse the very first POST command: the single-segment article fails
    // its only in-run attempt (`retries: 1`), lands in `failed_tasks`, and
    // is re-posted by the end-of-run blind retry
    // (`poster::repost_failed_tasks`). The retry must re-encrypt with the
    // same salt/index — posting plaintext there is the P0 leak this test
    // guards against.
    let (addr, articles, refused) = spawn_mock_server(1);

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("retry.bin");
    let plaintext: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
    std::fs::write(&input, &plaintext).unwrap();

    let cfg = config(addr, Some("retry-pass-123".into()));
    let inputs = expand_inputs(std::slice::from_ref(&input)).unwrap();
    let outcome = post_files_with_progress(&cfg, &inputs, None, None, None)
        .await
        .unwrap();

    // Two POST commands total: the refused in-run attempt and the accepted
    // blind-retry POST.
    assert_eq!(
        refused.load(Ordering::SeqCst),
        2,
        "expected the refused in-run POST plus the blind retry's POST"
    );
    assert!(
        outcome.failures.is_empty(),
        "the blind retry must recover the forced failure: {:?}",
        outcome.failures
    );

    let captured = articles.lock().unwrap().clone();
    assert_eq!(
        captured.len(),
        1,
        "only the successful retry POST should be stored by the server"
    );

    // The single captured article is the retry's output: it must be the
    // authenticated encrypted wire form decrypting to the original bytes.
    let indices = assert_all_articles_decrypt_to(&captured, "retry-pass-123", &plaintext);
    // First safe index of the release.
    assert_eq!(indices, vec![1u32]);

    // Identity check: the retry must reuse the failed task's planned
    // segment index — decrypt its bootstrap and compare with the outcome.
    assert_eq!(
        outcome.segments[0].segment_index, indices[0],
        "retry must preserve the original segment identity"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_check_repost_and_recovery_stay_encrypted_with_same_identity() {
    // All POSTs succeed, but the first two STATs miss — driving one normal
    // `check_post_retries` repost (`repost_one`) plus the automatic
    // recovery-pass repost, exactly like `check_recover_pass.rs`. Both
    // reposts must be re-encrypted under the same salt/index, never
    // plaintext.
    let (addr, articles, stat_count) = spawn_mock_server_with_stat_misses(2);

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("check.bin");
    let plaintext: Vec<u8> = (0..96u32).map(|i| (i * 3) as u8).collect();
    std::fs::write(&input, &plaintext).unwrap();

    let cfg = config(addr, Some("check-pass-123".into()));
    let inputs = expand_inputs(std::slice::from_ref(&input)).unwrap();
    let outcome = post_files_with_progress(&cfg, &inputs, None, None, None)
        .await
        .unwrap();

    assert!(
        outcome.still_missing.is_empty(),
        "the recovery pass should have resolved the stubborn miss: {:?}",
        outcome.still_missing
    );
    assert_eq!(outcome.segments.len(), 1);
    // Original + check repost + recovery-pass repost.
    assert_eq!(
        stat_count.load(Ordering::SeqCst),
        3,
        "expected 2 failing STATs (original + repost) then 1 succeeding"
    );

    let captured = articles.lock().unwrap().clone();
    assert_eq!(
        captured.len(),
        3,
        "expected the original POST plus 2 reposts"
    );

    // All three POSTs — original, check repost, recovery repost — must be
    // encrypted wire forms of the same segment, each carrying the same
    // bootstrap segment index and decrypting to the original plaintext.
    let indices = assert_all_articles_decrypt_to(&captured, "check-pass-123", &plaintext);
    assert_eq!(
        indices,
        vec![1u32; 3],
        "every repost must reuse the original segment index"
    );
    assert_eq!(
        outcome.segments[0].segment_index, indices[0],
        "outcome must record the preserved segment identity"
    );
}
