//! PESTO-R6-2 end-to-end proof: two actual CLI uploads (shared transport
//! password, distinct per-session salts), the actual `--merge-season`
//! output, and a real Penne download reconstructing both plaintexts.
//!
//! Unlike `download_encryption.rs::merged_encrypted_release_with_multiple_salts_decrypts`
//! (which hand-builds the merged XML), this drives the *producer* paths:
//! every `.nzb` involved is an actual `pesto` CLI output, and the combined
//! season NZB is produced by the real `run_merge_season`. The download side
//! uses the real `penne::nzb::load` → `download_decryptor` constructor and
//! the same fake-server pipeline as the other integration tests.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use penne::config::ServerTier;
use penne::download::download_queue_with_decryptor;
use penne::nzb::{download_decryptor, load};
use penne::queue::build;
use pesto::config::ServerEntry;

/// Build (or reuse a fresh build of) the `pesto` producer CLI and return its
/// path. `CARGO_BIN_EXE_pesto` only exists for the package owning the binary
/// (pesto-poster), so from penne's test crate we invoke the active `cargo`
/// binary — see PE-NEXT-4: the previous implementation trusted whatever
/// prebuilt binary happened to sit in the workspace `target/{debug,release}`
/// directory, ignoring `CARGO_TARGET_DIR` and the source revision.
///
/// The nested invocation is not "cargo nested in cargo blindly": the outer
/// `cargo test` releases its build lock before test execution, and the
/// nested `cargo build` shares the active target directory, so it either
/// reuses the outer run's fresh artifacts or builds the current source
/// itself. Cargo reports the produced artifact via `--message-format=json`,
/// so no target-dir/profile/triple layout is assumed here; a build failure
/// is a test failure, never a silent skip.
fn build_pesto_bin() -> PathBuf {
    let cargo = std::env::var("CARGO").expect("cargo must be running this test binary");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(Path::parent)
        .expect("penne lives two levels under the workspace root");
    let output = Command::new(cargo)
        .current_dir(workspace)
        .args([
            "build",
            "--offline",
            "--bin",
            "pesto",
            "-p",
            "pesto-poster",
            "--message-format=json",
        ])
        .output()
        .expect("failed to spawn the active cargo binary");
    assert!(
        output.status.success(),
        "building the pesto producer CLI from current source failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Pick the `pesto` bin artifact out of cargo's JSON stream; an up-to-date
    // (fresh) build still reports the artifact path.
    let mut bin: Option<PathBuf> = None;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let is_pesto_bin = msg.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact")
            && msg
                .get("target")
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
                == Some("pesto")
            && msg
                .get("target")
                .and_then(|t| t.get("kind"))
                .and_then(|k| k.as_array())
                .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("bin")));
        if is_pesto_bin {
            if let Some(exe) = msg.get("executable").and_then(|e| e.as_str()) {
                bin = Some(PathBuf::from(exe));
            }
        }
    }
    bin.unwrap_or_else(|| {
        panic!(
            "cargo build succeeded but reported no pesto bin artifact:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
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

fn article_message_id(article: &[u8]) -> String {
    let text = String::from_utf8_lossy(article);
    for line in text.split("\r\n") {
        if let Some(value) = line
            .strip_prefix("Message-ID:")
            .or_else(|| line.strip_prefix("Message-Id:"))
        {
            return value.trim().to_string();
        }
    }
    panic!("captured article has no Message-ID header");
}

/// Mock NNTP POST-capturing server for the two upload runs: every POST is
/// accepted and its raw article bytes recorded; STATs always succeed.
fn spawn_post_capture_server(captured: Arc<Mutex<Vec<Vec<u8>>>>) -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let captured = Arc::clone(&captured);
            std::thread::spawn(move || {
                let Ok(writer_stream) = stream.try_clone() else {
                    return;
                };
                let mut writer = writer_stream;
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
                        captured.lock().unwrap().push(article);
                        if writer.write_all(b"240 article received\r\n").is_err() {
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
            });
        }
    });
    addr
}

/// Fake BODY/QUIT server for the download pass: maps bare Message-IDs to
/// article bodies, exactly like `download_encryption.rs`'s helper.
fn spawn_body_server(known: HashMap<String, Vec<u8>>) -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let known = known.clone();
            std::thread::spawn(move || {
                let Ok(mut writer) = stream.try_clone() else {
                    return;
                };
                let mut reader = BufReader::new(stream);
                if writer.write_all(b"200 mock ready\r\n").is_err() {
                    return;
                }
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    let cmd = line.trim_end().to_string();
                    if let Some(rest) = cmd.strip_prefix("BODY ") {
                        let id = rest.trim_start_matches('<').trim_end_matches('>');
                        match known.get(id) {
                            Some(body) => {
                                let header = format!("222 0 <{id}> body\r\n");
                                if writer.write_all(header.as_bytes()).is_err()
                                    || write_dot_stuffed(&mut writer, body).is_err()
                                    || writer.write_all(b".\r\n").is_err()
                                {
                                    return;
                                }
                            }
                            None => {
                                if writer.write_all(b"430 No such article\r\n").is_err() {
                                    return;
                                }
                            }
                        }
                    } else if cmd == "QUIT" {
                        let _ = writer.write_all(b"205 bye\r\n");
                        return;
                    } else if writer.write_all(b"500 unknown command\r\n").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn write_dot_stuffed(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    for line in body.split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b".") {
            w.write_all(b".")?;
        }
        w.write_all(line)?;
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

fn run_pesto(xdg_home: &Path, args: &[&std::ffi::OsStr]) -> Output {
    Command::new(build_pesto_bin())
        .env("XDG_CONFIG_HOME", xdg_home)
        .args(args)
        .output()
        .expect("failed to run pesto")
}

/// The full producer→aggregate→consumer proof (Body Std v1.2 §8):
///
/// 1. Two actual `pesto` uploads with one `--encrypt-password` (each run
///    draws its own fresh salt — asserted distinct below).
/// 2. The actual per-episode NZBs merged by the actual `--merge-season`.
/// 3. The actual combined XML parsed via `penne::nzb::load` and the real
///    `download_decryptor` constructor.
/// 4. The existing fake-server download proof reconstructs both plaintexts.
#[tokio::test]
async fn merged_cli_season_output_downloads_and_decrypts_both_episodes() {
    let password = "merged-season-proof-pass";
    let payload1: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
    let payload2: Vec<u8> = (0..200u32).map(|i| (i % 253) as u8).collect();

    let root = tempfile::tempdir().unwrap();
    let episodes_dir = root.path().join("Season01");
    std::fs::create_dir_all(&episodes_dir).unwrap();
    std::fs::write(episodes_dir.join("Show.S01E01.mkv"), &payload1).unwrap();
    std::fs::write(episodes_dir.join("Show.S01E02.mkv"), &payload2).unwrap();

    let nzb_dir = root.path().join("nzbs");
    std::fs::create_dir_all(&nzb_dir).unwrap();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let post_addr = spawn_post_capture_server(Arc::clone(&captured));

    let xdg_home = root.path().join("xdg");
    std::fs::create_dir_all(&xdg_home).unwrap();

    let base_args: Vec<std::ffi::OsString> = [
        "--no-ssl",
        "-s",
        "127.0.0.1",
        "-P",
        &post_addr.port().to_string(),
        "-g",
        "alt.binaries.test",
        "-n",
        "1",
        "--no-check",
        "--par2",
        "0",
        "--no-hooks",
        // `--encrypt` uses `require_equals`, so the value must be attached.
        &format!("--encrypt-password={password}"),
    ]
    .iter()
    .map(|s| std::ffi::OsStr::new(*s).to_os_string())
    .collect();

    // Two separate upload invocations: each gets its own random session salt.
    for episode in ["Show.S01E01.mkv", "Show.S01E02.mkv"] {
        let mut args = base_args.clone();
        args.push(std::ffi::OsStr::new("--nzb-dir").to_os_string());
        args.push(std::ffi::OsString::from(nzb_dir.to_str().unwrap()));
        args.push(episodes_dir.join(episode).into_os_string());
        let arg_refs: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
        let output = run_pesto(&xdg_home, &arg_refs);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "pesto upload of {episode} failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        eprintln!("== {episode} stdout ==\n{stdout}\n== stderr ==\n{stderr}");
    }

    let posted = captured.lock().unwrap().clone();
    assert!(
        posted.len() >= 2,
        "expected articles from both episodes; got {}",
        posted.len()
    );

    // Distinct salts: each upload invocation must draw its own session salt
    // even though both share the transport password.
    let mut salts = Vec::new();
    for article in &posted {
        let (salt, _) = pesto::crypto::extract_bootstrap_from_line1(article_body(article)).unwrap();
        salts.push(salt);
    }
    salts.sort();
    salts.dedup();
    assert!(
        salts.len() >= 2,
        "the two uploads must use distinct salts under one shared password"
    );

    // Actual per-episode NZBs (written by the CLI above) must be marked and
    // carry the transport password.
    for episode in ["Show.S01E01.nzb", "Show.S01E02.nzb"] {
        let content = std::fs::read_to_string(nzb_dir.join(episode)).unwrap();
        let parsed = pesto::nzb::parse(&content).unwrap();
        assert!(parsed.meta.yenc_encrypted, "{episode} must be marked");
        assert_eq!(
            parsed.meta.password.as_deref(),
            Some(password),
            "{episode} must carry the transport password"
        );
    }

    // The actual offline merge over the actual per-episode NZBs. Season
    // grouping derives the key from the episode stems (`Show.S01E01` →
    // `Show.S01`), so the combined NZB is `Show.S01.nzb`.
    let merge_output = run_pesto(
        &xdg_home,
        &[std::ffi::OsStr::new("--merge-season"), nzb_dir.as_os_str()],
    );
    assert!(
        merge_output.status.success(),
        "merge-season failed:\n{}",
        String::from_utf8_lossy(&merge_output.stderr)
    );
    let merged_path = nzb_dir.join("Show.S01.nzb");
    assert!(merged_path.exists(), "merged season NZB must be written");

    // Real download metadata + decryptor constructor over the actual
    // combined XML.
    let parsed = load(&merged_path).expect("merged NZB must parse");
    assert!(parsed.meta.yenc_encrypted, "merged NZB must be marked");
    assert_eq!(
        parsed.meta.password.as_deref(),
        Some(password),
        "merged NZB must retain the shared transport password"
    );
    let decryptor = download_decryptor(&parsed.meta)
        .expect("decryptor construction must not fail")
        .expect("decryption must activate on the merged metadata");

    // Existing fake-server proof: map Message-ID → captured article body and
    // reconstruct both plaintexts through the real Penne pipeline.
    let mut known = HashMap::new();
    for article in &posted {
        known.insert(
            article_message_id(article)
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_string(),
            article_body(article).to_vec(),
        );
    }
    let body_addr = spawn_body_server(known);

    let queue = build(&parsed);
    let dest = root.path().join("downloads");
    let outcome = download_queue_with_decryptor(
        &queue,
        &[ServerTier::solo(server_entry(body_addr))],
        &dest,
        0,
        None,
        Some(decryptor),
    )
    .await
    .expect("download must succeed");

    assert!(outcome.missing.is_empty(), "missing: {:?}", outcome.missing);
    assert!(outcome.corrupt.is_empty(), "corrupt: {:?}", outcome.corrupt);
    assert_eq!(
        std::fs::read(dest.join("Show.S01E01.mkv")).unwrap(),
        payload1,
        "episode 1 plaintext must reconstruct exactly"
    );
    assert_eq!(
        std::fs::read(dest.join("Show.S01E02.mkv")).unwrap(),
        payload2,
        "episode 2 plaintext must reconstruct exactly"
    );
}
