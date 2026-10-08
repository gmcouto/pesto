//! Integration tests for encrypted yEnc downloads in Penne.
//!
//! Covers:
//! - Encrypted article downloads and round-trips to byte-identical plaintext (single-part and multi-part).
//! - Auth failure on wrong password triggers provider failover (SegmentCorrupt).
//! - Zero plaintext bytes committed to final output on auth failure.
//! - Malformed =yencryption grammar causes immediate hard error.

use std::collections::HashMap;
use std::net::SocketAddr;

use pesto::config::ServerEntry;
use pesto::yenc::encrypt::{
    build_yencryption_line, encrypt_body, encrypt_control_line, encrypt_line1,
    sample_alphabet_salt, session_key_from,
};
use pesto::yenc::{encode_part, PartSpec};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};

use penne::config::ServerTier;
use penne::download::download_queue;
use penne::queue::{DownloadQueue, QueuedFile, QueuedSegment};

#[allow(clippy::too_many_arguments)]
fn build_encrypted_article(
    password: &str,
    salt: &[u8; 16],
    segment_index: u32,
    file_name: &str,
    part_number: u32,
    total_parts: u32,
    file_size: u64,
    offset: u64,
    part_bytes: &[u8],
) -> Vec<u8> {
    let master_key = session_key_from(password.as_bytes(), salt);
    let (ciphertext, tag) = encrypt_body(&master_key, segment_index, part_bytes).unwrap();

    let is_multipart = total_parts > 1;
    let part_spec = PartSpec {
        number: part_number,
        total: total_parts,
        offset,
    };

    let encoded = encode_part(file_name, file_size, part_spec, &ciphertext, 128, None);

    let raw_lines: Vec<&[u8]> = encoded
        .body
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty())
        .collect();

    let yenc_header = build_yencryption_line(salt, segment_index, &tag).unwrap();
    let yenc_header_bytes = yenc_header.into_bytes();

    let mut lines: Vec<Vec<u8>> = Vec::new();
    if is_multipart {
        lines.push(raw_lines[0].to_vec()); // =ybegin
        lines.push(raw_lines[1].to_vec()); // =ypart
        lines.push(yenc_header_bytes); // =yencryption
        for line in &raw_lines[2..raw_lines.len() - 1] {
            lines.push(line.to_vec());
        }
        lines.push(raw_lines[raw_lines.len() - 1].to_vec()); // =yend
    } else {
        lines.push(raw_lines[0].to_vec()); // =ybegin
        lines.push(yenc_header_bytes); // =yencryption
        for line in &raw_lines[1..raw_lines.len() - 1] {
            lines.push(line.to_vec());
        }
        lines.push(raw_lines[raw_lines.len() - 1].to_vec()); // =yend
    }

    // FF1 encrypt control lines
    let total_lines = lines.len() as u32;
    let enc_line1 = encrypt_line1(&master_key, segment_index, salt, &lines[0]).unwrap();
    lines[0] = enc_line1;

    if is_multipart {
        lines[1] = encrypt_control_line(&master_key, segment_index, 2, &lines[1]).unwrap();
        lines[2] = encrypt_control_line(&master_key, segment_index, 3, &lines[2]).unwrap();
    } else {
        lines[1] = encrypt_control_line(&master_key, segment_index, 2, &lines[1]).unwrap();
    }

    let footer_idx = lines.len() - 1;
    lines[footer_idx] =
        encrypt_control_line(&master_key, segment_index, total_lines, &lines[footer_idx]).unwrap();

    let mut wire = Vec::new();
    for line in lines {
        wire.extend_from_slice(&line);
        wire.extend_from_slice(b"\r\n");
    }
    wire
}

fn spawn_fake_server(known: HashMap<&'static str, Vec<u8>>) -> SocketAddr {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    let listener = TcpListener::from_std(std_listener).unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(handle_connection(stream, known.clone()));
        }
    });

    addr
}

async fn handle_connection(stream: TcpStream, known: HashMap<&'static str, Vec<u8>>) {
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

#[tokio::test]
async fn encrypted_article_round_trips_to_byte_identical_plaintext() {
    let password = "correct-password-123";
    let salt = sample_alphabet_salt();
    let plaintext = b"Hello, encrypted Usenet world! 1234567890".to_vec();

    let wire_article = build_encrypted_article(
        password,
        &salt,
        1,
        "secure.bin",
        1,
        1,
        plaintext.len() as u64,
        0,
        &plaintext,
    );

    let mut known = HashMap::new();
    known.insert("enc1@test", wire_article);
    let addr = spawn_fake_server(known);

    let queue = DownloadQueue {
        files: vec![QueuedFile {
            name: "secure.bin".to_string(),
            segments: vec![QueuedSegment {
                message_id: "enc1@test".to_string(),
                part: 1,
                bytes: 40,
            }],
            password: Some(password.to_string()),
            encrypted: true,
            encryption: Some("combined".to_string()),
        }],
    };
    let servers = vec![ServerTier::solo(server_entry(addr))];

    let dir = tempfile::tempdir().unwrap();
    let outcome = download_queue(&queue, &servers, dir.path(), 0, None)
        .await
        .unwrap();

    assert!(outcome.missing.is_empty());
    assert!(outcome.corrupt.is_empty());
    assert!(outcome.segments.contains("enc1@test"));

    let written = tokio::fs::read(dir.path().join("secure.bin"))
        .await
        .unwrap();
    assert_eq!(written, plaintext);
}

#[tokio::test]
async fn encrypted_multipart_article_round_trips_to_byte_identical_plaintext() {
    let password = "correct-password-multipart";
    let salt = sample_alphabet_salt();
    let part1_bytes = b"First part of encrypted file. 12".to_vec();
    let part2_bytes = b"Second part of encrypted file! 34".to_vec();
    let total_size = (part1_bytes.len() + part2_bytes.len()) as u64;

    let wire1 = build_encrypted_article(
        password,
        &salt,
        1,
        "multi.bin",
        1,
        2,
        total_size,
        0,
        &part1_bytes,
    );
    let wire2 = build_encrypted_article(
        password,
        &salt,
        2,
        "multi.bin",
        2,
        2,
        total_size,
        part1_bytes.len() as u64,
        &part2_bytes,
    );

    let mut known = HashMap::new();
    known.insert("multi1@test", wire1);
    known.insert("multi2@test", wire2);
    let addr = spawn_fake_server(known);

    let queue = DownloadQueue {
        files: vec![QueuedFile {
            name: "multi.bin".to_string(),
            segments: vec![
                QueuedSegment {
                    message_id: "multi1@test".to_string(),
                    part: 1,
                    bytes: part1_bytes.len() as u64,
                },
                QueuedSegment {
                    message_id: "multi2@test".to_string(),
                    part: 2,
                    bytes: part2_bytes.len() as u64,
                },
            ],
            password: Some(password.to_string()),
            encrypted: true,
            encryption: Some("combined".to_string()),
        }],
    };
    let servers = vec![ServerTier::solo(server_entry(addr))];

    let dir = tempfile::tempdir().unwrap();
    let outcome = download_queue(&queue, &servers, dir.path(), 0, None)
        .await
        .unwrap();

    if !outcome.corrupt.is_empty() {
        panic!("CORRUPT: {:?}", outcome.corrupt);
    }
    assert!(outcome.missing.is_empty());
    assert!(outcome.corrupt.is_empty());
    let written = tokio::fs::read(dir.path().join("multi.bin")).await.unwrap();
    let mut expected = part1_bytes;
    expected.extend_from_slice(&part2_bytes);
    assert_eq!(written, expected);
}

#[tokio::test]
async fn wrong_password_fails_over_to_backup_or_leaves_zero_plaintext() {
    let correct_pw = "correct-password";
    let wrong_pw = "wrong-password";
    let salt = sample_alphabet_salt();
    let plaintext = b"Sensitive plaintext that must never leak".to_vec();

    // Primary has article encrypted with correct_pw, but queue has wrong_pw
    let wire_article = build_encrypted_article(
        correct_pw,
        &salt,
        1,
        "secret.bin",
        1,
        1,
        plaintext.len() as u64,
        0,
        &plaintext,
    );

    let mut primary_known = HashMap::new();
    primary_known.insert("sec1@test", wire_article.clone());
    let primary_addr = spawn_fake_server(primary_known);

    let queue = DownloadQueue {
        files: vec![QueuedFile {
            name: "secret.bin".to_string(),
            segments: vec![QueuedSegment {
                message_id: "sec1@test".to_string(),
                part: 1,
                bytes: 40,
            }],
            password: Some(wrong_pw.to_string()),
            encrypted: true,
            encryption: Some("combined".to_string()),
        }],
    };
    let servers = vec![ServerTier::solo(server_entry(primary_addr))];

    let dir = tempfile::tempdir().unwrap();
    let outcome = download_queue(&queue, &servers, dir.path(), 0, None)
        .await
        .unwrap();

    // Segment must be marked corrupt (auth failure)
    assert_eq!(outcome.corrupt.len(), 1);
    assert_eq!(outcome.corrupt[0].message_id, "sec1@test");
    assert!(outcome.segments.is_empty());

    // Zero-output guarantee: destination file must NOT exist or must contain zero plaintext
    let dest_file = dir.path().join("secret.bin");
    if dest_file.exists() {
        let content = tokio::fs::read(&dest_file).await.unwrap();
        assert_ne!(content, plaintext);
        assert_eq!(content.len(), 0);
    }
}

#[tokio::test]
async fn malformed_yencryption_produces_hard_error() {
    let password = "test-password";
    let salt = sample_alphabet_salt();
    let plaintext = b"Plaintext for malformed test".to_vec();

    // Build article with unsupported cipher in =yencryption
    let master_key = session_key_from(password.as_bytes(), &salt);
    let (ciphertext, tag) = encrypt_body(&master_key, 1, &plaintext).unwrap();
    let encoded = encode_part(
        "test.bin",
        plaintext.len() as u64,
        PartSpec {
            number: 1,
            total: 1,
            offset: 0,
        },
        &ciphertext,
        128,
        None,
    );
    let raw_lines: Vec<&[u8]> = encoded
        .body
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty())
        .collect();

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Invalid cipher name
    let bad_header = format!(
        "=yencryption cipher=AES-GCM salt={} index=00000001 tag={}",
        to_hex(&salt),
        to_hex(&tag)
    );

    let mut lines = vec![
        raw_lines[0].to_vec(),
        bad_header.into_bytes(),
        raw_lines[1].to_vec(),
    ];

    let total_lines = lines.len() as u32;
    lines[0] = encrypt_line1(&master_key, 1, &salt, &lines[0]).unwrap();
    lines[1] = encrypt_control_line(&master_key, 1, 2, &lines[1]).unwrap();
    lines[2] = encrypt_control_line(&master_key, 1, total_lines, &lines[2]).unwrap();

    let mut wire = Vec::new();
    for l in lines {
        wire.extend_from_slice(&l);
        wire.extend_from_slice(b"\r\n");
    }

    let mut known = HashMap::new();
    known.insert("bad1@test", wire);
    let addr = spawn_fake_server(known);

    let queue = DownloadQueue {
        files: vec![QueuedFile {
            name: "test.bin".to_string(),
            segments: vec![QueuedSegment {
                message_id: "bad1@test".to_string(),
                part: 1,
                bytes: 40,
            }],
            password: Some(password.to_string()),
            encrypted: true,
            encryption: Some("combined".to_string()),
        }],
    };
    let servers = vec![ServerTier::solo(server_entry(addr))];

    let dir = tempfile::tempdir().unwrap();
    let result = download_queue(&queue, &servers, dir.path(), 0, None).await;

    // Must be a hard Err, not an Ok with corrupt segment
    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(err_str.contains("UNSUPPORTED_CIPHER") || err_str.contains("malformed =yencryption"));
}
