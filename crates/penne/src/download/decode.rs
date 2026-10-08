//! Article decoding, control-line restoration, and authenticated body decryption.

use pesto::yenc::decode_part;

use crate::queue::QueuedFile;

#[derive(Debug)]
pub(super) enum DecodeError {
    Corrupt(String),
    Hard(String),
}

fn split_lines(body: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = body
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines
}

pub(super) fn decode_article(
    body: &[u8],
    queued_file: Option<&QueuedFile>,
) -> Result<pesto::yenc::DecodedPart, DecodeError> {
    let lines = split_lines(body);
    if lines.is_empty() {
        return Err(DecodeError::Corrupt("empty article body".into()));
    }

    let file_flagged_encrypted = queued_file.is_some_and(|f| f.encrypted);
    let line1_is_plain_ybegin = lines[0].starts_with(b"=ybegin");

    let is_encrypted = file_flagged_encrypted
        || (!line1_is_plain_ybegin
            && lines[0].len() >= pesto::yenc::encrypt::BOOTSTRAP_LEN + 2
            && pesto::yenc::encrypt::extract_bootstrap(lines[0]).is_ok());

    if !is_encrypted {
        let decoded = decode_part(body).map_err(|e| DecodeError::Corrupt(e.to_string()))?;
        if !decoded.crc_matches() {
            return Err(DecodeError::Corrupt("wire CRC mismatch".into()));
        }
        return Ok(decoded);
    }

    // C1-09: Missing/truncated =yencryption on a flagged-encrypted file = provider corruption/failover
    if file_flagged_encrypted && line1_is_plain_ybegin {
        return Err(DecodeError::Corrupt(
            "missing encryption bootstrap on flagged encrypted file".into(),
        ));
    }

    let password = queued_file
        .and_then(|f| f.password.as_deref())
        .unwrap_or("");

    // 1. Extract 20-byte Line-1 bootstrap (salt bytes 0..15, index bytes 16..19)
    let bootstrap = pesto::yenc::encrypt::extract_bootstrap(lines[0])
        .map_err(|e| DecodeError::Corrupt(format!("invalid line 1 bootstrap: {e}")))?;

    // 2. Derive master key from password and bootstrap salt
    let master_key = pesto::yenc::encrypt::session_key_from(password.as_bytes(), &bootstrap.salt);

    // 3. FF1-decrypt Line 1
    let (decrypted_line1, bootstrap) =
        match pesto::yenc::encrypt::decrypt_line1(&master_key, lines[0]) {
            Ok(res) => res,
            Err(e) => {
                return Err(DecodeError::Corrupt(format!(
                    "failed to decrypt line 1: {e}"
                )));
            }
        };
    if !decrypted_line1.starts_with(b"=ybegin ") {
        return Err(DecodeError::Corrupt(
            "decrypted line 1 does not start with =ybegin".into(),
        ));
    }

    let is_multipart = decrypted_line1
        .as_slice()
        .split(|&b| b == b' ')
        .any(|token| token.starts_with(b"part="));

    let min_lines = if is_multipart { 4 } else { 3 };
    if lines.len() < min_lines {
        return Err(DecodeError::Corrupt(
            "article too short for encrypted yEnc structure".into(),
        ));
    }

    // 4. Decrypt subsequent header lines until data lines
    let decrypted_line2: Vec<u8>;
    let yenc_header_bytes: Vec<u8>;
    let data_start: usize;

    if is_multipart {
        decrypted_line2 = pesto::yenc::encrypt::decrypt_control_line(
            &master_key,
            bootstrap.segment_index,
            2,
            lines[1],
        )
        .map_err(|e| DecodeError::Corrupt(format!("failed to decrypt line 2: {e}")))?;

        if !decrypted_line2.starts_with(b"=ypart ") {
            return Err(DecodeError::Corrupt(
                "decrypted line 2 does not start with =ypart".into(),
            ));
        }

        let decrypted_line3 = pesto::yenc::encrypt::decrypt_control_line(
            &master_key,
            bootstrap.segment_index,
            3,
            lines[2],
        )
        .map_err(|e| DecodeError::Corrupt(format!("failed to decrypt line 3: {e}")))?;

        if !decrypted_line3.starts_with(b"=yencryption") {
            return Err(DecodeError::Corrupt(
                "decrypted line 3 does not start with =yencryption".into(),
            ));
        }
        yenc_header_bytes = decrypted_line3;
        data_start = 3;
    } else {
        decrypted_line2 = pesto::yenc::encrypt::decrypt_control_line(
            &master_key,
            bootstrap.segment_index,
            2,
            lines[1],
        )
        .map_err(|e| DecodeError::Corrupt(format!("failed to decrypt line 2: {e}")))?;

        if !decrypted_line2.starts_with(b"=yencryption") {
            return Err(DecodeError::Corrupt(
                "decrypted line 2 does not start with =yencryption".into(),
            ));
        }
        yenc_header_bytes = decrypted_line2.clone();
        data_start = 2;
    }

    // 5. Validate =yencryption five-token grammar immediately
    let yenc_str = std::str::from_utf8(&yenc_header_bytes)
        .map_err(|_| DecodeError::Hard("invalid UTF-8 in =yencryption line".into()))?;

    let header = match pesto::yenc::encrypt::parse_yencryption_line(yenc_str) {
        Ok(h) => h,
        Err(e) => match e {
            pesto::yenc::encrypt::EncryptionError::UnsupportedCipher
            | pesto::yenc::encrypt::EncryptionError::InvalidTokenCount
            | pesto::yenc::encrypt::EncryptionError::InvalidWhitespace
            | pesto::yenc::encrypt::EncryptionError::InvalidTagHex
            | pesto::yenc::encrypt::EncryptionError::InvalidIndexHex
            | pesto::yenc::encrypt::EncryptionError::InvalidSaltHex
            | pesto::yenc::encrypt::EncryptionError::UppercaseHex
            | pesto::yenc::encrypt::EncryptionError::InvalidSaltLength
            | pesto::yenc::encrypt::EncryptionError::InvalidTagLength
            | pesto::yenc::encrypt::EncryptionError::InvalidIndexLength => {
                return Err(DecodeError::Hard(format!(
                    "malformed =yencryption header: {e}"
                )));
            }
            _ => {
                return Err(DecodeError::Corrupt(format!(
                    "invalid =yencryption parameters: {e}"
                )));
            }
        },
    };

    // 6. Dual-bootstrap agreement check (salt + index byte-equal)
    if bootstrap.salt != header.salt || bootstrap.segment_index != header.segment_index {
        return Err(DecodeError::Corrupt(
            "dual-bootstrap agreement mismatch: salt or segment_index in line 1 differs from =yencryption".into(),
        ));
    }

    // 7. Decrypt footer line (=yend)
    let total_lines = lines.len() as u32;
    let decrypted_footer = pesto::yenc::encrypt::decrypt_control_line(
        &master_key,
        bootstrap.segment_index,
        total_lines,
        lines[lines.len() - 1],
    )
    .map_err(|e| DecodeError::Corrupt(format!("failed to decrypt footer line: {e}")))?;

    if !decrypted_footer.starts_with(b"=yend") {
        return Err(DecodeError::Corrupt(
            "decrypted footer line does not start with =yend".into(),
        ));
    }

    // 8. Reconstruct yEnc block WITHOUT =yencryption and yEnc-decode
    let mut reconstructed = Vec::new();
    reconstructed.extend_from_slice(&decrypted_line1);
    reconstructed.extend_from_slice(b"\r\n");
    if is_multipart {
        reconstructed.extend_from_slice(&decrypted_line2);
        reconstructed.extend_from_slice(b"\r\n");
    }
    for data_line in &lines[data_start..lines.len() - 1] {
        reconstructed.extend_from_slice(data_line);
        reconstructed.extend_from_slice(b"\r\n");
    }
    reconstructed.extend_from_slice(&decrypted_footer);
    reconstructed.extend_from_slice(b"\r\n");

    let mut decoded = decode_part(&reconstructed)
        .map_err(|e| DecodeError::Corrupt(format!("yEnc decode failed: {e}")))?;

    if !decoded.crc_matches() {
        return Err(DecodeError::Corrupt(
            "wire CRC mismatch over ciphertext".into(),
        ));
    }

    // 9. AEAD authenticate + decrypt
    let plaintext = pesto::yenc::encrypt::decrypt_body(
        &master_key,
        header.segment_index,
        &decoded.data,
        &header.tag,
    )
    .map_err(|e| DecodeError::Corrupt(format!("AEAD authentication failed: {e}")))?;

    // 10. Recompute CRC over plaintext and clear wire CRC
    let mut crc = pesto::yenc::Crc32::new();
    crc.update(&plaintext);
    decoded.part_crc32 = Some(crc.finalize());
    decoded.file_crc32 = None;
    decoded.data = plaintext;

    Ok(decoded)
}
