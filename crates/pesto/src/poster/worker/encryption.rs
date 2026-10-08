//! Encryption helpers for worker article preparation and repost workflows.

use crate::yenc;

/// Encrypt every control line of a complete yEnc block in place, per the
/// control-lines standard v1.2 §4: lineIndex counts every physical line
/// (control and data) 1-based from the start of the block; only control
/// lines (starting `=y`) are FF1-encrypted; data lines and line endings are
/// preserved byte-for-byte. Line 1 additionally gets the 20-byte bootstrap
/// (16B raw Alphabet salt || 4B uint32_be(segmentIndex)) prepended after
/// encryption (§4 step f).
///
/// The `=yencryption` header line inserted before this call is itself a
/// control line and is FF1-encrypted with its own lineIndex, exactly as an
/// ordinary `=ybegin`/`=ypart`/`=yend` line.
pub(crate) fn encrypt_control_lines(
    key: &yenc::encrypt::SessionKey,
    segment_index: u32,
    salt: &[u8; yenc::encrypt::SALT_LEN],
    body: Vec<u8>,
) -> Result<Vec<u8>, yenc::encrypt::EncryptionError> {
    use yenc::encrypt::{control_enc_key, control_tweak, encrypt_line1, ff1_encrypt_line};

    // Split preserving terminators (CRLF or LF — both accepted on the wire).
    let mut out: Vec<u8> = Vec::with_capacity(body.len() + 20);
    let mut line_index: u32 = 1;
    let mut search: usize = 0;
    while search < body.len() {
        let line_start = search;
        let term_len = {
            let nl = body[search..].iter().position(|&b| b == b'\n');
            match nl {
                Some(p) => {
                    let mut e = p + 1; // include \n
                    if e >= 2 && body[line_start + p - 1] == b'\r' {
                        e += 0; // \r already inside range; terminators stay as-is
                    }
                    e
                }
                None => body.len() - search,
            }
        };
        let content_end = line_start + term_len;
        let content = &body[line_start..content_end];
        // Trim trailing CR/LF for content inspection.
        let trimmed: &[u8] = {
            let mut t = content;
            if t.last() == Some(&b'\n') {
                t = &t[..t.len() - 1];
            }
            if t.last() == Some(&b'\r') {
                t = &t[..t.len() - 1];
            }
            t
        };
        let terminators = &content[trimmed.len()..];
        let encrypted_content = if line_index == 1 {
            encrypt_line1(key, segment_index, salt, trimmed)?
        } else if trimmed.starts_with(b"=y") {
            let enc_key = control_enc_key(key);
            let tweak = control_tweak(key, segment_index, line_index);
            ff1_encrypt_line(&enc_key, &tweak, trimmed)?
        } else {
            trimmed.to_vec()
        };
        out.extend_from_slice(&encrypted_content);
        out.extend_from_slice(terminators);
        search = content_end;
        line_index += 1;
    }
    Ok(out)
}

/// Repost-path counterpart of `prepare_ready`'s encrypt hook: insert the
/// `=yencryption` header into an already-yEnc-encoded block (physical line 2
/// for single-part, after `=ypart` for multi-part — control standard §3
/// placement rules), then FF1-encrypt the control lines including it.
pub(crate) fn encrypt_article_for_repost(
    key: &yenc::encrypt::SessionKey,
    segment_index: u32,
    salt: &[u8; yenc::encrypt::SALT_LEN],
    tag: [u8; 16],
    total_parts: u32,
    body: Vec<u8>,
) -> Result<Vec<u8>, yenc::encrypt::EncryptionError> {
    let header_line = yenc::encrypt::build_yencryption_line(salt, segment_index, &tag)?;
    // yEnc bodies are binary-safe: split on bytes, never via UTF-8 lossy
    // conversion, which would corrupt any high (>0x7F) encoded byte.
    let insert_at = if total_parts > 1 { 2 } else { 1 };
    let mut out: Vec<u8> = Vec::with_capacity(body.len() + header_line.len() + 2);
    let mut line_no: usize = 0;
    let mut search = 0usize;
    let mut inserted = false;
    while search < body.len() {
        let nl = body[search..].iter().position(|&b| b == b'\n');
        let end = match nl {
            Some(p) => search + p + 1,
            None => body.len(),
        };
        if line_no == insert_at && !inserted {
            out.extend_from_slice(header_line.as_bytes());
            out.extend_from_slice(b"\r\n");
            inserted = true;
        }
        out.extend_from_slice(&body[search..end]);
        search = end;
        line_no += 1;
    }
    if !inserted {
        out.extend_from_slice(header_line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    encrypt_control_lines(key, segment_index, salt, out)
}
