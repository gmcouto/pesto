//! Cryptographic adapter presenting standard yEnc encode and decode article contracts.

use anyhow::{bail, ensure, Context, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

use super::body;
use super::control;
use super::kdf::EncryptionSession;
use crate::yenc::{self, DecodedPart, EncodedPart, PartSpec};

/// Build the canonical `=yencryption` control line (Body Encryption Standard
/// v1.2 §4: exactly `CANONICAL_YENCRYPTION_LINE_LEN` bytes + `\r\n`).
fn format_yencryption_line(salt: &[u8; 16], tag: &[u8; 16], segment_index: u32) -> String {
    use std::fmt::Write;
    let mut line = String::with_capacity(CANONICAL_YENCRYPTION_LINE_LEN + 2);
    line.push_str("=yencryption cipher=XChaCha20-Poly1305 salt=");
    for b in salt {
        write!(&mut line, "{b:02x}").expect("writing to a String cannot fail");
    }
    write!(&mut line, " index={segment_index:08x} tag=").expect("writing to a String cannot fail");
    for b in tag {
        write!(&mut line, "{b:02x}").expect("writing to a String cannot fail");
    }
    debug_assert_eq!(line.len(), CANONICAL_YENCRYPTION_LINE_LEN);
    line.push_str("\r\n");
    line
}

/// Insert the `=yencryption` line into an already yEnc-encoded article body:
/// immediately after `=ypart` for a multipart article, or after `=ybegin` for
/// a single-part one (v1.2 Body Std §4 placement). Crypto-only seam — the
/// ordinary codec knows nothing about `=yencryption`. Fails without touching
/// `body` when a multipart article lacks its `=ypart` line (recoverable
/// encoding error, never a panic).
fn insert_yencryption_line(
    body: &mut Vec<u8>,
    salt: &[u8; 16],
    tag: &[u8; 16],
    segment_index: u32,
    multipart: bool,
) -> Result<()> {
    let line = format_yencryption_line(salt, tag, segment_index);
    let insertion_idx = if multipart {
        let ypart_rel = body
            .windows(7)
            .position(|w| w == b"\n=ypart")
            .context("MISSING_YPART_LINE: yEnc body lacks the =ypart framing the =yencryption line must follow")?;
        let ypart_pos = ypart_rel + 1;
        let nl_pos = body[ypart_pos..]
            .iter()
            .position(|&b| b == b'\n')
            .context("MISSING_YPART_LINE: yEnc body lacks the =ypart framing the =yencryption line must follow")?;
        ypart_pos + nl_pos + 1
    } else {
        body.iter()
            .position(|&b| b == b'\n')
            .map(|nl_pos| nl_pos + 1)
            .context("encrypted yEnc body has no line terminator")?
    };

    let mut out = Vec::with_capacity(body.len() + line.len());
    out.extend_from_slice(&body[..insertion_idx]);
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(&body[insertion_idx..]);
    *body = out;
    Ok(())
}

/// Thin adapter presenting standard yEnc encode contract for encrypted articles.
pub struct UploadEncryptionAdapter {
    session: Arc<EncryptionSession>,
}

impl UploadEncryptionAdapter {
    pub fn new(session: Arc<EncryptionSession>) -> Self {
        Self { session }
    }

    /// Encrypt and yEnc-encode a raw article segment.
    ///
    /// 1. Derives 24-byte body nonce from `segment_index`.
    /// 2. Encrypts `data` via XChaCha20-Poly1305 -> `(ciphertext, tag)`.
    /// 3. yEnc-encodes `ciphertext` into `body` buffer.
    /// 4. Injects `=yencryption` control line.
    /// 5. FF1-encrypts all control lines over Radix 253, prepending 16-byte salt to line 1.
    ///
    /// `_file_crc32` is accepted for call-site symmetry with the ordinary
    /// encoder but never written: a plaintext whole-file CRC on the last
    /// multipart `=yend` must not be emitted (Body Std v1.2 §5 step 5), and a
    /// ciphertext whole-file CRC cannot be computed per segment.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_article(
        &self,
        name: &str,
        file_size: u64,
        spec: PartSpec,
        data: &[u8],
        line_len: usize,
        _file_crc32: Option<u32>,
        segment_index: u32,
        body: &mut Vec<u8>,
    ) -> Result<EncodedPart> {
        if file_size >= (1u64 << 32) {
            bail!("SIZE_OVERFLOW: encrypted file size must be less than 4 GiB (2^32 bytes)");
        }
        let nonce = self.session.derive_body_nonce(segment_index);
        // AAD geometry (Body Encryption Standard v1.2 §2.1): multipart
        // partBegin is the =ypart `begin` (= offset + 1); single-part
        // partBegin is 1 (=offset 0 + 1, same formula). segmentBytes is the
        // plaintext byte count, which equals end-begin+1 (multipart) or the
        // =ybegin `size` (single-part) by construction.
        let part_begin = (spec.offset + 1) as u32;
        let aad =
            body::format_body_aad(spec.number, part_begin, data.len() as u64, name.as_bytes());
        let (ciphertext, tag) = body::encrypt_body(data, &aad, self.session.master_key(), &nonce)?;

        let mut encoded =
            yenc::encode_part_into(name, file_size, spec, &ciphertext, line_len, None, body);

        // Format and insert the =yencryption control line: after =ypart
        // (multipart) or after =ybegin (single-part). A multipart body
        // missing =ypart fails with `MISSING_YPART_LINE` instead of
        // producing a silently misplaced header.
        let salt = self.session.salt();
        insert_yencryption_line(
            &mut encoded.body,
            &salt,
            &tag,
            segment_index,
            spec.total > 1,
        )?;

        // Encrypt control lines using FF1
        let wire_body =
            control::encrypt_yenc_control_lines(&self.session, segment_index, &encoded.body)?;

        encoded.body = wire_body;
        Ok(encoded)
    }
}

/// Parameters extracted from the `=yencryption` control line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YEncryptionParams {
    pub salt: [u8; 16],
    pub segment_index: u32,
    pub tag: [u8; 16],
}

/// Byte length of the canonical `=yencryption` line (v1.2 Body Std §4).
pub const CANONICAL_YENCRYPTION_LINE_LEN: usize = 128;

/// Parse parameters from `=yencryption ...` control line.
///
/// Accepts only the canonical token sequence:
/// `=yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>`
/// Salt and tag must be exactly 32 lowercase hexadecimal characters.
/// Index must be exactly 8 lowercase hexadecimal characters representing uint32_be > 0.
/// No extra, duplicate, missing, or reordered fields are permitted.
///
/// Whitespace strictness (v1.2 Control Std §3): tokens are separated by
/// EXACTLY one ASCII space — a tab anywhere or two consecutive spaces
/// anywhere is `INVALID_WHITESPACE`. The canonical line is exactly 128
/// bytes long (`11 + 26 + 1 + 37 + 1 + 13 + 1 + 36`); any other length is
/// rejected. Ordinary yEnc headers (`=ybegin`/`=ypart`/`=yend` in
/// `yenc/decode.rs`) historically allow flexible whitespace and are
/// deliberately NOT made strict here.
pub fn parse_yencryption_line(line: &[u8]) -> Result<YEncryptionParams> {
    ensure!(
        line.starts_with(b"=yencryption"),
        "INVALID_TOKEN_COUNT: line does not begin with =yencryption token"
    );
    let text =
        std::str::from_utf8(line).map_err(|_| anyhow::anyhow!("invalid utf8 in =yencryption"))?;
    // Strict single-SP split (v1.2 Control Std §3): tab or repeated/edge
    // space anywhere is INVALID_WHITESPACE.
    if text.contains('\t') || text.contains("  ") || text.starts_with(' ') || text.ends_with(' ') {
        bail!("INVALID_WHITESPACE: tab or repeated space in =yencryption line");
    }
    let tokens: Vec<&str> = text.split(' ').collect();
    if tokens.len() != 5 {
        // The vectors distinguish a missing first parameter from a generic
        // count error: bare `=yencryption` is MISSING_CIPHER.
        if tokens.len() < 2 {
            bail!("MISSING_CIPHER: cipher parameter missing");
        }
        bail!(
            "INVALID_TOKEN_COUNT: expected 5 tokens, got {}",
            tokens.len()
        );
    }
    let (cipher, salt, index, tag) = (&tokens[1], &tokens[2], &tokens[3], &tokens[4]);
    if !cipher.starts_with("cipher=") {
        bail!("UNSUPPORTED_CIPHER: cipher parameter out of order");
    }
    if cipher["cipher=".len()..] != *"XChaCha20-Poly1305" {
        bail!(
            "UNSUPPORTED_CIPHER: unsupported cipher {}",
            &cipher["cipher=".len()..]
        );
    }
    if !salt.starts_with("salt=") {
        bail!("REORDERED_HEADER: salt parameter out of order");
    }
    if !index.starts_with("index=") {
        bail!("REORDERED_HEADER: index parameter out of order");
    }
    if !tag.starts_with("tag=") {
        bail!("REORDERED_HEADER: tag parameter out of order");
    }

    let salt_bytes = decode_hex_field(
        &salt["salt=".len()..],
        32,
        "INVALID_SALT_LENGTH",
        "INVALID_SALT_HEX",
    )?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&salt_bytes);
    let index_str = &index["index=".len()..];
    let index_bytes = decode_hex_field(index_str, 8, "INVALID_INDEX_LENGTH", "INVALID_INDEX_HEX")?;
    let segment_index = u32::from_be_bytes(index_bytes.try_into().unwrap());
    let tag_bytes = decode_hex_field(
        &tag["tag=".len()..],
        32,
        "INVALID_TAG_LENGTH",
        "INVALID_TAG_HEX",
    )?;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    if segment_index == 0 {
        bail!("ZERO_SEGMENT_INDEX: segment index cannot be zero");
    }

    Ok(YEncryptionParams {
        salt,
        segment_index,
        tag,
    })
}

/// Decode a fixed-length lowercase-hex field, keeping the vector-matched
/// error codes: `len_code` when the length is wrong, `UPPERCASE_HEX` for
/// uppercase digits and `hex_code` for any other non-hex character.
fn decode_hex_field(
    value: &str,
    expected_len: usize,
    len_code: &str,
    hex_code: &str,
) -> Result<Vec<u8>> {
    if value.len() != expected_len {
        bail!(
            "{len_code}: must be exactly {expected_len} hex characters, got {}",
            value.len()
        );
    }
    let mut out = vec![0u8; expected_len / 2];
    for (i, b) in value.bytes().enumerate() {
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => bail!("UPPERCASE_HEX: hex contains uppercase hex characters"),
            _ => bail!("{hex_code}: hex contains non-hex or non-lowercase characters"),
        };
        out[i / 2] = if i % 2 == 0 { v << 4 } else { out[i / 2] | v };
    }
    Ok(out)
}

/// Extract `=yencryption` parameters and remove the single `=yencryption` line from restored yEnc text.
///
/// Enforces strict header structure:
/// - Restored line 1 must be `=ybegin`
/// - For multipart input (line 2 is `=ypart`), line 3 must be the sole `=yencryption` line
/// - For single-part input, line 2 must be the sole `=yencryption` line
/// - Any duplicate or misplaced `=yencryption` line anywhere in the article is rejected
pub fn extract_and_remove_yencryption(input: &[u8]) -> Result<(YEncryptionParams, Vec<u8>)> {
    let lines = control::split_lines_preserving_endings(input);
    ensure!(
        lines.len() >= 2,
        "article has too few lines for encrypted yEnc headers"
    );

    ensure!(
        lines[0].content.starts_with(b"=ybegin"),
        "restored line 1 must be =ybegin"
    );

    let yenc_line_idx = if lines[1].content.starts_with(b"=ypart") {
        ensure!(
            lines.len() >= 3,
            "article has too few lines for multipart encrypted yEnc headers"
        );
        ensure!(
            lines[2].content.starts_with(b"=yencryption"),
            "restored line 3 must be =yencryption in multipart article"
        );
        2
    } else if lines[1].content.starts_with(b"=yencryption") {
        1
    } else {
        bail!("missing or misplaced =yencryption header line");
    };

    // Ensure no other =yencryption line exists in the entire article
    for (idx, line) in lines.iter().enumerate() {
        if idx != yenc_line_idx && line.content.starts_with(b"=yencryption") {
            bail!(
                "duplicate or misplaced =yencryption line at line {}",
                idx + 1
            );
        }
    }

    let params = parse_yencryption_line(lines[yenc_line_idx].content)?;

    let mut out = Vec::with_capacity(input.len());
    for (idx, line) in lines.iter().enumerate() {
        if idx != yenc_line_idx {
            out.extend_from_slice(line.content);
            out.extend_from_slice(line.ending);
        }
    }

    Ok((params, out))
}

/// Raw bytes of the `name=` value on the restored `=ybegin` line (the first
/// line of `restored`). `name=` is the last `=ybegin` keyword and its value
/// runs to the end of the line (Body Std v1.2 §2.1), so no byte is decoded.
fn ybegin_raw_name(restored: &[u8]) -> Result<Vec<u8>> {
    let end = restored
        .iter()
        .position(|&b| b == b'\n')
        .context("restored article has no =ybegin line terminator")?;
    let line = restored[..end]
        .strip_suffix(b"\r")
        .unwrap_or(&restored[..end]);
    let pos = line
        .windows(5)
        .position(|w| w == b"name=")
        .context("MISSING_AAD_INPUT: =ybegin line has no name= parameter")?;
    Ok(line[pos + 5..].to_vec())
}

const MAX_CACHED_SESSIONS: usize = 16;

/// One slot per salt so concurrent workers that miss the cache for the same
/// salt share a single Argon2id derivation instead of each running their own.
///
/// Derivation failure is deterministic for a given password and salt, so the
/// slot stores the error message and later callers see the same failure.
type SessionSlot = Arc<OnceLock<std::result::Result<Arc<EncryptionSession>, String>>>;

type SessionCache = (HashMap<[u8; 16], SessionSlot>, VecDeque<[u8; 16]>);

/// Thin adapter presenting standard yEnc decode contract for downloaded articles.
pub struct DownloadDecryptionAdapter {
    password: Zeroizing<String>,
    cached_sessions: std::sync::Mutex<SessionCache>,
}

impl DownloadDecryptionAdapter {
    /// Build a decryption adapter for `password`. The caller configured
    /// transport decryption for this download, so any unencrypted article
    /// starting with `=ybegin` is rejected as `UNAUTHENTICATED_ARTICLE`
    /// (fail closed): accepting it would release unauthenticated plaintext
    /// and violate the Zero-Output Guarantee.
    pub fn with_password(password: &str) -> Self {
        Self {
            password: Zeroizing::new(password.to_string()),
            cached_sessions: std::sync::Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }

    /// Decode an article wire body, restoring encrypted control lines and decrypting body ciphertext.
    ///
    /// The `segmentIndex` and salt are taken from the article bootstrap.
    /// Strictly guarantees Zero-Output on authentication failure.
    pub fn decode_article(&self, body: &[u8]) -> Result<DecodedPart> {
        if body.starts_with(b"=ybegin") {
            bail!("UNAUTHENTICATED_ARTICLE: unencrypted article received for encrypted segment");
        }

        // Line 1 terminator search must skip the 20-byte bootstrap prefix
        // (which may itself contain 0x0A/0x0D) — exactly what
        // `split_lines_preserving_endings` implements, so reuse it instead
        // of a second hand-rolled scan.
        let lines = control::split_lines_preserving_endings(body);
        let first_line = lines
            .first()
            .context("article has no newline terminators")?;
        let (salt, segment_index) = control::extract_bootstrap_from_line1(first_line.content)?;
        let session = self.get_or_create_session(salt)?;

        // Decrypt control lines
        let restored_yenc = control::decrypt_yenc_control_lines(&session, segment_index, body)?;

        // Extract and remove =yencryption line
        let (yenc_params, clean_yenc) = extract_and_remove_yencryption(&restored_yenc)?;

        // Dual-Bootstrap Agreement (Body Std v1.2 §6): the salt and
        // segmentIndex extracted from control Line 1 must match the
        // `=yencryption` header tokens.
        if yenc_params.salt != session.salt() {
            bail!(
                "DUAL_SALT_MISMATCH: salt mismatch between control line 1 and =yencryption header"
            );
        }
        if yenc_params.segment_index != segment_index {
            bail!(
                "DUAL_INDEX_MISMATCH: segmentIndex mismatch between control line 1 ({}) and =yencryption header ({})",
                segment_index,
                yenc_params.segment_index
            );
        }

        let multipart = control::split_lines_preserving_endings(&clean_yenc)
            .get(1)
            .is_some_and(|line| line.content.starts_with(b"=ypart"));

        let lines = control::split_lines_preserving_endings(&clean_yenc);
        // Body Standard v1.2 §2.1/§5: preserve physical multipart metadata
        // independently of the ordinary decoder's total-based framing.
        let multipart_metadata = if multipart {
            let range = std::str::from_utf8(lines[1].content)
                .context("INVALID_GEOMETRY: =ypart has non-ASCII fields")?;
            let field = |key: &str| -> Result<u64> {
                range
                    .split_whitespace()
                    .find_map(|token| token.strip_prefix(key))
                    .and_then(|value| value.parse().ok())
                    .with_context(|| format!("INVALID_GEOMETRY: =ypart missing or invalid {key}"))
            };
            let begin = field("begin=")?;
            let end = field("end=")?;
            let pcrc = lines
                .iter()
                .find(|line| line.content.starts_with(b"=yend"))
                .and_then(|line| {
                    line.content
                        .split(|&b| b == b' ' || b == b'\t')
                        .find_map(|token| token.strip_prefix(b"pcrc32="))
                })
                .filter(|value| value.len() == 8)
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| u32::from_str_radix(value, 16).ok())
                .context("PROVIDER_FAILOVER: missing or invalid ciphertext pcrc32 CRC")?;
            Some((begin, end, pcrc))
        } else {
            None
        };

        let name_idx = lines[0]
            .content
            .windows(5)
            .position(|w| w == b"name=")
            .context("MISSING_AAD_INPUT: =ybegin line has no name= parameter")?;
        let fields = std::str::from_utf8(&lines[0].content[..name_idx])
            .context("INVALID_GEOMETRY: =ybegin has non-ASCII fields")?;
        let file_size = fields
            .split_whitespace()
            .filter_map(|token| token.strip_prefix("size="))
            .next_back()
            .and_then(|value| value.parse::<u64>().ok())
            .context("INVALID_GEOMETRY: =ybegin missing or invalid size=")?;
        let (begin, end) = multipart_metadata
            .map(|(begin, end, _)| (begin, end))
            .unwrap_or((1, file_size));
        // Body Standard v1.2 §2.1/§5: validate untrusted geometry before
        // the ordinary decoder can reserve memory from the declared range.
        ensure!(
            file_size < (1u64 << 32) && begin < (1u64 << 32) && end < (1u64 << 32),
            "PROVIDER_FAILOVER: SIZE_OVERFLOW: encrypted file size/offset exceeds 4 GiB (2^32 bytes)"
        );
        let segment_bytes = if file_size == 0 {
            ensure!(
                begin == 1 && end == 0,
                "PROVIDER_FAILOVER: INVALID_GEOMETRY: empty file begin/end mismatch"
            );
            0
        } else {
            ensure!(
                begin >= 1 && begin <= end && end <= file_size,
                "PROVIDER_FAILOVER: INVALID_GEOMETRY: part range is outside the file"
            );
            end - begin + 1
        };
        ensure!(
            segment_bytes <= clean_yenc.len() as u64,
            "PROVIDER_FAILOVER: INVALID_GEOMETRY: segment range exceeds article length"
        );
        let is_multi = fields
            .split_whitespace()
            .filter_map(|token| token.strip_prefix("total="))
            .next_back()
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|total| total > 1);

        // Keep ordinary decoding upstream. Supply article-sized geometry at
        // its seam, then restore the original authenticated metadata. In
        // particular, total=1 must not reserve the whole file's capacity.
        let mut clean_for_decode = Vec::with_capacity(clean_yenc.len());
        clean_for_decode.extend_from_slice(&lines[0].content[..name_idx]);
        clean_for_decode.extend_from_slice(format!("size={segment_bytes} ").as_bytes());
        clean_for_decode.extend_from_slice(&lines[0].content[name_idx..]);
        clean_for_decode.extend_from_slice(lines[0].ending);
        for (idx, line) in lines.iter().enumerate().skip(1) {
            if multipart && idx == 1 {
                if is_multi {
                    clean_for_decode.extend_from_slice(
                        format!("=ypart begin=1 end={segment_bytes}").as_bytes(),
                    );
                    clean_for_decode.extend_from_slice(line.ending);
                }
            } else {
                clean_for_decode.extend_from_slice(line.content);
                clean_for_decode.extend_from_slice(line.ending);
            }
        }
        let mut decoded = yenc::decode_part(&clean_for_decode)?;
        decoded.file_size = file_size;
        decoded.begin = begin;
        decoded.end = end;
        if let Some((_, _, pcrc)) = multipart_metadata {
            decoded.part_crc32 = Some(pcrc);
        }

        // Ciphertext CRC check before AEAD decryption. Multipart framing is
        // carried explicitly by the `=ypart` line: a `pcrc32=` on a
        // part=1/total=1 article (or on any article carrying `=ypart`) is
        // the per-part ciphertext CRC and is checked the same way — the
        // wire CRC describes the ciphertext, so it must verify regardless
        // of the part count (Body Std v1.2 §5 CRC ordering).
        ensure!(
            if multipart {
                decoded.part_crc32.is_some()
            } else {
                decoded.file_crc32.is_some()
            },
            "PROVIDER_FAILOVER: missing ciphertext CRC"
        );
        if !decoded.crc_matches() {
            bail!("ciphertext CRC mismatch");
        }

        // AAD inputs (Body Std v1.2 §2.1): read from the restored article
        // only. `name` is mandatory in encrypted articles; multipart
        // geometry comes from the restored `=ypart`, single-part geometry
        // from the `=ybegin` size. The name is the raw bytes after `name=`
        // on the restored `=ybegin` line: `decoded.name` is lossy UTF-8 and
        // would change the AAD for a non-UTF-8 name.
        let aad_name = ybegin_raw_name(&clean_yenc)?;
        ensure!(
            !aad_name.is_empty(),
            "MISSING_AAD_INPUT: =ybegin name parameter is mandatory in encrypted articles"
        );
        ensure!(
            segment_bytes as usize == decoded.data.len(),
            "INVALID_GEOMETRY: segment bytes does not match ciphertext length"
        );
        let part_number = decoded.part;
        let part_begin = decoded.begin as u32;
        let aad = body::format_body_aad(part_number, part_begin, segment_bytes, &aad_name);

        // Authenticate and decrypt body ciphertext with Zero-Output Guarantee.
        // Poly1305 failure is provider corruption (retriable).
        let nonce = session.derive_body_nonce(segment_index);
        let plaintext = body::decrypt_body(
            &decoded.data,
            &yenc_params.tag,
            &aad,
            session.master_key(),
            &nonce,
        )
        .map_err(|e| anyhow::anyhow!("AUTHENTICATION_FAILURE: {e}"))?;

        // Zero-output guarantee: replace data with authenticated plaintext.
        // CRC normalization — recompute over the authenticated plaintext (Body
        // Std v1.2 §5, Downstream CRC Normalization, permits clear OR
        // recompute; recompute preserves the
        // downstream per-part verification that clearing would drop). The
        // plaintext here is post-Poly1305-auth, so the CRC describes verified
        // data. The wire `crc32=`/`pcrc32=` values cover ciphertext and are
        // discarded; the whole-file CRC cannot be derived from a single
        // segment, so `file_crc32` stays cleared and verification folds part
        // CRCs via `crc32_combine` at assembly time.
        decoded.part_crc32 = {
            let mut crc = yenc::Crc32::new();
            crc.update(&plaintext);
            Some(crc.finalize())
        };
        decoded.file_crc32 = None;
        decoded.data = plaintext;

        Ok(decoded)
    }

    fn get_or_create_session(&self, salt: [u8; 16]) -> Result<Arc<EncryptionSession>> {
        self.get_or_derive_session(salt, || EncryptionSession::new(&self.password, salt))
    }

    fn get_or_derive_session(
        &self,
        salt: [u8; 16],
        derive: impl FnOnce() -> Result<EncryptionSession>,
    ) -> Result<Arc<EncryptionSession>> {
        // A poisoned lock fails closed as a crypto error instead of panicking.
        let slot = {
            let mut guard = self
                .cached_sessions
                .lock()
                .map_err(|_| anyhow::anyhow!("session cache lock poisoned"))?;
            if let Some(slot) = guard.0.get(&salt) {
                slot.clone()
            } else {
                if guard.0.len() == MAX_CACHED_SESSIONS {
                    if let Some(oldest) = guard.1.pop_front() {
                        guard.0.remove(&oldest);
                    }
                }
                let slot = SessionSlot::default();
                guard.0.insert(salt, slot.clone());
                guard.1.push_back(salt);
                slot
            }
        };

        // Derive outside the map lock so different salts run in parallel; the
        // slot runs the 64 MiB Argon2id derivation once per salt while other
        // workers for the same salt wait for its result.
        slot.get_or_init(|| derive().map(Arc::new).map_err(|e| format!("{e:#}")))
            .clone()
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(test)]
mod tests;
