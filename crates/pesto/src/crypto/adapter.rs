//! Cryptographic adapter presenting standard yEnc encode and decode article contracts.

use anyhow::{bail, ensure, Context, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use super::body;
use super::control;
use super::kdf::EncryptionSession;
use super::{attach_crypto_error_kind, CryptoErrorKind};
use crate::poster::SegmentIdentity;
use crate::yenc::{self, DecodedPart, EncodedPart, PartSpec};

/// Thin adapter presenting standard yEnc encode contract for encrypted articles.
pub struct UploadEncryptionAdapter {
    session: Arc<EncryptionSession>,
}

impl UploadEncryptionAdapter {
    pub fn new(session: Arc<EncryptionSession>) -> Self {
        Self { session }
    }

    pub fn session(&self) -> &Arc<EncryptionSession> {
        &self.session
    }

    /// Encrypt and yEnc-encode a raw article segment.
    ///
    /// 1. Derives 24-byte body nonce from `identity.segment_index`.
    /// 2. Encrypts `data` via XChaCha20-Poly1305 -> `(ciphertext, tag)`.
    /// 3. yEnc-encodes `ciphertext` into `body` buffer.
    /// 4. Injects `=yencryption` control line.
    /// 5. FF1-encrypts all control lines over Radix 253, prepending 16-byte salt to line 1.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_article(
        &self,
        name: &str,
        file_size: u64,
        spec: PartSpec,
        data: &[u8],
        line_len: usize,
        file_crc32: Option<u32>,
        identity: SegmentIdentity,
        body: &mut Vec<u8>,
    ) -> Result<EncodedPart> {
        let nonce = self.session.derive_body_nonce(identity.segment_index);
        let (ciphertext, tag) = body::encrypt_body(data, self.session.master_key(), &nonce)?;

        let mut encoded = yenc::encode_part_into(
            name,
            file_size,
            spec,
            &ciphertext,
            line_len,
            file_crc32,
            body,
        );

        // Format and insert the =yencryption control line at the codec seam
        // (`yenc::insert_yencryption_line`): after =ypart (multipart) or
        // after =ybegin (single-part). A multipart body missing =ypart fails
        // with the typed `MISSING_YPART_LINE` error instead of a generic
        // context message.
        let salt = self.session.salt();
        yenc::insert_yencryption_line(
            &mut encoded.body,
            &salt,
            &tag,
            identity.segment_index,
            spec.total > 1,
        )
        // Keep `MissingYPartLineError` as the downcastable error-chain root.
        .map_err(anyhow::Error::new)?;

        // Encrypt control lines using FF1
        let wire_body = control::encrypt_yenc_control_lines(
            &self.session,
            identity.segment_index,
            &encoded.body,
        )?;

        encoded.body = wire_body;
        Ok(encoded)
    }
}

/// Parameters extracted from the `=yencryption` control line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YEncryptionParams {
    pub cipher: String,
    pub salt: [u8; 16],
    pub segment_index: u32,
    pub tag: [u8; 16],
}

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
    ensure!(line.starts_with(b"=yencryption"), "not a =yencryption line");
    let text =
        std::str::from_utf8(line).map_err(|_| anyhow::anyhow!("invalid utf8 in =yencryption"))?;
    // Strict single-SP split: tab or double-space anywhere yields empty
    // tokens / wrong counts and is rejected as INVALID_WHITESPACE below.
    if text.contains('\t') || text.contains("  ") || text.starts_with(' ') || text.ends_with(' ') {
        bail!("INVALID_WHITESPACE: tab or repeated space in =yencryption line");
    }
    let tokens: Vec<&str> = text.split(' ').collect();

    ensure!(
        tokens.first() == Some(&"=yencryption"),
        "line does not begin with =yencryption token"
    );

    // Reject duplicate parameters
    let mut seen_keys = std::collections::HashSet::new();
    for token in tokens.iter().skip(1) {
        if let Some((k, _)) = token.split_once('=') {
            if !seen_keys.insert(k) {
                bail!("INVALID_TOKEN_COUNT: duplicate parameter in =yencryption header");
            }
        }
    }

    if tokens.len() < 2 {
        bail!("MISSING_CIPHER: cipher parameter missing");
    }

    // Token 1 must be cipher=. The canonical validator (v1.2 vectors) raises
    // UNSUPPORTED_CIPHER for a reordered cipher token and INVALID_TOKEN_COUNT
    // for a missing one.
    if !tokens[1].starts_with("cipher=") {
        if tokens.iter().skip(1).any(|t| t.starts_with("cipher=")) {
            bail!("UNSUPPORTED_CIPHER: cipher parameter out of order");
        } else {
            bail!("INVALID_TOKEN_COUNT: missing cipher parameter");
        }
    }
    let cipher_val = &tokens[1]["cipher=".len()..];
    // An empty cipher value is UNSUPPORTED_CIPHER (canonical vector
    // malformed-header-03): there is no cipher to support.
    if cipher_val.is_empty() || cipher_val != "XChaCha20-Poly1305" {
        bail!("UNSUPPORTED_CIPHER: unsupported cipher {cipher_val}");
    }

    if tokens.len() < 5 {
        bail!(
            "INVALID_TOKEN_COUNT: expected 5 tokens, got {}",
            tokens.len()
        );
    }
    if tokens.len() > 5 {
        bail!("INVALID_TOKEN_COUNT: unexpected additional parameters in =yencryption header");
    }

    // Token 2 must be salt=
    if !tokens[2].starts_with("salt=") {
        if tokens.iter().skip(1).any(|t| t.starts_with("salt=")) {
            bail!("REORDERED_HEADER: salt parameter out of order");
        } else {
            bail!("INVALID_TOKEN_COUNT: missing salt parameter");
        }
    }
    let salt_str = &tokens[2]["salt=".len()..];
    if salt_str.len() != 32 {
        bail!(
            "INVALID_SALT_LENGTH: salt must be exactly 32 hex characters, got {}",
            salt_str.len()
        );
    }
    if salt_str.chars().any(|c| matches!(c, 'A'..='F')) {
        bail!("UPPERCASE_HEX: salt contains uppercase hex characters");
    }
    if salt_str
        .chars()
        .any(|c| !c.is_ascii_digit() && !matches!(c, 'a'..='f'))
    {
        bail!("INVALID_SALT_HEX: salt contains non-hex or non-lowercase characters");
    }
    let mut salt = [0u8; 16];
    for i in 0..16 {
        salt[i] = u8::from_str_radix(&salt_str[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("INVALID_SALT_HEX: salt contains non-hex characters"))?;
    }

    // Token 3 must be index=
    if !tokens[3].starts_with("index=") {
        if tokens.iter().skip(1).any(|t| t.starts_with("index=")) {
            bail!("REORDERED_HEADER: index parameter out of order");
        } else {
            bail!("INVALID_TOKEN_COUNT: missing index parameter");
        }
    }
    let index_str = &tokens[3]["index=".len()..];
    if index_str.len() != 8 {
        bail!(
            "INVALID_INDEX_LENGTH: index must be exactly 8 hex characters, got {}",
            index_str.len()
        );
    }
    if index_str.chars().any(|c| matches!(c, 'A'..='F')) {
        bail!("UPPERCASE_HEX: index contains uppercase hex characters");
    }
    if index_str
        .chars()
        .any(|c| !c.is_ascii_digit() && !matches!(c, 'a'..='f'))
    {
        bail!("INVALID_INDEX_HEX: index contains non-hex characters");
    }
    let segment_index = u32::from_str_radix(index_str, 16)
        .map_err(|_| anyhow::anyhow!("INVALID_INDEX_HEX: failed to parse index hex"))?;
    if segment_index == 0 {
        bail!("ZERO_SEGMENT_INDEX: segment index cannot be zero");
    }
    // CR-02 (Control Std §4/§8; Body Std §4): an index whose big-endian
    // encoding contains 0x0A (LF) or 0x0D (CR) would have split a control
    // line on the wire — reject it here too so the gap cannot resurface if
    // body-only mode is ever added (combined mode already rejects it at the
    // Line-1 bootstrap, `extract_bootstrap_from_line1`).
    if segment_index
        .to_be_bytes()
        .iter()
        .any(|&b| b == 0x0A || b == 0x0D)
    {
        return Err(attach_crypto_error_kind(
            anyhow::anyhow!(
                "FORBIDDEN_SEGMENT_INDEX_BYTE: segment index bytes contain 0x0A or 0x0D"
            ),
            CryptoErrorKind::ProviderFailover,
        ));
    }

    // Token 4 must be tag=
    if !tokens[4].starts_with("tag=") {
        if tokens.iter().skip(1).any(|t| t.starts_with("tag=")) {
            bail!("REORDERED_HEADER: tag parameter out of order");
        } else {
            bail!("INVALID_TOKEN_COUNT: missing tag parameter");
        }
    }
    let tag_str = &tokens[4]["tag=".len()..];
    if tag_str.len() != 32 {
        bail!(
            "INVALID_TAG_LENGTH: tag must be exactly 32 hex characters, got {}",
            tag_str.len()
        );
    }
    if tag_str.chars().any(|c| matches!(c, 'A'..='F')) {
        bail!("UPPERCASE_HEX: tag contains uppercase hex characters");
    }
    if tag_str
        .chars()
        .any(|c| !c.is_ascii_digit() && !matches!(c, 'a'..='f'))
    {
        bail!("INVALID_TAG_HEX: tag contains non-hex or non-lowercase characters");
    }
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = u8::from_str_radix(&tag_str[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("INVALID_TAG_HEX: tag contains non-hex characters"))?;
    }

    // 128-byte total length assertion: the canonical five-token grammar is
    // exactly 128 bytes, so any accepted line with a different total length
    // would imply non-canonical content smuggled past the field checks.
    ensure!(
        line.len() == 128,
        "INVALID_LINE_LENGTH: =yencryption line must be exactly 128 bytes, got {}",
        line.len()
    );

    Ok(YEncryptionParams {
        cipher: "XChaCha20-Poly1305".to_string(),
        salt,
        segment_index,
        tag,
    })
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
        let is_multipart = lines[0]
            .content
            .windows(5)
            .position(|w| w == b"name=")
            .map(|name_idx| {
                let kv_prefix = &lines[0].content[..name_idx];
                kv_prefix
                    .split(|&b| b == b' ' || b == b'\t')
                    .any(|tok| tok.starts_with(b"part="))
            })
            .unwrap_or(false);
        ensure!(
            !is_multipart,
            "misplaced =yencryption: multipart =ybegin requires =ypart before =yencryption"
        );
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

const MAX_CACHED_SESSIONS: usize = 16;

type SessionCache = (
    HashMap<[u8; 16], Arc<EncryptionSession>>,
    VecDeque<[u8; 16]>,
);

/// Thin adapter presenting standard yEnc decode contract for downloaded articles.
pub struct DownloadDecryptionAdapter {
    password: Option<String>,
    cached_sessions: std::sync::Mutex<SessionCache>,
}

impl DownloadDecryptionAdapter {
    pub fn new(session: Option<Arc<EncryptionSession>>) -> Self {
        let mut map = HashMap::new();
        let mut order = VecDeque::new();
        if let Some(s) = session {
            order.push_back(s.salt());
            map.insert(s.salt(), s);
        }
        Self {
            password: None,
            cached_sessions: std::sync::Mutex::new((map, order)),
        }
    }

    pub fn with_password(password: &str) -> Self {
        Self {
            password: Some(password.to_string()),
            cached_sessions: std::sync::Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }

    /// Decode an article wire body, restoring encrypted control lines and decrypting body ciphertext.
    ///
    /// If the adapter holds decryption credentials (`password` or a cached session) the caller
    /// has configured transport decryption for this download: any unencrypted article starting
    /// with `=ybegin` is rejected as `UNAUTHENTICATED_ARTICLE` (fail closed), because accepting
    /// it would release unauthenticated plaintext and violate the Zero-Output Guarantee.
    /// Unencrypted passthrough is only allowed for an adapter with no credentials at all.
    /// If encrypted, requires `segment_index` and valid session/password.
    /// Strictly guarantees Zero-Output on authentication failure.
    pub fn decode_article(&self, body: &[u8], segment_index: Option<u32>) -> Result<DecodedPart> {
        let caller_segment_index = segment_index;
        if body.starts_with(b"=ybegin") {
            if caller_segment_index.is_some() || self.has_decryption_credentials() {
                bail!(
                    "UNAUTHENTICATED_ARTICLE: unencrypted article received for encrypted segment"
                );
            }
            return yenc::decode_part(body);
        }
        // IN-03: a uu-encoded article (starts with "begin <mode> <name>") is
        // not an encrypted segment — name the actual condition instead of the
        // misleading LINE_TRUNCATED-style bootstrap error.
        if body.starts_with(b"begin ") && self.has_decryption_credentials() {
            bail!(
                "UU_ENCODED_ARTICLE: unencrypted uu-encoded article received where an encrypted segment was expected"
            );
        }

        let first_line_end =
            if !body.starts_with(b"=y") && body.len() >= control::BOOTSTRAP_PREFIX_LEN {
                body[control::BOOTSTRAP_PREFIX_LEN..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|p| p + control::BOOTSTRAP_PREFIX_LEN)
                    .context("article has no newline terminators")?
            } else {
                body.iter()
                    .position(|&b| b == b'\n')
                    .context("article has no newline terminators")?
            };
        let first_line = &body[..first_line_end]
            .strip_suffix(b"\r")
            .unwrap_or(&body[..first_line_end]);

        let (salt, line1_segment_index) = control::extract_bootstrap_from_line1(first_line)?;
        let segment_index = match caller_segment_index {
            Some(caller_idx) => {
                ensure!(
                    caller_idx == line1_segment_index,
                    "CALLER_INDEX_MISMATCH: caller index {} does not match line 1 bootstrap index {}",
                    caller_idx,
                    line1_segment_index
                );
                caller_idx
            }
            None => line1_segment_index,
        };
        let session = self.get_or_create_session(salt)?;

        // Decrypt control lines
        let restored_yenc = control::decrypt_yenc_control_lines(&session, segment_index, body)?;

        // Extract and remove =yencryption line
        let (yenc_params, clean_yenc) = extract_and_remove_yencryption(&restored_yenc)?;

        // Dual-Bootstrap Agreement
        if yenc_params.salt != session.salt() {
            bail!(attach_crypto_error_kind(
                anyhow::anyhow!(
                    "DUAL_SALT_MISMATCH: salt mismatch between control line 1 and =yencryption header"
                ),
                CryptoErrorKind::ProviderFailover,
            ));
        }
        if yenc_params.segment_index != segment_index {
            bail!(attach_crypto_error_kind(
                anyhow::anyhow!(
                    "DUAL_INDEX_MISMATCH: segmentIndex mismatch between control line 1 ({}) and =yencryption header ({})",
                    segment_index,
                    yenc_params.segment_index
                ),
                CryptoErrorKind::ProviderFailover,
            ));
        }

        // Decode yEnc ciphertext
        let mut decoded = yenc::decode_part(&clean_yenc)?;

        // Ciphertext CRC check before AEAD decryption
        if !decoded.crc_matches() {
            bail!(attach_crypto_error_kind(
                anyhow::anyhow!("ciphertext CRC mismatch"),
                CryptoErrorKind::ProviderFailover,
            ));
        }

        // Authenticate and decrypt body ciphertext with Zero-Output Guarantee.
        // Typed at origin: Poly1305 failure is provider corruption (retriable).
        let nonce = session.derive_body_nonce(segment_index);
        let plaintext = body::decrypt_body(
            &decoded.data,
            &yenc_params.tag,
            session.master_key(),
            &nonce,
        )
        .map_err(|e| {
            attach_crypto_error_kind(
                anyhow::anyhow!("AUTHENTICATION_FAILURE: {e}"),
                CryptoErrorKind::ProviderFailover,
            )
        })?;

        // Zero-output guarantee: replace data with authenticated plaintext.
        // CRC normalization — recompute over the authenticated plaintext (Body
        // Standard §10 permits clear OR recompute; recompute preserves the
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

    /// Directly authenticate and decrypt ciphertext with given salt and segment index.
    ///
    /// Strictly guarantees Zero-Output on authentication failure.
    pub fn decrypt_raw(
        &self,
        salt: [u8; 16],
        segment_index: u32,
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>> {
        let session = self.get_or_create_session(salt)?;
        let nonce = session.derive_body_nonce(segment_index);
        body::decrypt_body(ciphertext, tag, session.master_key(), &nonce).map_err(|e| {
            attach_crypto_error_kind(
                anyhow::anyhow!("AUTHENTICATION_FAILURE: {e}"),
                CryptoErrorKind::ProviderFailover,
            )
        })
    }

    /// Whether this adapter holds any decryption credentials (an explicit password
    /// or at least one cached encryption session). When true, `decode_article` fails
    /// closed on unencrypted (`=ybegin`-prefixed) articles: the caller configured
    /// transport decryption, so plaintext passthrough is an authentication bypass
    /// (Zero-Output Guarantee — see `crypto/mod.rs` threat model).
    fn has_decryption_credentials(&self) -> bool {
        if self.password.is_some() {
            return true;
        }
        self.cached_sessions
            .lock()
            .map(|guard| !guard.0.is_empty())
            .unwrap_or(true)
    }

    fn get_or_create_session(&self, salt: [u8; 16]) -> Result<Arc<EncryptionSession>> {
        // IN-02-R4: same poisoned-tolerant policy as `has_decryption_credentials`
        // above — a poisoned mutex in the download hot path fails closed as a
        // mapped crypto error instead of panicking.
        let mut guard = self.cached_sessions.lock().map_err(|_| {
            attach_crypto_error_kind(
                anyhow::anyhow!("session cache lock poisoned"),
                CryptoErrorKind::MetadataValidation,
            )
        })?;
        if let Some(session) = guard.0.get(&salt) {
            return Ok(session.clone());
        }

        if let Some(ref pwd) = self.password {
            let session = Arc::new(EncryptionSession::new(pwd, salt)?);
            if guard.0.len() == MAX_CACHED_SESSIONS {
                if let Some(oldest) = guard.1.pop_front() {
                    guard.0.remove(&oldest);
                }
            }
            guard.0.insert(salt, session.clone());
            guard.1.push_back(salt);
            return Ok(session);
        }

        Err(attach_crypto_error_kind(
            anyhow::anyhow!("no password or encryption session available to decrypt article"),
            CryptoErrorKind::MetadataValidation,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_salt_session_caching() {
        let password = "multi-salt-cache-password";
        let adapter = DownloadDecryptionAdapter::with_password(password);

        let salt1 = [0x11u8; 16];
        let salt2 = [0x22u8; 16];

        let s1 = adapter.get_or_create_session(salt1).unwrap();
        let s2 = adapter.get_or_create_session(salt2).unwrap();
        assert_eq!(s1.salt(), salt1);
        assert_eq!(s2.salt(), salt2);
        assert!(!Arc::ptr_eq(&s1, &s2));

        // Re-request salt1: must return cached instance (same Arc pointer)
        let s1_again = adapter.get_or_create_session(salt1).unwrap();
        assert!(Arc::ptr_eq(&s1, &s1_again));

        // Re-request salt2: must return cached instance (same Arc pointer)
        let s2_again = adapter.get_or_create_session(salt2).unwrap();
        assert!(Arc::ptr_eq(&s2, &s2_again));
    }

    #[test]
    fn decryption_session_cache_evicts_oldest_entry_at_capacity() {
        let adapter = DownloadDecryptionAdapter::with_password("bounded-session-cache");
        let mut first = None;
        for value in 1u8..=17 {
            let session = adapter.get_or_create_session([value; 16]).unwrap();
            if value == 1 {
                first = Some(session);
            }
        }

        let guard = adapter.cached_sessions.lock().unwrap();
        assert_eq!(guard.0.len(), 16);
        assert!(!guard.0.contains_key(&[1; 16]));
        assert!(guard.0.contains_key(&[17; 16]));
        drop(guard);

        let first_again = adapter.get_or_create_session([1; 16]).unwrap();
        assert!(!Arc::ptr_eq(&first.unwrap(), &first_again));
    }

    #[test]
    fn encrypted_control_lines_round_trip_with_lf_endings() {
        let password = "lf-only-control-lines";
        let salt = control::generate_alphabet_salt();
        let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
        let upload_adapter = UploadEncryptionAdapter::new(session);
        let payload = b"LF-only encrypted control framing";
        let identity = SegmentIdentity::checked(0, 1, 1, 1).unwrap();
        let mut body = Vec::new();
        let encoded = upload_adapter
            .encode_article(
                "lf.bin",
                payload.len() as u64,
                PartSpec {
                    number: 1,
                    total: 1,
                    offset: 0,
                },
                payload,
                128,
                None,
                identity,
                &mut body,
            )
            .unwrap();
        let mut lf_wire = encoded.body;
        let mut index = 0;
        while index + 1 < lf_wire.len() {
            if lf_wire[index..].starts_with(b"\r\n") {
                lf_wire.remove(index);
            }
            index += 1;
        }

        let decoded = DownloadDecryptionAdapter::with_password(password)
            .decode_article(&lf_wire, Some(identity.segment_index))
            .unwrap();
        assert_eq!(decoded.data, payload);
    }

    #[test]
    fn zero_length_encrypted_body_round_trips() {
        let password = "zero-length-body";
        let salt = control::generate_alphabet_salt();
        let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
        let upload_adapter = UploadEncryptionAdapter::new(session);
        let identity = SegmentIdentity::checked(0, 1, 1, 1).unwrap();
        let mut body = Vec::new();
        let encoded = upload_adapter
            .encode_article(
                "empty.bin",
                0,
                PartSpec {
                    number: 1,
                    total: 1,
                    offset: 0,
                },
                b"",
                128,
                None,
                identity,
                &mut body,
            )
            .unwrap();

        let decoded = DownloadDecryptionAdapter::with_password(password)
            .decode_article(&encoded.body, Some(identity.segment_index))
            .unwrap();
        assert!(decoded.data.is_empty());
        assert_eq!(decoded.file_size, 0);
    }

    #[test]
    fn test_single_part_filename_containing_part_equals() {
        let password = "test-part-equals-password";
        let salt = control::generate_alphabet_salt();
        let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
        let upload_adapter = UploadEncryptionAdapter::new(session);

        let payload = b"Content for file named ep_part=pilot.mkv";
        let spec = PartSpec {
            number: 1,
            total: 1,
            offset: 0,
        };
        let identity = SegmentIdentity::checked(0, 1, 1, 1).unwrap();
        let mut body = Vec::new();
        let encoded = upload_adapter
            .encode_article(
                "ep_part=pilot.mkv",
                payload.len() as u64,
                spec,
                payload,
                128,
                None,
                identity,
                &mut body,
            )
            .expect("encode single-part file with part= in filename");

        let download_adapter = DownloadDecryptionAdapter::with_password(password);
        let decoded = download_adapter
            .decode_article(&encoded.body, Some(identity.segment_index))
            .expect("decode single-part file with part= in filename must succeed");

        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.name, "ep_part=pilot.mkv");
    }

    #[test]
    fn test_multipart_filename_containing_ypart() {
        let password = "test-multipart-ypart-password";
        let salt = control::generate_alphabet_salt();
        let session = Arc::new(EncryptionSession::new(password, salt).unwrap());
        let upload_adapter = UploadEncryptionAdapter::new(session);

        let payload = vec![0x33u8; 1024];
        let spec = PartSpec {
            number: 1,
            total: 2,
            offset: 0,
        };
        let identity = SegmentIdentity::checked(0, 1, 2, 1).unwrap();
        let mut body = Vec::new();
        let encoded = upload_adapter
            .encode_article(
                "movie=ypart1.mkv",
                2048,
                spec,
                &payload,
                128,
                None,
                identity,
                &mut body,
            )
            .expect("encode multipart file with =ypart in filename");

        let download_adapter = DownloadDecryptionAdapter::with_password(password);
        let decoded = download_adapter
            .decode_article(&encoded.body, Some(identity.segment_index))
            .expect("decode multipart file with =ypart in filename must succeed");

        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.name, "movie=ypart1.mkv");
        assert_eq!(decoded.part, 1);
        assert_eq!(decoded.total, 2);
    }
}
