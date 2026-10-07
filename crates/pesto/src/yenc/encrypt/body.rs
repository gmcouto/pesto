//! XChaCha20-Poly1305 body encryption and `=yencryption` wire line.
//!
//! Body standard v1.2 §4: XChaCha20-Poly1305 encrypt over the raw segment
//! bytes (before yEnc encoding) with the derived session key and per-segment
//! nonce; §3: the tag and salt travel in the `=yencryption` header line with
//! a strict five-token grammar — exactly one SP between tokens, lowercase
//! hex only, salt 32 hex chars, index 8 hex chars (non-zero, no 0x0A/0x0D
//! bytes), tag 32 hex chars, cipher token exactly `XChaCha20-Poly1305`,
//! total content length exactly 128 bytes.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use super::error::EncryptionError;
use super::header::{ENCRIPTION_LINE_LEN, SALT_HEX_LEN, TAG_HEX_LEN};
use super::header::{INDEX_HEX_LEN, SEGMENT_INDEX_MAX, SEGMENT_INDEX_MIN};
use super::index::index_is_forbidden;
use super::keys::{body_nonce, SessionKey, SALT_LEN};

/// Authenticate and encrypt the raw segment plaintext.
///
/// Returns the ciphertext (same length as the plaintext) and the 16-byte
/// Poly1305 tag. AAD is empty; the segment identity is bound through the
/// nonce derivation instead (body standard §4 step c/d).
pub fn encrypt_body(
    key: &SessionKey,
    segment_index: u32,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), EncryptionError> {
    validate_segment_index(segment_index)?;
    let nonce = body_nonce(key, segment_index);
    let cipher = XChaCha20Poly1305::new(key.into());
    let payload = Payload {
        msg: plaintext,
        aad: &[],
    };
    let mut ciphertext = cipher
        .encrypt((&nonce).into(), payload)
        .map_err(|e| EncryptionError::Crypto(format!("body encryption failed: {e}")))?;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext.split_off(ciphertext.len() - 16));
    Ok((ciphertext, tag))
}

/// Verify the Poly1305 tag and decrypt the ciphertext back to plaintext.
///
/// On authentication failure the returned error carries no plaintext bytes
/// and the caller must release no output (body standard §5 zero-output rule).
pub fn decrypt_body(
    key: &SessionKey,
    segment_index: u32,
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, EncryptionError> {
    validate_segment_index(segment_index)?;
    let nonce = body_nonce(key, segment_index);
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut sealed = Vec::with_capacity(ciphertext.len() + 16);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);
    let payload = Payload {
        msg: sealed.as_slice(),
        aad: &[],
    };
    cipher
        .decrypt((&nonce).into(), payload)
        .map_err(|_| EncryptionError::Authentication)
}

fn validate_segment_index(segment_index: u32) -> Result<(), EncryptionError> {
    if !(SEGMENT_INDEX_MIN..=SEGMENT_INDEX_MAX).contains(&segment_index) {
        return Err(EncryptionError::ZeroSegmentIndex);
    }
    if index_is_forbidden(segment_index) {
        return Err(EncryptionError::ForbiddenSegmentIndexByte);
    }
    Ok(())
}

/// Build the canonical `=yencryption` line content (128 ASCII bytes, no line
/// terminator). Note: the salt parameter accepts the full body-only byte
/// domain here — combined-mode producers constrain the shared salt to the
/// 253-byte Alphabet at generation time (see [`session::sample_alphabet_salt`]),
/// while body-only vectors legitimately carry 0x0A/0x0D salt bytes.
pub fn build_yencryption_line(
    salt: &[u8; SALT_LEN],
    segment_index: u32,
    tag: &[u8; 16],
) -> Result<String, EncryptionError> {
    let mut line = String::with_capacity(ENCRIPTION_LINE_LEN);
    line.push_str("=yencryption cipher=XChaCha20-Poly1305 salt=");
    push_hex_lower(&mut line, salt);
    line.push_str(" index=");
    let index_hex = format!("{segment_index:08x}");
    line.push_str(&index_hex);
    line.push_str(" tag=");
    push_hex_lower(&mut line, tag);
    debug_assert_eq!(line.len(), ENCRIPTION_LINE_LEN);
    Ok(line)
}

fn push_hex_lower(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        out.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("nibble"));
    }
}

/// Decode ASCII lowercase hex into bytes; `None` on any non-hex or
/// odd-length input. Uppercase digits are rejected by the caller's grammar
/// check before this point.
pub(crate) fn hex_to_bytes_exact(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Parsed `=yencryption` header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionHeader {
    pub salt: [u8; SALT_LEN],
    pub segment_index: u32,
    pub tag: [u8; 16],
}

/// Strict five-token grammar parse of an `=yencryption` line content
/// (body standard §3). Every deviation is a parse error — never a silent
/// fallback to ordinary yEnc. Check order mirrors the malformed-input
/// taxonomy (VEC-05): whitespace, token count, cipher token, then
/// salt/index/tag length → case → hex → value validation.
pub fn parse_yencryption_line(line: &str) -> Result<EncryptionHeader, EncryptionError> {
    if line.contains(['\t', '\n', '\r'])
        || line.contains("  ")
        || line.starts_with(' ')
        || line.ends_with(' ')
    {
        return Err(EncryptionError::InvalidWhitespace);
    }
    let tokens: Vec<&str> = line.split(' ').collect();
    if tokens.len() != 5 {
        return Err(EncryptionError::InvalidTokenCount);
    }
    if tokens[0] != "=yencryption"
        || !tokens[1].starts_with("cipher=")
        || !tokens[2].starts_with("salt=")
        || !tokens[3].starts_with("index=")
        || !tokens[4].starts_with("tag=")
    {
        // Reordered, duplicate-keyed, or unrecognizable token layout.
        return Err(EncryptionError::UnsupportedCipher);
    }
    if tokens[1] != "cipher=XChaCha20-Poly1305" {
        return Err(EncryptionError::UnsupportedCipher);
    }
    let salt_hex = &tokens[2]["salt=".len()..];
    if salt_hex.len() != SALT_HEX_LEN {
        return Err(EncryptionError::InvalidSaltLength);
    }
    if salt_hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(EncryptionError::UppercaseHex);
    }
    let salt_vec = hex_to_bytes_exact(salt_hex).ok_or(EncryptionError::InvalidSaltHex)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_vec);

    let index_hex = &tokens[3]["index=".len()..];
    if index_hex.len() != INDEX_HEX_LEN {
        return Err(EncryptionError::InvalidIndexLength);
    }
    if index_hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(EncryptionError::UppercaseHex);
    }
    let index = u32::from_str_radix(index_hex, 16).map_err(|_| EncryptionError::InvalidIndexHex)?;
    if index == 0 {
        return Err(EncryptionError::ZeroSegmentIndex);
    }
    if index_is_forbidden(index) {
        return Err(EncryptionError::ForbiddenSegmentIndexByte);
    }

    let tag_hex = &tokens[4]["tag=".len()..];
    if tag_hex.len() != TAG_HEX_LEN {
        return Err(EncryptionError::InvalidTagLength);
    }
    if tag_hex.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(EncryptionError::UppercaseHex);
    }
    let tag_vec = hex_to_bytes_exact(tag_hex).ok_or(EncryptionError::InvalidTagHex)?;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_vec);

    // Body standard §5 step 2: content is exactly 128 bytes. All preceding
    // field checks already pin each fixed-width token, so reaching this with
    // the wrong total means an unclassifiable extension defect.
    if line.len() != ENCRIPTION_LINE_LEN {
        return Err(EncryptionError::LineTruncated);
    }
    Ok(EncryptionHeader {
        salt,
        segment_index: index,
        tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_header() {
        let salt = [0x4bu8; SALT_LEN];
        let tag = [0xabu8; 16];
        let line = build_yencryption_line(&salt, 1, &tag).unwrap();
        assert_eq!(line.len(), ENCRIPTION_LINE_LEN);
        let parsed = parse_yencryption_line(&line).unwrap();
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.segment_index, 1);
        assert_eq!(parsed.tag, tag);
    }

    #[test]
    fn rejects_uppercase_and_wrong_length() {
        let salt = [0x4bu8; SALT_LEN];
        let tag = [0xabu8; 16];
        let line = build_yencryption_line(&salt, 1, &tag).unwrap();
        let upper = line.replacen("cipher", "CIPHER", 1);
        assert!(matches!(
            parse_yencryption_line(&upper),
            Err(EncryptionError::UnsupportedCipher)
        ));
        let long = format!("{line} ");
        assert!(parse_yencryption_line(&long).is_err());
    }
}
