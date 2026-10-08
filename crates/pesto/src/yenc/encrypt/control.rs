//! FF1 control-line encryption/decryption over the 253-byte Alphabet and the
//! Line-1 article bootstrap.
//!
//! Control standard v1.2 §4 (encrypt): derive encKey and per-line tweak,
//! FF1-encrypt each control line individually over Alphabet numerals, and
//! prepend the 20-byte bootstrap (16 raw Alphabet salt bytes ||
//! uint32_be(segmentIndex)) to Line 1 only. §5 (decrypt): extract and
//! validate the bootstrap, FF1-decrypt Line 1 and verify it starts with
//! `=ybegin`, then process subsequent lines per the caller's header/footer
//! loop.

use aes::Aes256;
use fpe::ff1::{FlexibleNumeralString, FF1};

use super::alphabet::{byte_to_numeral, is_alphabet_byte, numeral_to_byte, RADIX};
use super::error::EncryptionError;
use super::header::{BOOTSTRAP_LEN, LINE1_MIN_LEN, SEGMENT_INDEX_MIN};
use super::index::index_is_forbidden;
use super::keys::{control_enc_key, control_tweak, SessionKey, SALT_LEN};

fn numerals_to_bytes(numerals: &[u16]) -> Result<Vec<u8>, EncryptionError> {
    numerals
        .iter()
        .map(|n| numeral_to_byte(*n).ok_or(EncryptionError::ControlLineDecryptFailure))
        .collect()
}

fn bytes_to_numerals(bytes: &[u8]) -> Result<Vec<u16>, EncryptionError> {
    bytes
        .iter()
        .map(|b| byte_to_numeral(*b).ok_or(EncryptionError::InvalidSaltCharacter))
        .collect()
}

/// FF1-encrypt one control line's content over the Alphabet.
pub fn ff1_encrypt_line(
    enc_key: &SessionKey,
    tweak: &[u8; 8],
    line_content: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    if line_content.len() < 2 {
        return Err(EncryptionError::LineTooShort);
    }
    if line_content.iter().any(|b| !is_alphabet_byte(*b)) {
        return Err(EncryptionError::InvalidSaltCharacter);
    }
    let ff1 =
        FF1::<Aes256>::new(enc_key, RADIX).map_err(|e| EncryptionError::Crypto(e.to_string()))?;
    let numerals = bytes_to_numerals(line_content)?;
    let pt = FlexibleNumeralString::from(numerals);
    let ct = ff1
        .encrypt(tweak.as_ref(), &pt)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
    let out: Vec<u16> = ct.into();
    numerals_to_bytes(&out)
}

/// FF1-decrypt one control line's content over the Alphabet. Failure is
/// `ControlLineDecryptFailure` (retriable provider corruption).
pub fn ff1_decrypt_line(
    enc_key: &SessionKey,
    tweak: &[u8; 8],
    line_content: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    if line_content.len() < 2 {
        return Err(EncryptionError::LineTooShort);
    }
    if line_content.iter().any(|b| !is_alphabet_byte(*b)) {
        return Err(EncryptionError::InvalidSaltCharacter);
    }
    let ff1 =
        FF1::<Aes256>::new(enc_key, RADIX).map_err(|e| EncryptionError::Crypto(e.to_string()))?;
    let numerals = bytes_to_numerals(line_content)?;
    let ct = FlexibleNumeralString::from(numerals);
    let pt = ff1
        .decrypt(tweak.as_ref(), &ct)
        .map_err(|_| EncryptionError::ControlLineDecryptFailure)?;
    let out: Vec<u16> = pt.into();
    numerals_to_bytes(&out)
}

/// Bootstrap carried by Line 1: raw Alphabet salt plus the segment index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    pub salt: [u8; SALT_LEN],
    pub segment_index: u32,
}

/// Build the 20-byte Line-1 prefix (control standard §4 step f).
pub fn build_bootstrap(bootstrap: &Bootstrap) -> [u8; BOOTSTRAP_LEN] {
    let mut out = [0u8; BOOTSTRAP_LEN];
    out[..SALT_LEN].copy_from_slice(&bootstrap.salt);
    out[SALT_LEN..].copy_from_slice(&bootstrap.segment_index.to_be_bytes());
    out
}

/// Extract and validate the Line-1 bootstrap from the (dot-unstuffed) Line-1
/// content (control standard §5 step 3). Order mirrors the VEC-05
/// control_syntax taxonomy: length, salt bytes, index zero, index bytes.
pub fn extract_bootstrap(line1_content: &[u8]) -> Result<Bootstrap, EncryptionError> {
    if line1_content.len() < LINE1_MIN_LEN {
        return Err(EncryptionError::LineTruncated);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&line1_content[..SALT_LEN]);
    if salt.iter().any(|b| !is_alphabet_byte(*b)) {
        return Err(EncryptionError::InvalidSaltCharacter);
    }
    let segment_index = u32::from_be_bytes([
        line1_content[16],
        line1_content[17],
        line1_content[18],
        line1_content[19],
    ]);
    if segment_index == 0 {
        return Err(EncryptionError::ZeroSegmentIndex);
    }
    if index_is_forbidden(segment_index) {
        return Err(EncryptionError::ForbiddenSegmentIndexByte);
    }
    Ok(Bootstrap {
        salt,
        segment_index,
    })
}

/// Encrypt Line 1: FF1-encrypt its content and prepend the 20-byte bootstrap.
pub fn encrypt_line1(
    master_key: &SessionKey,
    segment_index: u32,
    salt: &[u8; SALT_LEN],
    line1_content: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    if segment_index < SEGMENT_INDEX_MIN {
        return Err(EncryptionError::ZeroSegmentIndex);
    }
    if index_is_forbidden(segment_index) {
        return Err(EncryptionError::ForbiddenSegmentIndexByte);
    }
    let enc_key = control_enc_key(master_key);
    let tweak = control_tweak(master_key, segment_index, 1);
    let mut out = Vec::with_capacity(line1_content.len() + BOOTSTRAP_LEN);
    out.extend_from_slice(&build_bootstrap(&Bootstrap {
        salt: *salt,
        segment_index,
    }));
    out.extend_from_slice(&ff1_encrypt_line(&enc_key, &tweak, line1_content)?);
    Ok(out)
}

/// Decrypt Line 1: extract/validate the bootstrap, FF1-decrypt the remainder,
/// and verify the plaintext starts with `=ybegin` (control standard §5 step
/// 3g). Returns the restored content and the extracted bootstrap.
pub fn decrypt_line1(
    master_key: &SessionKey,
    line1_content: &[u8],
) -> Result<(Vec<u8>, Bootstrap), EncryptionError> {
    let bootstrap = extract_bootstrap(line1_content)?;
    let enc_key = control_enc_key(master_key);
    let tweak = control_tweak(master_key, bootstrap.segment_index, 1);
    let restored = ff1_decrypt_line(&enc_key, &tweak, &line1_content[BOOTSTRAP_LEN..])?;
    if !restored.starts_with(b"=ybegin") {
        return Err(EncryptionError::ControlLineDecryptFailure);
    }
    Ok((restored, bootstrap))
}

/// Encrypt a non-Line-1 control line (header or footer) with its physical
/// lineIndex.
pub fn encrypt_control_line(
    master_key: &SessionKey,
    segment_index: u32,
    line_index: u32,
    line_content: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let enc_key = control_enc_key(master_key);
    let tweak = control_tweak(master_key, segment_index, line_index);
    ff1_encrypt_line(&enc_key, &tweak, line_content)
}

/// Decrypt a non-Line-1 control line (header or footer) with its physical
/// lineIndex. The caller verifies the restored content starts with `=y` /
/// `=yend` as appropriate (control standard §5 steps 4/6).
pub fn decrypt_control_line(
    master_key: &SessionKey,
    segment_index: u32,
    line_index: u32,
    line_content: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let enc_key = control_enc_key(master_key);
    let tweak = control_tweak(master_key, segment_index, line_index);
    ff1_decrypt_line(&enc_key, &tweak, line_content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_round_trip_and_layout() {
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(b"K7mX9pL2qR8vN4wZ");
        let bs = Bootstrap {
            salt,
            segment_index: 1,
        };
        let raw = build_bootstrap(&bs);
        assert_eq!(raw.len(), BOOTSTRAP_LEN);
        assert_eq!(&raw[..16], b"K7mX9pL2qR8vN4wZ");
        assert_eq!(&raw[16..], &[0, 0, 0, 1]);
        // A bare 20-byte bootstrap is below the 22-byte Line-1 minimum and
        // must be rejected (control standard §5 step 3b).
        assert!(matches!(
            extract_bootstrap(&raw),
            Err(EncryptionError::LineTruncated)
        ));
    }

    #[test]
    fn line1_encrypt_round_trips() {
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(b"K7mX9pL2qR8vN4wZ");
        let master_key = [7u8; 32];
        let line = b"=ybegin line=128 size=18 name=file.bin";
        let wire = encrypt_line1(&master_key, 1, &salt, line).unwrap();
        // bootstrap + same-length FF1 ciphertext
        assert_eq!(wire.len(), line.len() + 20);
        let (restored, bs) = decrypt_line1(&master_key, &wire).unwrap();
        assert_eq!(restored, line.to_vec());
        assert_eq!(bs.segment_index, 1);
        assert_eq!(bs.salt, salt);
    }

    #[test]
    fn wrong_password_fails_line1() {
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(b"K7mX9pL2qR8vN4wZ");
        let line = b"=ybegin line=128 size=18 name=file.bin";
        let wire = encrypt_line1(&[7u8; 32], 1, &salt, line).unwrap();
        let err = decrypt_line1(&[8u8; 32], &wire).unwrap_err();
        assert!(matches!(
            err,
            EncryptionError::ControlLineDecryptFailure | EncryptionError::InvalidSaltCharacter
        ));
    }
}
