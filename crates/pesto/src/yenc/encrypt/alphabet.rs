//! Canonical 253-byte Alphabet for yEnc control-line encryption.
//!
//! Defined by the yEnc Control Lines Encryption Standard v1.2 §2: every byte
//! in 0x01..=0xFF except 0x0A (LF) and 0x0D (CR). The numeral bijection is
//! strictly by ascending byte value — the byte↔numeral mapping below is
//! normative wire behavior (VEC-04 locks it via `salt_ascii` /
//! `expected_wire_hex`).

/// Number of symbols in the Alphabet.
pub const RADIX: u32 = 253;

/// Map an Alphabet byte to its FF1 numeral (0..=252). Returns `None` when
/// `byte` is outside the Alphabet (0x00, 0x0A, or 0x0D).
///
/// Bijection (standard §2):
/// - bytes 0x01..=0x09 map to numerals 0..=8 (`I = b - 1`)
/// - byte 0x0B maps to numeral 9; byte 0x0C maps to numeral 10
/// - bytes 0x0E..=0xFF map to numerals 11..=252 (`I = b - 3`)
pub fn byte_to_numeral(byte: u8) -> Option<u16> {
    match byte {
        0x01..=0x09 => Some(u16::from(byte) - 1),
        0x0B => Some(9),
        0x0C => Some(10),
        0x0E..=0xFF => Some(u16::from(byte) - 3),
        _ => None,
    }
}

/// Map an FF1 numeral (0..=252) back to its Alphabet byte. Returns `None`
/// for numerals outside 0..=252.
pub fn numeral_to_byte(numeral: u16) -> Option<u8> {
    match numeral {
        0..=8 => Some(numeral as u8 + 1),
        9 => Some(0x0B),
        10 => Some(0x0C),
        11..=252 => Some(numeral as u8 + 3),
        _ => None,
    }
}

/// Returns `true` when `byte` lies in the Alphabet (never 0x00, 0x0A, 0x0D).
pub fn is_alphabet_byte(byte: u8) -> bool {
    byte != 0x00 && byte != 0x0A && byte != 0x0D
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bijection_round_trips_every_alphabet_byte() {
        for byte in 0x01u8..=0xFF {
            if byte == 0x0A || byte == 0x0D {
                assert_eq!(byte_to_numeral(byte), None);
                assert!(!is_alphabet_byte(byte));
                continue;
            }
            let numeral = byte_to_numeral(byte).expect("alphabet byte");
            assert_eq!(numeral_to_byte(numeral), Some(byte));
            assert!(is_alphabet_byte(byte));
        }
        assert_eq!(byte_to_numeral(0x00), None);
        assert!(!is_alphabet_byte(0x00));
    }

    #[test]
    fn numeral_domain_is_contiguous() {
        // Every numeral in 0..=252 is hit exactly once by the Alphabet.
        let mut seen = vec![false; 253];
        for byte in 0x01u8..=0xFF {
            if let Some(n) = byte_to_numeral(byte) {
                seen[usize::from(n)] = true;
            }
        }
        assert!(seen.iter().all(|s| *s), "bijection must be total");
    }
}
