//! Fixed wire constants for the `=yencryption` header line (body standard
//! v1.2 §3) and the Line-1 article bootstrap (control standard v1.2 §2/§5).

/// Length of the `=yencryption` line content in ASCII bytes (no terminator).
pub const ENCRIPTION_LINE_LEN: usize = 128;

/// Hex length of the 16-byte salt parameter.
pub const SALT_HEX_LEN: usize = 32;

/// Hex length of the 8-hex-digit index parameter (uint32_be).
pub const INDEX_HEX_LEN: usize = 8;

/// Hex length of the 16-byte Poly1305 tag parameter.
pub const TAG_HEX_LEN: usize = 32;

/// Line-1 article bootstrap length: 16 raw Alphabet salt bytes followed by
/// 4-byte uint32_be(segmentIndex) (control standard §4 step f).
pub const BOOTSTRAP_LEN: usize = 20;

/// Minimum restored Line-1 length: bootstrap + at least a 2-byte FF1
/// ciphertext (control standard §5 step 3b).
pub const LINE1_MIN_LEN: usize = BOOTSTRAP_LEN + 2;

/// A valid segmentIndex lies in 1..=4294967295; zero is invalid.
pub const SEGMENT_INDEX_MIN: u32 = 1;
/// Largest representable segmentIndex (uint32_be).
pub const SEGMENT_INDEX_MAX: u32 = u32::MAX;
