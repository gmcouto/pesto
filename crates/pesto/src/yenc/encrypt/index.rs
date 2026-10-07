//! Release-wide segmentIndex allocation (VEC-07 / CR-02).
//!
//! A candidate index whose uint32_be encoding contains 0x0A (LF) or 0x0D
//! (CR) is forbidden: either byte would inject an NNTP line delimiter into
//! the Line-1 bootstrap and split it short. Uploaders skip such indices;
//! decoders reject them under PROVIDER_FAILOVER.

use super::error::EncryptionError;

/// Returns `true` when the big-endian encoding of `index` contains 0x0A or
/// 0x0D.
pub fn index_is_forbidden(index: u32) -> bool {
    let be = index.to_be_bytes();
    be.contains(&0x0A) || be.contains(&0x0D)
}

/// Advance forward from `candidate` to the next permitted index. Saturates
/// at `u32::MAX` (which is permitted) instead of overflowing.
pub fn next_permitted_index(candidate: u32) -> u32 {
    let mut index = candidate.max(super::header::SEGMENT_INDEX_MIN);
    while index_is_forbidden(index) {
        // The forbidden-byte run is bounded: 0xFFFFFFFF is always permitted,
        // so this loop cannot run away.
        index = index.saturating_add(1);
    }
    index
}

/// Release-wide allocator: hands out strictly increasing permitted indices
/// in 1..=4294967295. The counter advances monotonically for the whole
/// upload session and must be persisted with spool/resume state so retries
/// reproduce the same indices — never derived from completion order.
#[derive(Debug)]
pub struct SegmentIndexAllocator {
    next: u32,
}

impl SegmentIndexAllocator {
    /// Start allocating from `first_candidate` (the first permitted index at
    /// or after it is assigned first).
    pub fn new(first_candidate: u32) -> Self {
        Self {
            next: first_candidate.max(super::header::SEGMENT_INDEX_MIN),
        }
    }

    /// Allocate the next permitted index, skipping forbidden candidates.
    pub fn allocate(&mut self) -> Result<u32, EncryptionError> {
        if self.next == u32::MAX && index_is_forbidden(u32::MAX) {
            return Err(EncryptionError::Crypto(
                "segment index space exhausted".into(),
            ));
        }
        let assigned = next_permitted_index(self.next);
        self.next = assigned.saturating_add(1);
        Ok(assigned)
    }
}

impl Default for SegmentIndexAllocator {
    fn default() -> Self {
        Self::new(super::header::SEGMENT_INDEX_MIN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_forbidden_candidates() {
        // VEC-07: 10->11, 13->14, 266->267, 269->270.
        assert_eq!(next_permitted_index(10), 11);
        assert_eq!(next_permitted_index(13), 14);
        assert_eq!(next_permitted_index(266), 267);
        assert_eq!(next_permitted_index(269), 270);
        assert!(!index_is_forbidden(11));
        assert!(!index_is_forbidden(14));
        assert!(!index_is_forbidden(267));
        assert!(!index_is_forbidden(270));
    }

    #[test]
    fn allocator_is_monotonic_and_skips() {
        let mut alloc = SegmentIndexAllocator::new(1);
        assert_eq!(alloc.allocate().unwrap(), 1);
        // March the counter to 9; next allocation must jump over 10.
        for expected in 2..=9 {
            assert_eq!(alloc.allocate().unwrap(), expected);
        }
        assert_eq!(alloc.allocate().unwrap(), 11);
        assert_eq!(alloc.allocate().unwrap(), 12);
        assert_eq!(alloc.allocate().unwrap(), 14);
    }

    #[test]
    fn candidate_zero_is_promoted_to_one() {
        assert_eq!(next_permitted_index(0), 1);
        let mut alloc = SegmentIndexAllocator::new(0);
        assert_eq!(alloc.allocate().unwrap(), 1);
    }
}
