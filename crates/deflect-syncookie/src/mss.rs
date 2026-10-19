/// Advertisable MSS values a cookie can encode, ascending. Three bits select
/// one of eight; the connection's real MSS is quantised down to the largest
/// entry not exceeding it, so the restored value is never larger than the peer
/// asked for. Values span a legacy floor to a jumbo-frame ceiling.
pub const MSS_TABLE: [u16; 8] = [536, 1300, 1440, 1460, 4312, 8960, 9000, 65495];

/// Encode an MSS to its 3-bit table index: the largest entry `<= mss`, or index
/// `0` when `mss` is below the floor.
#[must_use]
pub fn encode_mss(mss: u16) -> u8 {
    let mut idx = 0u8;
    for (i, &v) in MSS_TABLE.iter().enumerate().take(8) {
        if v <= mss {
            // i < 8 by take(8), so the narrowing cannot truncate.
            #[allow(clippy::cast_possible_truncation)]
            {
                idx = i as u8;
            }
        } else {
            break;
        }
    }
    idx
}

/// Decode a 3-bit index back to its MSS. Indices are masked to the table, so
/// out-of-range input cannot panic.
#[must_use]
pub fn decode_mss(idx: u8) -> u16 {
    MSS_TABLE[(idx & 0b111) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_picks_largest_not_exceeding() {
        assert_eq!(encode_mss(1500), 3); // 1460
        assert_eq!(encode_mss(1460), 3);
        assert_eq!(encode_mss(1459), 2); // 1440
        assert_eq!(encode_mss(65_535), 7); // 65495
    }

    #[test]
    fn below_floor_uses_index_zero() {
        assert_eq!(encode_mss(100), 0);
        assert_eq!(decode_mss(0), 536);
    }

    #[test]
    fn roundtrip_never_exceeds_input() {
        for mss in [536u16, 700, 1300, 1440, 1460, 9000, 65_495, 65_535] {
            let restored = decode_mss(encode_mss(mss));
            assert!(restored <= mss, "mss {mss} restored to {restored}");
        }
    }

    #[test]
    fn decode_masks_out_of_range() {
        assert_eq!(decode_mss(0b1111), decode_mss(0b0111));
    }
}
