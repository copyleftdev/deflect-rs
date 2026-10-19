use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A read past the end of the buffer, i.e. truncated or malformed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated;

/// A cursor over a byte buffer with checked big-endian reads. Every read is
/// bounds-checked and returns [`Truncated`] rather than panicking, because the
/// input is attacker-controlled network data.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Borrow the next `n` bytes and advance.
    ///
    /// # Errors
    /// Returns [`Truncated`] if fewer than `n` bytes remain.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        let end = self.pos.checked_add(n).ok_or(Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Advance over `n` bytes without returning them.
    ///
    /// # Errors
    /// Returns [`Truncated`] if fewer than `n` bytes remain.
    pub fn skip(&mut self, n: usize) -> Result<(), Truncated> {
        self.bytes(n).map(|_| ())
    }

    /// Fork a sub-reader over the next `n` bytes and advance past them; used to
    /// bound a nested structure (a set or record) to its declared length.
    ///
    /// # Errors
    /// Returns [`Truncated`] if fewer than `n` bytes remain.
    pub fn sub(&mut self, n: usize) -> Result<Reader<'a>, Truncated> {
        Ok(Reader::new(self.bytes(n)?))
    }

    /// # Errors
    /// Returns [`Truncated`] if no byte remains.
    pub fn u8(&mut self) -> Result<u8, Truncated> {
        Ok(self.bytes(1)?[0])
    }

    /// # Errors
    /// Returns [`Truncated`] if fewer than two bytes remain.
    pub fn u16(&mut self) -> Result<u16, Truncated> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// # Errors
    /// Returns [`Truncated`] if fewer than four bytes remain.
    pub fn u32(&mut self) -> Result<u32, Truncated> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read `n` (1..=8) bytes as a big-endian unsigned integer, widened to
    /// `u64`. `n == 0` yields `0`; `n > 8` reads the low 8 and skips the rest.
    ///
    /// # Errors
    /// Returns [`Truncated`] if fewer than `n` bytes remain.
    pub fn uint(&mut self, n: usize) -> Result<u64, Truncated> {
        if n > 8 {
            self.skip(n - 8)?;
            return self.uint(8);
        }
        let raw = self.bytes(n)?;
        // Right-align the bytes in an 8-byte big-endian buffer so the value is
        // their unsigned interpretation; no manual shift-or (keeps the decode
        // free of an and/or/xor that a flipped operator could not change).
        let mut buf = [0u8; 8];
        buf[8 - n..].copy_from_slice(raw);
        Ok(u64::from_be_bytes(buf))
    }

    /// # Errors
    /// Returns [`Truncated`] if fewer than four bytes remain.
    pub fn ipv4(&mut self) -> Result<IpAddr, Truncated> {
        let b = self.bytes(4)?;
        Ok(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
    }

    /// # Errors
    /// Returns [`Truncated`] if fewer than sixteen bytes remain.
    pub fn ipv6(&mut self) -> Result<IpAddr, Truncated> {
        let b = self.bytes(16)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(b);
        Ok(IpAddr::V6(Ipv6Addr::from(octets)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian_scalars() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(r.u8().unwrap(), 0x01);
        assert_eq!(r.u16().unwrap(), 0x0203);
        assert_eq!(r.u32().unwrap(), 0x0405_0607);
        assert!(r.is_empty());
    }

    #[test]
    fn truncation_is_an_error_not_a_panic() {
        let mut r = Reader::new(&[0x00]);
        assert_eq!(r.u32(), Err(Truncated));
        // Position is unchanged after a failed read.
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn uint_reads_variable_width() {
        let mut r = Reader::new(&[0x00, 0x00, 0x01, 0x00]);
        assert_eq!(r.uint(4).unwrap(), 256);
        let mut r2 = Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(r2.uint(8).unwrap(), u64::MAX);
    }

    #[test]
    fn uint_zero_width_is_zero() {
        let mut r = Reader::new(&[0xAA]);
        assert_eq!(r.uint(0).unwrap(), 0);
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn is_empty_is_false_with_bytes_remaining() {
        let mut r = Reader::new(&[0x01, 0x02]);
        assert!(!r.is_empty());
        r.u16().unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn uint_wider_than_eight_skips_the_high_bytes() {
        // 10-byte field: the leading 2 bytes are skipped, the low 8 form the value.
        let mut r = Reader::new(&[0xAA, 0xBB, 0, 0, 0, 0, 0, 0, 0x01, 0x00]);
        assert_eq!(r.uint(10).unwrap(), 256);
        assert!(r.is_empty());
    }

    #[test]
    fn sub_bounds_a_nested_region() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5]);
        let mut inner = r.sub(2).unwrap();
        assert_eq!(inner.remaining(), 2);
        assert_eq!(r.remaining(), 3);
        assert_eq!(inner.u16().unwrap(), 0x0102);
    }

    #[test]
    fn addresses_parse() {
        let mut r = Reader::new(&[203, 0, 113, 5]);
        assert_eq!(r.ipv4().unwrap(), "203.0.113.5".parse::<IpAddr>().unwrap());
    }
}
