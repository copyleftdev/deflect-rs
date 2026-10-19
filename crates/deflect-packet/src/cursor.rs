use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A forward cursor over a byte slice with checked big-endian reads. Every read
/// returns `None` rather than panicking when fewer bytes remain than requested,
/// because the bytes come from sampled packet headers captured off the wire.
///
/// A failed read leaves the position unchanged, so a caller may attempt a
/// shorter read afterwards (used to parse the layer-4 header best-effort when a
/// sampled header was truncated past the IP addresses).
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Cursor<'a> {
        Cursor { buf, pos: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    pub(crate) fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn ipv4(&mut self) -> Option<IpAddr> {
        let b = self.take(4)?;
        Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
    }

    pub(crate) fn ipv6(&mut self) -> Option<IpAddr> {
        let b = self.take(16)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(b);
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_scalars_big_endian_and_advances() {
        let mut c = Cursor::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(c.u8(), Some(0x01));
        assert_eq!(c.u16(), Some(0x0203));
        assert_eq!(c.u32(), Some(0x0405_0607));
        assert_eq!(c.u8(), None); // exhausted
    }

    #[test]
    fn a_short_read_returns_none_and_does_not_advance() {
        let mut c = Cursor::new(&[0x00]);
        assert_eq!(c.u32(), None);
        // The byte is still there for a narrower read.
        assert_eq!(c.u8(), Some(0x00));
    }

    #[test]
    fn take_past_the_end_is_none() {
        let mut c = Cursor::new(&[1, 2, 3]);
        assert_eq!(c.take(4), None);
        assert_eq!(c.take(3).map(<[u8]>::len), Some(3));
        assert_eq!(c.take(1), None);
    }

    #[test]
    fn skip_consumes_without_yielding() {
        let mut c = Cursor::new(&[1, 2, 3, 4]);
        assert_eq!(c.skip(3), Some(()));
        assert_eq!(c.u8(), Some(4));
        assert_eq!(c.skip(1), None);
    }

    #[test]
    fn addresses_parse() {
        let mut c4 = Cursor::new(&[203, 0, 113, 5]);
        assert_eq!(
            c4.ipv4(),
            "203.0.113.5".parse::<IpAddr>().map(Some).unwrap()
        );
        let octets: [u8; 16] = "2001:db8::1"
            .parse::<core::net::Ipv6Addr>()
            .unwrap()
            .octets();
        let mut c6 = Cursor::new(&octets);
        assert_eq!(
            c6.ipv6(),
            "2001:db8::1".parse::<IpAddr>().map(Some).unwrap()
        );
    }
}
