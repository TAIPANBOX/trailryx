//! A protobuf wire reader.
//!
//! Written here rather than taken, for the same reason as everything else in
//! the core: this is the first code that touches bytes from a stranger. An
//! ingest endpoint is the one place in the system where an attacker chooses the
//! input, so the parser is a security boundary before it is a convenience.
//!
//! # Where this deliberately differs from our own codec
//!
//! [`trailryx_journal::wire`] rejects a non-canonical varint outright, because
//! we wrote those bytes: anything unexpected there is corruption or tampering.
//! Here we did not write them. The protobuf encoding permits a padded varint,
//! conforming parsers accept one, and refusing would mean a foreign agent with
//! an unusual encoder cannot talk to us at all. That would fail the only
//! criterion stage 6 has.
//!
//! So a padded varint is accepted and **counted**. No real encoder emits one,
//! which makes the count a useful signal about who is talking to us, and a
//! signal is worth more than a rejection we would have to apologise for.
//!
//! # What is refused
//!
//! - a length that runs past the end of the buffer, at any nesting level;
//! - group wire types (3 and 4), removed from proto3 and never used by OTLP;
//! - field number zero, which no encoder produces and no decoder can use;
//! - nesting past [`MAX_DEPTH`].
//!
//! The depth limit is not tidiness. `AnyValue` may contain a list of
//! `AnyValue`, so a few hundred bytes of nested length prefixes describe a
//! structure thousands deep, and a recursive descent parser meeting one
//! overflows the stack. In Rust a stack overflow aborts the process, so
//! without this limit a single small message takes the whole store down.

use std::cell::Cell;
use std::fmt;

/// How deeply nested a message may be before we stop believing it is sincere.
///
/// OTLP's own worst case is shallow: request → resource spans → scope spans →
/// span → attribute → value, and a value that is a list of maps adds two more.
/// Sixteen leaves room for a schema we have not seen without leaving room for a
/// message designed to exhaust the stack.
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// A field claimed more bytes than the buffer holds.
    Truncated,
    /// More than ten bytes of varint, which cannot encode a 64-bit value.
    VarintTooLong,
    /// Wire types 3 and 4 (groups) or anything above 5.
    UnknownWireType(u8),
    /// Field number 0, which the encoding reserves.
    FieldNumberZero,
    TooDeep,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated: a field runs past the end of the buffer"),
            Self::VarintTooLong => write!(f, "varint longer than ten bytes"),
            Self::UnknownWireType(t) => write!(f, "unknown wire type {t}"),
            Self::FieldNumberZero => write!(f, "field number zero"),
            Self::TooDeep => write!(f, "nested deeper than {MAX_DEPTH}"),
        }
    }
}

impl std::error::Error for WireError {}

/// What the bytes told us about their author, beyond their contents.
///
/// Shared by every reader in one decode, including nested ones, so the totals
/// describe the whole message rather than whichever level happened to notice.
#[derive(Debug, Default)]
pub struct Stats {
    padded_varints: Cell<u32>,
    unknown_fields: Cell<u32>,
    deepest: Cell<usize>,
}

impl Stats {
    /// Varints encoded in more bytes than the value needs. Zero for every
    /// encoder in ordinary use, which is what makes a non-zero count worth
    /// looking at.
    pub fn padded_varints(&self) -> u32 {
        self.padded_varints.get()
    }

    /// Fields we skipped because this version does not know them.
    ///
    /// Not an error: forward compatibility is the entire point of the encoding.
    /// But a record mapped from a message we only partly understood is a
    /// partial view of what the emitter said, and an auditor is entitled to
    /// know that before relying on it.
    pub fn unknown_fields(&self) -> u32 {
        self.unknown_fields.get()
    }

    pub fn deepest(&self) -> usize {
        self.deepest.get()
    }

    fn note_padded(&self) {
        self.padded_varints
            .set(self.padded_varints.get().saturating_add(1));
    }

    fn note_unknown(&self) {
        self.unknown_fields
            .set(self.unknown_fields.get().saturating_add(1));
    }

    fn note_depth(&self, depth: usize) {
        if depth > self.deepest.get() {
            self.deepest.set(depth);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    Varint,
    Fixed64,
    Bytes,
    Fixed32,
}

impl WireType {
    fn from_bits(bits: u8) -> Result<Self, WireError> {
        match bits {
            0 => Ok(Self::Varint),
            1 => Ok(Self::Fixed64),
            2 => Ok(Self::Bytes),
            5 => Ok(Self::Fixed32),
            other => Err(WireError::UnknownWireType(other)),
        }
    }
}

/// A cursor over one protobuf message.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
    stats: &'a Stats,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], stats: &'a Stats) -> Self {
        Self {
            buf,
            pos: 0,
            depth: 0,
            stats,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn stats(&self) -> &'a Stats {
        self.stats
    }

    /// The next field's number and wire type.
    pub fn tag(&mut self) -> Result<(u32, WireType), WireError> {
        let key = self.varint()?;
        let field = (key >> 3) as u32;
        if field == 0 {
            return Err(WireError::FieldNumberZero);
        }
        Ok((field, WireType::from_bits((key & 0x07) as u8)?))
    }

    pub fn varint(&mut self) -> Result<u64, WireError> {
        let start = self.pos;
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = *self.buf.get(self.pos).ok_or(WireError::Truncated)?;
            self.pos += 1;
            if shift == 63 {
                // The tenth byte carries one meaningful bit. Encoders that set
                // the rest exist in the wild; conforming parsers discard them,
                // so we discard them too rather than reject a message over a
                // byte nobody reads.
                value |= u64::from(byte & 0x01) << 63;
                if byte & 0x80 != 0 {
                    return Err(WireError::VarintTooLong);
                }
                break;
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        if self.pos - start > canonical_len(value) {
            self.stats.note_padded();
        }
        Ok(value)
    }

    pub fn fixed64(&mut self) -> Result<u64, WireError> {
        let end = self.pos.checked_add(8).ok_or(WireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(slice);
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn fixed32(&mut self) -> Result<u32, WireError> {
        let end = self.pos.checked_add(4).ok_or(WireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(slice);
        Ok(u32::from_le_bytes(bytes))
    }

    /// A length-delimited field, borrowed rather than copied.
    pub fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.varint()?).map_err(|_| WireError::Truncated)?;
        let end = self.pos.checked_add(len).ok_or(WireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// A length-delimited field read as a submessage, one level deeper.
    pub fn nested(&mut self) -> Result<Reader<'a>, WireError> {
        let depth = self.depth + 1;
        if depth > MAX_DEPTH {
            return Err(WireError::TooDeep);
        }
        self.stats.note_depth(depth);
        let buf = self.bytes()?;
        Ok(Reader {
            buf,
            pos: 0,
            depth,
            stats: self.stats,
        })
    }

    /// Step over a field this version does not know, and remember that we did.
    pub fn skip(&mut self, wire: WireType) -> Result<(), WireError> {
        self.stats.note_unknown();
        match wire {
            WireType::Varint => {
                self.varint()?;
            }
            WireType::Fixed64 => {
                self.fixed64()?;
            }
            WireType::Fixed32 => {
                self.fixed32()?;
            }
            WireType::Bytes => {
                self.bytes()?;
            }
        }
        Ok(())
    }
}

/// How many bytes the varint encoding of `value` needs.
fn canonical_len(value: u64) -> usize {
    let bits = 64 - value.leading_zeros() as usize;
    if bits == 0 { 1 } else { bits.div_ceil(7) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut v = value;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    #[test]
    fn varints_round_trip_at_the_edges() {
        for value in [
            0u64,
            1,
            127,
            128,
            300,
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let bytes = varint(value);
            let stats = Stats::default();
            let mut r = Reader::new(&bytes, &stats);
            assert_eq!(r.varint().unwrap(), value, "value {value}");
            assert_eq!(stats.padded_varints(), 0, "value {value}");
        }
    }

    #[test]
    fn a_padded_varint_is_accepted_and_counted() {
        // Nothing in ordinary use emits this. Accepting it keeps us a
        // conforming parser; counting it keeps the oddity visible.
        let bytes = [0x81, 0x80, 0x80, 0x00];
        let stats = Stats::default();
        let mut r = Reader::new(&bytes, &stats);
        assert_eq!(r.varint().unwrap(), 1);
        assert_eq!(stats.padded_varints(), 1);
    }

    #[test]
    fn an_eleven_byte_varint_is_refused() {
        let bytes = [0xff; 11];
        let stats = Stats::default();
        let mut r = Reader::new(&bytes, &stats);
        assert_eq!(r.varint(), Err(WireError::VarintTooLong));
    }

    #[test]
    fn a_length_past_the_end_is_truncation_not_a_panic() {
        // len = 200 with four bytes following.
        let mut bytes = varint(200);
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        let stats = Stats::default();
        let mut r = Reader::new(&bytes, &stats);
        assert_eq!(r.bytes(), Err(WireError::Truncated));
    }

    #[test]
    fn a_length_near_usize_max_is_truncation_not_an_overflow() {
        let mut bytes = varint(u64::MAX);
        bytes.push(0);
        let stats = Stats::default();
        let mut r = Reader::new(&bytes, &stats);
        assert_eq!(r.bytes(), Err(WireError::Truncated));
    }

    #[test]
    fn group_wire_types_are_refused() {
        // Field 1, wire type 3 (start group).
        let bytes = [0x0b];
        let stats = Stats::default();
        let mut r = Reader::new(&bytes, &stats);
        assert_eq!(r.tag(), Err(WireError::UnknownWireType(3)));
    }

    #[test]
    fn field_number_zero_is_refused() {
        let bytes = [0x02];
        let stats = Stats::default();
        let mut r = Reader::new(&bytes, &stats);
        assert_eq!(r.tag(), Err(WireError::FieldNumberZero));
    }

    #[test]
    fn nesting_stops_before_the_stack_does() {
        // A message that is nothing but length prefixes, one per level. Cheap
        // to write, and without the limit it is a way to abort the process
        // from outside.
        let mut buf = Vec::new();
        for _ in 0..64 {
            let mut next = vec![0x0a]; // field 1, wire type 2
            next.extend_from_slice(&varint(buf.len() as u64));
            next.extend_from_slice(&buf);
            buf = next;
        }

        let stats = Stats::default();
        let mut r = Reader::new(&buf, &stats);
        let mut depth = 0;
        let err = loop {
            let Ok((_, wire)) = r.tag() else { break None };
            assert_eq!(wire, WireType::Bytes);
            match r.nested() {
                Ok(next) => {
                    r = next;
                    depth += 1;
                }
                Err(e) => break Some(e),
            }
        };
        assert_eq!(err, Some(WireError::TooDeep));
        assert_eq!(depth, MAX_DEPTH);
    }

    #[test]
    fn skipping_an_unknown_field_leaves_the_cursor_on_the_next_one() {
        // Field 1 varint 7 (unknown to us), then field 2 varint 9.
        let bytes = [0x08, 0x07, 0x10, 0x09];
        let stats = Stats::default();
        let mut r = Reader::new(&bytes, &stats);
        let (field, wire) = r.tag().unwrap();
        assert_eq!(field, 1);
        r.skip(wire).unwrap();
        let (field, wire) = r.tag().unwrap();
        assert_eq!(field, 2);
        assert_eq!(wire, WireType::Varint);
        assert_eq!(r.varint().unwrap(), 9);
        assert!(r.is_empty());
        assert_eq!(stats.unknown_fields(), 1);
    }

    #[test]
    fn fixed_width_fields_read_little_endian() {
        let stats = Stats::default();
        let mut r = Reader::new(&[1, 0, 0, 0, 0, 0, 0, 0], &stats);
        assert_eq!(r.fixed64().unwrap(), 1);
        let mut r = Reader::new(&[0, 1, 0, 0], &stats);
        assert_eq!(r.fixed32().unwrap(), 256);
    }

    #[test]
    fn nested_readers_share_one_tally() {
        // Otherwise the totals describe whichever level happened to notice,
        // and a message padded three levels down would look clean.
        let inner = [0x81, 0x80, 0x00]; // padded varint, field-less body
        let mut buf = vec![0x0a];
        buf.extend_from_slice(&varint(inner.len() as u64));
        buf.extend_from_slice(&inner);

        let stats = Stats::default();
        let mut r = Reader::new(&buf, &stats);
        r.tag().unwrap();
        let mut inner = r.nested().unwrap();
        inner.varint().unwrap();
        assert_eq!(stats.padded_varints(), 1);
        assert_eq!(stats.deepest(), 1);
    }
}
