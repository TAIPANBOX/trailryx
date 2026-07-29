//! Thrift compact protocol, the write half.
//!
//! Parquet's footer is a Thrift-encoded structure, so a Parquet writer needs a
//! Thrift writer. This is the subset that footer uses and nothing else: no
//! service calls, no maps, no reading. About a hundred lines, which is the
//! whole reason it is here rather than pulled in.
//!
//! The encoding is worth knowing in one paragraph. A struct is a sequence of
//! fields and a zero byte. Each field starts with one byte holding the type in
//! the low nibble and, in the high nibble, how far the field id has moved since
//! the last one; a jump too large for four bits sets the high nibble to zero and
//! writes the id as a zigzag varint instead. Integers are zigzag varints, bytes
//! are a varint length followed by the bytes, and a list is a header byte
//! holding its size and element type, with the same escape when the size does
//! not fit.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    I32 = 5,
    I64 = 6,
    Binary = 8,
    List = 9,
    Struct = 12,
}

#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
    /// The last field id written at this nesting level. Field headers encode a
    /// delta, so each struct has to remember where it was.
    last_field: Vec<i16>,
}

impl Writer {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            last_field: vec![0],
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn varint(&mut self, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(byte);
                return;
            }
            self.buf.push(byte | 0x80);
        }
    }

    fn zigzag(&mut self, v: i64) {
        self.varint(((v << 1) ^ (v >> 63)) as u64);
    }

    fn field_header(&mut self, id: i16, kind: Kind) {
        let last = *self.last_field.last().unwrap_or(&0);
        let delta = id - last;
        if delta > 0 && delta <= 15 {
            self.buf.push(((delta as u8) << 4) | kind as u8);
        } else {
            self.buf.push(kind as u8);
            self.zigzag(i64::from(id));
        }
        if let Some(slot) = self.last_field.last_mut() {
            *slot = id;
        }
    }

    pub fn i32_field(&mut self, id: i16, value: i32) {
        self.field_header(id, Kind::I32);
        self.zigzag(i64::from(value));
    }

    pub fn i64_field(&mut self, id: i16, value: i64) {
        self.field_header(id, Kind::I64);
        self.zigzag(value);
    }

    pub fn binary_field(&mut self, id: i16, value: &[u8]) {
        self.field_header(id, Kind::Binary);
        self.varint(value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    pub fn string_field(&mut self, id: i16, value: &str) {
        self.binary_field(id, value.as_bytes());
    }

    pub fn struct_field(&mut self, id: i16, body: impl FnOnce(&mut Self)) {
        self.field_header(id, Kind::Struct);
        self.begin_struct();
        body(self);
        self.end_struct();
    }

    /// A list whose elements are written by the closure, one call per element.
    pub fn list_field(
        &mut self,
        id: i16,
        elem: Kind,
        len: usize,
        mut item: impl FnMut(&mut Self, usize),
    ) {
        self.field_header(id, Kind::List);
        if len < 15 {
            self.buf.push(((len as u8) << 4) | elem as u8);
        } else {
            self.buf.push(0xf0 | elem as u8);
            self.varint(len as u64);
        }
        for i in 0..len {
            item(self, i);
        }
    }

    /// An element inside a list: no field header, just the value.
    pub fn elem_i32(&mut self, value: i32) {
        self.zigzag(i64::from(value));
    }

    pub fn elem_string(&mut self, value: &str) {
        self.varint(value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
    }

    pub fn elem_struct(&mut self, body: impl FnOnce(&mut Self)) {
        self.begin_struct();
        body(self);
        self.end_struct();
    }

    pub fn begin_struct(&mut self) {
        self.last_field.push(0);
    }

    pub fn end_struct(&mut self) {
        self.last_field.pop();
        self.buf.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_small_field_delta_fits_in_the_header_byte() {
        let mut w = Writer::new();
        w.i32_field(1, 1);
        // delta 1, kind I32 (5) => 0x15, then zigzag(1) = 2.
        assert_eq!(w.into_bytes(), vec![0x15, 0x02]);
    }

    #[test]
    fn a_large_jump_escapes_to_a_zigzag_id() {
        let mut w = Writer::new();
        w.i32_field(20, 0);
        // No delta fits, so the high nibble is zero and the id follows.
        assert_eq!(w.into_bytes(), vec![0x05, 40, 0x00]);
    }

    #[test]
    fn a_nested_struct_restarts_the_field_delta() {
        // The bug this prevents: a nested struct continuing the outer struct's
        // field numbering writes fields nobody can read back.
        let mut w = Writer::new();
        w.i32_field(5, 0);
        w.struct_field(6, |w| w.i32_field(1, 0));
        w.i32_field(7, 0);
        let bytes = w.into_bytes();
        // 5, then struct at delta 1, inner field 1 at delta 1, struct end,
        // then 7 at delta 1 from 6.
        assert_eq!(bytes, vec![0x55, 0x00, 0x1c, 0x15, 0x00, 0x00, 0x15, 0x00]);
    }

    #[test]
    fn zigzag_keeps_small_negatives_small() {
        let mut w = Writer::new();
        w.i64_field(1, -1);
        assert_eq!(w.into_bytes(), vec![0x16, 0x01]);
    }

    #[test]
    fn a_long_list_escapes_its_length() {
        let mut w = Writer::new();
        w.list_field(1, Kind::I32, 20, |w, _| w.elem_i32(0));
        let bytes = w.into_bytes();
        assert_eq!(&bytes[..3], &[0x19, 0xf5, 20]);
        assert_eq!(bytes.len(), 3 + 20);
    }
}
