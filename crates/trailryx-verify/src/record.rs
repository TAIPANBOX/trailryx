//! Reading a canonical record, far enough to check the index.
//!
//! Not a full decoder. The verifier needs five fields and a sequence number,
//! and every other field is walked past by its shape. A partial decoder is the
//! right size here: it keeps the trusted computing base small, and the parts it
//! skips are parts it never has to have an opinion about.
//!
//! The order below is the record's canonical order and is what makes it work.
//! A field cannot be found by name, only by counting past the ones in front of
//! it, so this file is a direct transcription of the writing order and has to
//! change with it. That is stated here so nobody discovers it by surprise.

use crate::pack::PackError;

/// What the verifier extracts, and everything it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields {
    pub id: u128,
    pub recorded_at: u64,
    pub agent_id: String,
    pub run_id: String,
    pub event_type: u8,
    pub seq: u64,
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> Result<u8, PackError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(PackError::Truncated("a record"))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PackError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(PackError::Truncated("a record"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(PackError::Truncated("a record"))?;
        self.pos = end;
        Ok(slice)
    }

    /// LEB128, as the journal writes it.
    fn varint(&mut self) -> Result<u64, PackError> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            if shift >= 64 {
                return Err(PackError::Truncated("a varint"));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn zigzag(&mut self) -> Result<i64, PackError> {
        let v = self.varint()?;
        Ok(((v >> 1) as i64) ^ -((v & 1) as i64))
    }

    fn bytes(&mut self) -> Result<&'a [u8], PackError> {
        let len = self.varint()? as usize;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, PackError> {
        let b = self.bytes()?;
        std::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|_| PackError::NotUtf8("a record field"))
    }

    fn u128(&mut self) -> Result<u128, PackError> {
        let b = self.take(16)?;
        let mut v = [0u8; 16];
        v.copy_from_slice(b);
        Ok(u128::from_be_bytes(v))
    }

    fn hash(&mut self) -> Result<(), PackError> {
        self.take(48).map(|_| ())
    }

    /// An optional field: a presence byte, then the value if present.
    fn opt(
        &mut self,
        mut f: impl FnMut(&mut Self) -> Result<(), PackError>,
    ) -> Result<(), PackError> {
        if self.byte()? == 1 { f(self) } else { Ok(()) }
    }

    fn seq(
        &mut self,
        mut f: impl FnMut(&mut Self) -> Result<(), PackError>,
    ) -> Result<(), PackError> {
        let n = self.varint()?;
        for _ in 0..n {
            f(self)?;
        }
        Ok(())
    }
}

/// Walk a canonical record and pull out what the index is built from.
pub fn fields(bytes: &[u8]) -> Result<Fields, PackError> {
    let mut c = Cursor { buf: bytes, pos: 0 };

    let id = c.u128()?;
    c.bytes()?; // tenant
    c.varint()?; // shard
    let agent_id = c.string()?;
    let run_id = c.string()?;
    c.opt(|c| c.bytes().map(|_| ()))?; // parent run id
    c.seq(|c| c.bytes().map(|_| ()))?; // on behalf of

    c.varint()?; // occurred at
    c.opt(|c| c.varint().map(|_| ()))?; // decided at
    let recorded_at = c.varint()?;
    c.opt(|c| c.varint().map(|_| ()))?; // knowledge as of
    c.opt(|c| c.varint().map(|_| ()))?; // clock skew

    let event_type = c.byte()?;
    c.byte()?; // severity

    // Basis.
    c.opt(|c| c.bytes().map(|_| ()))?; // policy version
    c.opt(|c| c.zigzag().map(|_| ()))?; // budget remaining
    c.opt(|c| c.hash())?; // memory ref
    c.opt(|c| c.bytes().map(|_| ()))?; // model
    c.opt(|c| c.varint().map(|_| ()))?; // temperature
    c.opt(|c| c.varint().map(|_| ()))?; // max tokens
    c.opt(|c| c.hash())?; // prompt hash
    c.seq(|c| c.bytes().map(|_| ()))?; // tool manifest
    c.seq(|c| c.bytes().map(|_| ()))?; // identity chain

    c.seq(|c| c.u128().map(|_| ()))?; // caused by

    // Outcome.
    c.opt(|c| c.byte().map(|_| ()))?; // verdict
    c.opt(|c| c.byte().map(|_| ()))?; // error
    c.opt(|c| c.varint().map(|_| ()))?; // latency
    c.opt(|c| c.varint().map(|_| ()))?; // tokens in
    c.opt(|c| c.varint().map(|_| ()))?; // tokens out
    c.opt(|c| c.zigzag().map(|_| ()))?; // cost

    c.opt(|c| {
        c.hash()?; // payload hash
        c.varint()?; // size
        c.byte()?; // class
        c.hash() // key id
    })?;

    let seq = c.varint()?;

    Ok(Fields {
        id,
        recorded_at,
        agent_id,
        run_id,
        event_type,
        seq,
    })
}

/// The index key for a dimension, byte for byte as the store computes it.
///
/// Big-endian for numbers, so byte order is value order. A key whose
/// lexicographic order disagreed with its semantic order would make every range
/// answer wrong in a way no proof could catch, because the proof would be about
/// the wrong ordering.
pub fn key_for(dimension: &str, f: &Fields) -> Option<Vec<u8>> {
    Some(match dimension {
        "id" => f.id.to_be_bytes().to_vec(),
        "recorded_at" => f.recorded_at.to_be_bytes().to_vec(),
        "agent_id" => f.agent_id.as_bytes().to_vec(),
        "run_id" => f.run_id.as_bytes().to_vec(),
        "event_type" => vec![f.event_type],
        _ => return None,
    })
}
