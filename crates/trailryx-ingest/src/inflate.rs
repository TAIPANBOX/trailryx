//! Gzip, decoded by hand.
//!
//! # Why this is here at all
//!
//! The OTLP specification makes gzip mandatory for a server and optional for a
//! client, and the topology decides the rest: a stock SDK usually sends
//! uncompressed, but the OpenTelemetry Collector's `otlphttp` exporter defaults
//! to gzip, and agent → collector → store is the ordinary production shape.
//! Refusing gzip would mean the standard forwarder cannot talk to us until
//! somebody edits its configuration, and the failure it produces is a
//! non-retryable 415, which is silent data loss at the emitter.
//!
//! So it is implemented, for the same reason the protobuf reader is: the parser
//! at the trust boundary should be one we can read end to end.
//!
//! # Written for legibility
//!
//! The Huffman decoder walks one bit at a time in canonical-code order, the way
//! zlib's own reference decoder does. A table-driven decoder is faster and the
//! speed is worth nothing here: the input is capped at a few megabytes and this
//! runs once per request.
//!
//! # The bomb
//!
//! Every published vulnerability in this class is the same bug: decompress
//! fully, then check the size. So the output cap is enforced **inside** the
//! loop, checked before every byte is appended, and there is a ratio cap on top
//! of it. A few kilobytes must not be able to buy an attacker the whole limit
//! over and over.

/// Only RFC 1951 is recursive in the specification's prose. Nothing here is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateError {
    /// The gzip container is not one.
    BadMagic,
    /// A compression method other than deflate.
    UnsupportedMethod(u8),
    /// Reserved flag bits set, which no encoder produces.
    ReservedFlags(u8),
    /// The stream ends inside something.
    Truncated,
    /// Block type 3, which the specification reserves and no encoder emits.
    ReservedBlockType,
    /// A Huffman table that does not describe a complete code.
    BadHuffmanTable,
    /// A symbol outside the alphabet it was decoded from.
    BadSymbol(u16),
    /// A back-reference pointing before the start of the output.
    DistanceTooFar,
    /// The stored block's length and its complement disagree.
    StoredLengthMismatch,
    /// The trailing checksum does not match what we decoded.
    ChecksumMismatch,
    /// The trailing length does not match what we decoded.
    LengthMismatch,
    /// The output crossed the cap. Reported rather than truncated, because a
    /// truncated body handed onward is half a batch written on somebody's cue.
    OutputTooLarge,
    /// Small input, enormous output. The absolute cap alone still lets a few
    /// kilobytes buy the whole limit, repeatedly, across connections.
    RatioTooHigh,
    /// The stream asked for far more work than its length can justify.
    ///
    /// A body of nothing but empty blocks produces no output at all, so neither
    /// the output cap nor the ratio cap has anything to measure while the
    /// decoder spends minutes on it.
    TooMuchWork,
    /// The deflate stream did not end where the gzip trailer begins.
    ///
    /// Either bytes are hidden between them, or this is a multi-member stream,
    /// and the two need different answers rather than a checksum mismatch.
    TrailerNotWhereTheStreamEnded,
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a gzip stream"),
            Self::UnsupportedMethod(m) => write!(f, "compression method {m} is not deflate"),
            Self::ReservedFlags(b) => write!(f, "reserved gzip flag bits {b:#04x} are set"),
            Self::Truncated => write!(f, "the stream ends mid-symbol"),
            Self::ReservedBlockType => write!(f, "reserved block type"),
            Self::BadHuffmanTable => write!(f, "an incomplete Huffman code"),
            Self::BadSymbol(s) => write!(f, "symbol {s} is outside its alphabet"),
            Self::DistanceTooFar => write!(f, "a back-reference points before the output"),
            Self::StoredLengthMismatch => write!(f, "a stored block's length check failed"),
            Self::ChecksumMismatch => write!(f, "the gzip checksum does not match"),
            Self::LengthMismatch => write!(f, "the gzip length does not match"),
            Self::OutputTooLarge => write!(f, "the decompressed body exceeds the limit"),
            Self::RatioTooHigh => write!(f, "the compression ratio exceeds the limit"),
            Self::TooMuchWork => {
                write!(f, "the stream asks for more work than its length justifies")
            }
            Self::TrailerNotWhereTheStreamEnded => {
                write!(
                    f,
                    "the deflate stream does not end where the trailer begins"
                )
            }
        }
    }
}

impl std::error::Error for InflateError {}

/// What a decode is allowed to cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// Hard ceiling on produced bytes.
    pub max_output: usize,
    /// Output divided by input consumed so far.
    pub max_ratio: usize,
    /// How much **output** must exist before the ratio is judged.
    ///
    /// This gated on *input consumed* until an adversarial review measured it:
    /// a 16 MiB bomb is 16 KiB of input, and the gate opened at 32 KiB, so the
    /// ratio cap could not fire on any bomb worth sending. It was decoration
    /// with a comment claiming otherwise, which is worse than an absent check.
    ///
    /// Gating on output instead makes it bind exactly where it was meant to. A
    /// legitimate body reaching this much output has consumed roughly this much
    /// divided by its real ratio, so a stream that genuinely compresses better
    /// than [`Bounds::max_ratio`] is refused and nothing else is.
    pub ratio_after_output: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            max_output: 16 * 1024 * 1024,
            max_ratio: 200,
            ratio_after_output: 64 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Bits
// ---------------------------------------------------------------------------

struct Bits<'a> {
    data: &'a [u8],
    /// Byte position of the next unread byte.
    pos: usize,
    /// Bits held from the current partial byte, least significant first, which
    /// is the order deflate uses and the opposite of the one you expect.
    buffer: u32,
    count: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buffer: 0,
            count: 0,
        }
    }

    fn bit(&mut self) -> Result<u32, InflateError> {
        if self.count == 0 {
            self.buffer = u32::from(*self.data.get(self.pos).ok_or(InflateError::Truncated)?);
            self.pos += 1;
            self.count = 8;
        }
        let b = self.buffer & 1;
        self.buffer >>= 1;
        self.count -= 1;
        Ok(b)
    }

    fn bits(&mut self, n: u32) -> Result<u32, InflateError> {
        let mut value = 0u32;
        for i in 0..n {
            value |= self.bit()? << i;
        }
        Ok(value)
    }

    fn align(&mut self) {
        self.buffer = 0;
        self.count = 0;
    }

    /// Bytes consumed so far, for the ratio check.
    fn consumed(&self) -> usize {
        self.pos
    }
}

// ---------------------------------------------------------------------------
// Huffman
// ---------------------------------------------------------------------------

/// Whether a code has to fill its tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Completeness {
    /// A code read from the stream. Incomplete is an error: bit patterns that
    /// decode to nothing make a decoder's output depend on how it happens to
    /// fail, and every zlib-based decoder refuses one.
    ///
    /// With zlib's one exception, kept here: a code of one symbol or none, which
    /// is what a distance code looks like in a block that has no matches.
    Required,
    /// The specification's own fixed pair. Its distance code is defined over
    /// thirty symbols with five-bit codes, so two patterns of the thirty-two are
    /// unused: incomplete by arithmetic and legal by definition. Requiring
    /// completeness here broke every stream in the corpus, which is how this
    /// distinction came to be written down.
    AsSpecified,
}

/// A canonical Huffman code, held as counts per length plus symbols in order.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self, InflateError> {
        Self::build(lengths, Completeness::Required)
    }

    fn build(lengths: &[u8], completeness: Completeness) -> Result<Self, InflateError> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            counts[usize::from(len)] += 1;
        }
        // Length zero means "this symbol is not in the code" and is not a
        // length. Everything below counts codes, so it must be excluded first.
        counts[0] = 0;

        // A code is over-subscribed if the lengths describe more codes than the
        // tree has room for. Accepting one means two symbols share a prefix and
        // the decode is ambiguous.
        let mut left = 1i32;
        for count in counts.iter().skip(1) {
            left <<= 1;
            left -= i32::from(*count);
            if left < 0 {
                return Err(InflateError::BadHuffmanTable);
            }
        }

        // And under-subscribed is refused too, which it was not until a review
        // pointed out that a stream every zlib-based decoder rejects decoded
        // here. An incomplete code has bit patterns that decode to nothing, and
        // a decoder that walks off the end of one is a decoder whose output
        // depends on how it happens to fail.
        //
        // The exception zlib makes and this makes with it: a code of one symbol,
        // or none, which is what a distance code looks like in a block that has
        // no matches. It is incomplete by arithmetic and legal by convention.
        let symbols_used: u16 = counts.iter().skip(1).sum();
        if left > 0 && symbols_used > 1 && completeness == Completeness::Required {
            return Err(InflateError::BadHuffmanTable);
        }

        let mut offsets = [0u16; 16];
        for len in 1..15 {
            offsets[len + 1] = offsets[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len != 0 {
                symbols[usize::from(offsets[usize::from(len)])] = symbol as u16;
                offsets[usize::from(len)] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    /// Walk the canonical code one bit at a time.
    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, InflateError> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for len in 1..16 {
            code |= bits.bit()? as i32;
            let count = i32::from(self.counts[len]);
            if code - first < count {
                let at = usize::try_from(index + (code - first))
                    .map_err(|_| InflateError::BadHuffmanTable)?;
                return self
                    .symbols
                    .get(at)
                    .copied()
                    .ok_or(InflateError::BadHuffmanTable);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(InflateError::BadHuffmanTable)
    }
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u32; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// The order the code-length alphabet's own lengths arrive in.
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// The fixed code pair, built once for the life of the process.
///
/// Built per block until a review measured it: a 16 MiB body of empty fixed
/// blocks burned twenty-one seconds of processor time while both the output cap
/// and the ratio cap stayed silent, because empty blocks produce nothing to
/// measure. There is exactly one fixed code in the specification, so there is no
/// reason to build it more than once.
fn fixed_tables() -> &'static (Huffman, Huffman) {
    static FIXED: std::sync::OnceLock<(Huffman, Huffman)> = std::sync::OnceLock::new();
    FIXED.get_or_init(|| {
        let mut literal = [0u8; 288];
        for (symbol, slot) in literal.iter_mut().enumerate() {
            *slot = match symbol {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        let distance = [5u8; 30];
        (
            Huffman::build(&literal, Completeness::AsSpecified)
                .expect("the fixed literal code is the specification's"),
            Huffman::build(&distance, Completeness::AsSpecified)
                .expect("the fixed distance code is the specification's"),
        )
    })
}

/// What building one Huffman table costs, in the same units as one symbol.
///
/// Approximate on purpose. The point is that a table is expensive and a symbol
/// is cheap, so a stream made of nothing but table headers cannot hide behind a
/// meter that counts only symbols.
const TABLE_COST: usize = 300;

// ---------------------------------------------------------------------------
// The stream
// ---------------------------------------------------------------------------

struct Out {
    bytes: Vec<u8>,
    bounds: Bounds,
    /// Work done, in units where one symbol is one and one table is many.
    work: usize,
    /// Work allowed, derived from the input length and the output ceiling.
    work_budget: usize,
}

impl Out {
    fn push(&mut self, byte: u8, bits: &Bits<'_>) -> Result<(), InflateError> {
        // Checked before the byte is appended, every time. The moment this
        // check moves after the loop, this file has a CVE in it.
        if self.bytes.len() >= self.bounds.max_output {
            return Err(InflateError::OutputTooLarge);
        }
        // Judged once there is enough output to judge, rather than once enough
        // input has been read. A bomb's whole point is that its input is small.
        if self.bytes.len() >= self.bounds.ratio_after_output
            && self.bytes.len() / bits.consumed().max(1) >= self.bounds.max_ratio
        {
            return Err(InflateError::RatioTooHigh);
        }
        self.bytes.push(byte);
        Ok(())
    }

    fn charge(&mut self, units: usize) -> Result<(), InflateError> {
        self.work = self.work.saturating_add(units);
        if self.work > self.work_budget {
            return Err(InflateError::TooMuchWork);
        }
        Ok(())
    }
}

fn inflate_blocks(bits: &mut Bits<'_>, out: &mut Out) -> Result<(), InflateError> {
    loop {
        out.charge(1)?;
        let last = bits.bit()?;
        match bits.bits(2)? {
            0 => {
                bits.align();
                let len = u16::from(*bits.data.get(bits.pos).ok_or(InflateError::Truncated)?)
                    | (u16::from(*bits.data.get(bits.pos + 1).ok_or(InflateError::Truncated)?)
                        << 8);
                let nlen = u16::from(*bits.data.get(bits.pos + 2).ok_or(InflateError::Truncated)?)
                    | (u16::from(*bits.data.get(bits.pos + 3).ok_or(InflateError::Truncated)?)
                        << 8);
                if len != !nlen {
                    return Err(InflateError::StoredLengthMismatch);
                }
                bits.pos += 4;
                for _ in 0..len {
                    let byte = *bits.data.get(bits.pos).ok_or(InflateError::Truncated)?;
                    bits.pos += 1;
                    out.push(byte, bits)?;
                }
            }
            1 => {
                let (literal, distance) = fixed_tables();
                inflate_symbols(bits, out, literal, distance)?;
            }
            2 => {
                out.charge(2 * TABLE_COST)?;
                let (literal, distance) = dynamic_tables(bits)?;
                inflate_symbols(bits, out, &literal, &distance)?;
            }
            _ => return Err(InflateError::ReservedBlockType),
        }
        if last == 1 {
            return Ok(());
        }
    }
}

fn dynamic_tables(bits: &mut Bits<'_>) -> Result<(Huffman, Huffman), InflateError> {
    let hlit = bits.bits(5)? as usize + 257;
    let hdist = bits.bits(5)? as usize + 1;
    let hclen = bits.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(InflateError::BadHuffmanTable);
    }

    let mut code_lengths = [0u8; 19];
    for &slot in CODE_LENGTH_ORDER.iter().take(hclen) {
        code_lengths[slot] = bits.bits(3)? as u8;
    }
    let code_length_code = Huffman::new(&code_lengths)?;

    let mut lengths = vec![0u8; hlit + hdist];
    let mut at = 0usize;
    while at < lengths.len() {
        let symbol = code_length_code.decode(bits)?;
        match symbol {
            0..=15 => {
                lengths[at] = symbol as u8;
                at += 1;
            }
            16 => {
                // Repeat the previous length. There must be one.
                if at == 0 {
                    return Err(InflateError::BadHuffmanTable);
                }
                let previous = lengths[at - 1];
                let repeat = 3 + bits.bits(2)? as usize;
                for _ in 0..repeat {
                    if at >= lengths.len() {
                        return Err(InflateError::BadHuffmanTable);
                    }
                    lengths[at] = previous;
                    at += 1;
                }
            }
            17 | 18 => {
                let repeat = if symbol == 17 {
                    3 + bits.bits(3)? as usize
                } else {
                    11 + bits.bits(7)? as usize
                };
                for _ in 0..repeat {
                    if at >= lengths.len() {
                        return Err(InflateError::BadHuffmanTable);
                    }
                    lengths[at] = 0;
                    at += 1;
                }
            }
            other => return Err(InflateError::BadSymbol(other)),
        }
    }

    Ok((
        Huffman::new(&lengths[..hlit])?,
        Huffman::new(&lengths[hlit..])?,
    ))
}

fn inflate_symbols(
    bits: &mut Bits<'_>,
    out: &mut Out,
    literal: &Huffman,
    distance: &Huffman,
) -> Result<(), InflateError> {
    loop {
        out.charge(1)?;
        let symbol = literal.decode(bits)?;
        match symbol {
            0..=255 => out.push(symbol as u8, bits)?,
            256 => return Ok(()),
            257..=285 => {
                let index = usize::from(symbol) - 257;
                let length =
                    usize::from(LENGTH_BASE[index]) + bits.bits(LENGTH_EXTRA[index])? as usize;

                let dsymbol = usize::from(distance.decode(bits)?);
                if dsymbol >= DIST_BASE.len() {
                    return Err(InflateError::BadSymbol(dsymbol as u16));
                }
                let dist = DIST_BASE[dsymbol] as usize + bits.bits(DIST_EXTRA[dsymbol])? as usize;
                if dist == 0 || dist > out.bytes.len() {
                    return Err(InflateError::DistanceTooFar);
                }
                // Byte at a time, on purpose: overlapping copies are legal and
                // common (a run of one byte is encoded as distance 1), and a
                // bulk copy would get them wrong.
                for _ in 0..length {
                    let byte = out.bytes[out.bytes.len() - dist];
                    out.push(byte, bits)?;
                }
            }
            other => return Err(InflateError::BadSymbol(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// The gzip container
// ---------------------------------------------------------------------------

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            // Branchless, so the loop reads the same whichever bit is set.
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Decode a gzip stream, bounded.
pub fn gunzip(input: &[u8], bounds: Bounds) -> Result<Vec<u8>, InflateError> {
    if input.len() < 18 {
        // Ten bytes of header, eight of trailer, and at least something
        // between them. Anything shorter cannot be a gzip stream.
        return Err(InflateError::Truncated);
    }
    if input[0] != 0x1f || input[1] != 0x8b {
        return Err(InflateError::BadMagic);
    }
    if input[2] != 8 {
        return Err(InflateError::UnsupportedMethod(input[2]));
    }
    let flags = input[3];
    if flags & 0xE0 != 0 {
        return Err(InflateError::ReservedFlags(flags));
    }

    let mut at = 10usize;
    if flags & 0x04 != 0 {
        // FEXTRA. Its length is client-supplied, so it is bounded like every
        // other length here rather than trusted.
        let len = usize::from(*input.get(at).ok_or(InflateError::Truncated)?)
            | (usize::from(*input.get(at + 1).ok_or(InflateError::Truncated)?) << 8);
        at = at
            .checked_add(2 + len)
            .filter(|end| *end <= input.len())
            .ok_or(InflateError::Truncated)?;
    }
    for flag in [0x08u8, 0x10] {
        if flags & flag != 0 {
            // FNAME and FCOMMENT are NUL-terminated. A stream with no
            // terminator must not run us off the end.
            let start = at;
            loop {
                let byte = *input.get(at).ok_or(InflateError::Truncated)?;
                at += 1;
                if byte == 0 {
                    break;
                }
                if at - start > 1024 {
                    return Err(InflateError::Truncated);
                }
            }
        }
    }
    if flags & 0x02 != 0 {
        at = at
            .checked_add(2)
            .filter(|end| *end <= input.len())
            .ok_or(InflateError::Truncated)?;
    }

    let trailer_at = input.len() - 8;
    if at >= trailer_at {
        return Err(InflateError::Truncated);
    }

    let deflate = &input[at..trailer_at];
    let mut bits = Bits::new(deflate);
    let mut out = Out {
        bytes: Vec::new(),
        bounds,
        work: 0,
        // Proportional to what the stream may produce, plus a term for its own
        // length, so a body of nothing but block headers is bounded by the
        // length it paid for rather than by an output it never produces.
        work_budget: bounds
            .max_output
            .saturating_add(input.len().saturating_mul(16))
            .saturating_add(1_000_000),
    };
    inflate_blocks(&mut bits, &mut out)?;

    // The trailer was read from the last eight bytes of the input regardless of
    // where the stream ended, which a review caught two ways: a legal
    // multi-member stream was refused as a checksum mismatch, and bytes hidden
    // between the end of the deflate data and the trailer were ignored
    // entirely. Requiring the two to meet refuses both, and names which.
    if bits.consumed() < deflate.len() {
        return Err(InflateError::TrailerNotWhereTheStreamEnded);
    }

    let expected_crc = u32::from_le_bytes([
        input[trailer_at],
        input[trailer_at + 1],
        input[trailer_at + 2],
        input[trailer_at + 3],
    ]);
    let expected_len = u32::from_le_bytes([
        input[trailer_at + 4],
        input[trailer_at + 5],
        input[trailer_at + 6],
        input[trailer_at + 7],
    ]);
    if crc32(&out.bytes) != expected_crc {
        return Err(InflateError::ChecksumMismatch);
    }
    // The trailer records the length modulo 2^32, which is the only comparison
    // the format allows and is still worth making.
    if (out.bytes.len() as u32) != expected_len {
        return Err(InflateError::LengthMismatch);
    }
    Ok(out.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checksum_matches_the_published_value() {
        // The one constant in this file that cannot be derived by reading it.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_stream_that_is_not_gzip_is_named_rather_than_guessed_at() {
        assert_eq!(
            gunzip(&[0u8; 32], Bounds::default()),
            Err(InflateError::BadMagic)
        );
        assert_eq!(
            gunzip(b"short", Bounds::default()),
            Err(InflateError::Truncated)
        );
    }

    #[test]
    fn the_specifications_own_fixed_distance_code_is_not_rejected_as_incomplete() {
        // Thirty symbols of five-bit codes leaves two of thirty-two patterns
        // unused, so it is incomplete by arithmetic. Requiring completeness of
        // it broke every stream in the corpus, which is why the two kinds of
        // code are distinguished rather than treated alike.
        assert!(Huffman::build(&[5u8; 30], Completeness::AsSpecified).is_ok());
        assert_eq!(
            Huffman::build(&[5u8; 30], Completeness::Required).err(),
            Some(InflateError::BadHuffmanTable)
        );
    }

    #[test]
    fn an_incomplete_code_from_the_stream_is_refused() {
        // The defect this closes: a code whose lengths leave patterns decoding
        // to nothing was accepted, so a stream every other decoder rejects
        // produced a body we handed onward.
        assert_eq!(
            Huffman::new(&[1, 2]).err(),
            Some(InflateError::BadHuffmanTable),
            "one one-bit code and one two-bit code leaves a pattern unreachable"
        );
        // zlib's exception, kept: a code of one symbol, which is what a distance
        // code looks like in a block with no matches.
        assert!(Huffman::new(&[1]).is_ok());
        assert!(Huffman::new(&[0, 0, 0]).is_ok());
        // And a complete code is still a complete code.
        assert!(Huffman::new(&[1, 1]).is_ok());
    }

    #[test]
    fn an_over_subscribed_huffman_table_is_refused() {
        // Three symbols of length one describe more codes than a binary tree of
        // that depth holds. Accepting it makes two symbols share a prefix and
        // the decode ambiguous, which is a decoder that can be steered.
        assert_eq!(
            Huffman::new(&[1, 1, 1]).err(),
            Some(InflateError::BadHuffmanTable)
        );
        assert!(Huffman::new(&[1, 1]).is_ok());
    }

    #[test]
    fn a_length_of_zero_is_absence_and_not_a_code() {
        // If zero were counted as a length, every table with an unused symbol
        // would look over-subscribed and nothing would decode.
        assert!(Huffman::new(&[0, 0, 1, 1]).is_ok());
    }
}
