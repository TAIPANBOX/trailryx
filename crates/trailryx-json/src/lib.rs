//! A strict, bounded reader for RFC 8259 JSON, and a framer for JSON Lines.
//!
//! Depends on nothing, like [`trailryx_verify`]. Same reason: this is code
//! somebody has to read end to end before trusting what it lets into an audit
//! store, and every crate underneath it is a crate they would have to read too.
//!
//! # Why the error type has three classes
//!
//! RFC 8259 §9 puts two requirements in one paragraph. "A JSON parser MUST
//! accept all texts that conform to the JSON grammar", and "An implementation
//! may set limits on the size of texts that it accepts". Those pull against
//! each other, and a parser that resolves the tension by reporting a bound as a
//! syntax error is lying about the document.
//!
//! So a refusal says which of three things happened:
//!
//! - [`Kind::Syntax`]: the bytes are not JSON. Never returned for a document
//!   that conforms to the grammar, and that is a test.
//! - [`Kind::Limit`]: the bytes are JSON and we declined to read them. Names the
//!   bound, so an operator can raise it or fix the producer.
//! - [`Kind::Encoding`]: the bytes are not UTF-8, or are UTF-16 or UTF-32.
//!
//! # What this refuses that a lenient parser accepts
//!
//! Three deliberate divergences, each because a lenient answer would change the
//! bytes this store hashes and publishes a Merkle root over.
//!
//! - **A duplicate member name is fatal.** RFC 8259 is genuinely undecidable
//!   here: §4 blesses "report an error", §9 says accept all grammar-conformant
//!   texts. Every real parser picks a winner, and which one it picks is an
//!   implementation detail. CVE-2017-12635 is that detail becoming a privilege
//!   escalation. A detail must not be baked into evidence.
//! - **A lone surrogate is fatal**, escaped or raw. Rust cannot hold one in a
//!   `String`, so every lenient path is lossy: U+FFFD substitution changes the
//!   hashed bytes, and truncation is a published escalation primitive, because
//!   `"superadmin\ud888"` must never become `superadmin`.
//! - **`NaN`, `Infinity` and `-Infinity` as bare literals are refused.** They
//!   are not JSON. CPython accepts them, which makes CPython the outlier here
//!   and not us. (A `doubleValue` may still *say* infinity in OTLP/JSON, but it
//!   says it as the string `"Infinity"`, which is a value and not a literal.)
//!
//! Every other divergence between a strict reader and a lenient one goes our
//! way: `tests/oracle.rs` compares us against two independent parsers with no
//! shared ancestry and fails the build if the disagreement set grows.
//!
//! # Nothing is converted until asked
//!
//! A number is scanned, validated and kept as the bytes the producer wrote.
//! [`Number::as_u64`] and friends convert on demand from those digits, so a
//! 64-bit integer never passes through an `f64` on the way in. Rust's own
//! `str::parse` is the wrong tool for JSON and it is worth writing down why:
//! `"01"`, `"+1"`, `".5"`, `"5."`, `"inf"` and `"NaN"` all parse `Ok` as `f64`,
//! and `"01"` and `"+1"` parse `Ok` as `i64`. So the grammar is checked here
//! first, and `parse` is only ever handed bytes it cannot misread.

pub mod frame;
pub mod lex;
pub mod number;
pub mod reader;
pub mod validate;

pub use frame::{Framer, Line};
pub use number::Number;
pub use reader::{Event, Reader, Stats};
pub use validate::validate;

/// Which bound was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// Nesting deeper than [`Limits::max_depth`].
    Depth,
    /// A number longer than [`Limits::max_number_bytes`] digits.
    NumberDigits,
    /// More members in one object than [`Limits::max_keys_per_object`].
    ObjectMembers,
    /// A line longer than [`Limits::max_line_bytes`].
    LineTooLong,
}

impl Bound {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Depth => "nesting depth",
            Self::NumberDigits => "number length",
            Self::ObjectMembers => "members in one object",
            Self::LineTooLong => "line length",
        }
    }
}

/// What the bytes were, when they were not UTF-8 JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    InvalidUtf8,
    /// The bytes end part-way through a UTF-8 sequence that was still valid.
    ///
    /// Told apart from [`Self::InvalidUtf8`] because for the last line of a file
    /// being appended to it is not a fault at all: a collector that flushes on a
    /// timer stops wherever it stops, and an adversarial review measured 19 of 299
    /// truncation points of one line landing inside a two-byte Cyrillic character
    /// and each one producing a warning record claiming a line had been lost.
    /// Nothing had been lost; the producer had not finished writing the character.
    ///
    /// `std::str::Utf8Error::error_len` already draws exactly this line, so the
    /// distinction costs nothing: `None` means the input ended mid-sequence.
    IncompleteUtf8,
    /// A byte-order mark said UTF-16 or UTF-32. Detected and named rather than
    /// decoded: half-reading a UTF-16 document as ASCII is worse than refusing
    /// it, because the NULs make it *look* like a truncated ASCII document.
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

impl Encoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "not valid UTF-8",
            Self::IncompleteUtf8 => "ends part-way through a UTF-8 sequence",
            Self::Utf16Le => "UTF-16 little-endian",
            Self::Utf16Be => "UTF-16 big-endian",
            Self::Utf32Le => "UTF-32 little-endian",
            Self::Utf32Be => "UTF-32 big-endian",
        }
    }
}

/// Why the bytes are not JSON.
///
/// Each variant is a thing a test names. A single `Syntax` with a message would
/// make the corpus assert on strings, and a corpus that asserts on strings stops
/// being changed when the strings are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// The document ended in the middle of something.
    UnexpectedEof,
    /// A byte that cannot start a value.
    UnexpectedByte,
    /// Content after a complete value. A trailing NUL counts.
    TrailingContent,
    /// `[1,]`, `{"a":1,}`, or a comma where a value belongs.
    TrailingComma,
    /// A `:` missing, doubled, or somewhere it does not belong.
    ExpectedColon,
    /// An object member name that is not a string.
    ExpectedName,
    /// The same member name twice in one object. See the crate doc.
    DuplicateName,
    /// A control character U+0000..U+001F unescaped inside a string. This is the
    /// check that stops a raw newline splitting one record into two lines.
    ControlInString,
    /// `\q`, or a `\u` that is not followed by four hex digits.
    BadEscape,
    /// An unpaired surrogate, escaped or raw. See the crate doc.
    LoneSurrogate,
    /// Leading zero, leading `+`, bare `.5` or `5.`, a truncated exponent, a
    /// bare `NaN` or `Infinity`, a hex literal, a digit separator.
    BadNumber,
    /// Not `true`, `false` or `null` after the byte that started one.
    BadLiteral,
}

impl Syntax {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedEof => "the document ends here",
            Self::UnexpectedByte => "this byte cannot start a value",
            Self::TrailingContent => "content after the value",
            Self::TrailingComma => "a comma where a value belongs",
            Self::ExpectedColon => "a colon belongs here",
            Self::ExpectedName => "a member name must be a string",
            Self::DuplicateName => "this member name appears twice",
            Self::ControlInString => "an unescaped control character in a string",
            Self::BadEscape => "not an escape this grammar has",
            Self::LoneSurrogate => "an unpaired surrogate",
            Self::BadNumber => "not a number this grammar has",
            Self::BadLiteral => "not true, false or null",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Syntax(Syntax),
    Limit(Bound),
    Encoding(Encoding),
}

/// A refusal, and where.
///
/// The position is maintained incrementally as the reader advances, never
/// recovered afterwards by rescanning. A hundred thousand bad lines in a row
/// must cost a hundred thousand times one line, not a hundred thousand times the
/// file, and `tests/hostile.rs` measures the ratio rather than trusting it.
///
/// `AdapterError` in the contracts crate carries `&'static str` only, so a
/// source cannot hand a line number back through `poll`. That is why this type
/// exists and why positions reach an operator through the counters and the
/// anomaly record instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError {
    pub kind: Kind,
    /// 1-based, counting every line in the stream including blank ones.
    pub line: u64,
    /// 0-based byte offset within the line.
    pub byte_in_line: u64,
}

impl JsonError {
    pub fn syntax(s: Syntax, line: u64, byte_in_line: u64) -> Self {
        Self {
            kind: Kind::Syntax(s),
            line,
            byte_in_line,
        }
    }

    pub fn limit(b: Bound, line: u64, byte_in_line: u64) -> Self {
        Self {
            kind: Kind::Limit(b),
            line,
            byte_in_line,
        }
    }

    pub fn encoding(e: Encoding, line: u64, byte_in_line: u64) -> Self {
        Self {
            kind: Kind::Encoding(e),
            line,
            byte_in_line,
        }
    }

    /// Whether this refusal is a bound rather than a defect in the bytes.
    pub fn is_limit(&self) -> bool {
        matches!(self.kind, Kind::Limit(_))
    }
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = match self.kind {
            Kind::Syntax(s) => s.as_str(),
            Kind::Limit(b) => b.as_str(),
            Kind::Encoding(e) => e.as_str(),
        };
        write!(f, "line {} byte {}: {what}", self.line, self.byte_in_line)
    }
}

impl std::error::Error for JsonError {}

pub type JsonResult<T> = Result<T, JsonError>;

/// Every bound, in one place, with the reason next to the number.
///
/// The same discipline as `trailryx_ingest::Config`: a limit written as a
/// literal at the point of use drifts away from its sibling, and the one that
/// was forgotten is the one somebody finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Containers, counting arrays and objects alike.
    ///
    /// A backstop against hostile nesting, and nothing more. It used to be 25 and
    /// to claim it was *derived* from the protobuf reader's own limit of 16, so
    /// that neither OTLP transport would be more permissive than the other about
    /// how deep a payload may be. That derivation cannot be made to work, and an
    /// adversarial review measured it failing in both directions at once: a
    /// resource attribute nested two array levels and three map levels was
    /// refused on the wire and accepted here, while a span attribute nested four
    /// array levels and one map level was accepted on the wire and refused here.
    ///
    /// The reason is arithmetic. The wire counts nested *messages* and charges 2
    /// per `arrayValue` level and 3 per `kvlistValue` level; JSON counts
    /// *containers* and charges 3 and 4. Two different ratios, so no single
    /// container bound matches the message bound for every mix of the two. The
    /// parity now lives where it can be exact, in `trailryx_otlp::otlpjson`, which
    /// counts OTLP message levels the way the wire reader does.
    ///
    /// Which leaves this number free to be what it always should have been: large
    /// enough never to be the binding constraint on anything OTLP admits, small
    /// enough to bound a document designed to exhaust a parser. The deepest
    /// container nesting a wire-legal OTLP value can reach is **27** (an
    /// attribute of a span event, nested five `arrayValue` levels), so 32 leaves
    /// five containers of headroom for a shape the conventions have not produced
    /// yet. Depth costs heap and not stack here, because skipping is iterative,
    /// so the cost of the headroom is a hundred and sixty bytes.
    pub max_depth: usize,

    /// Bytes in one number's literal.
    ///
    /// A `u64` is 20 digits, a nanosecond timestamp 19, a shortest round-trip
    /// `f64` at most 24. A thousand is forty times the widest legal OTLP number.
    /// Jackson's comparable cap is 1000 characters and CPython's is 4300 digits.
    ///
    /// This bound covers a *long* literal and nothing else, and the distinction
    /// matters because the attack that has taken parsers down is short.
    /// `9.223372E+1010671858` is twenty bytes, so no length cap refuses it;
    /// what refuses it is that [`Number`] converts nothing until asked and then
    /// converts by checked integer arithmetic with the exponent clamped, so the
    /// accumulator overflows within twenty steps and returns `None`. The
    /// corpus test caught this doc claiming otherwise.
    pub max_number_bytes: usize,

    /// Members in one object.
    ///
    /// Duplicate detection holds one bounded vector per open object, so this is
    /// also the cost of that check. The widest OTLP/JSON object is a span with
    /// sixteen known members, so 256 is sixteen times the real worst case, and
    /// the whole stack at maximum depth is about 150 KiB. A bounded vector
    /// rather than a hash set is deliberate: there is no seed to attack, and a
    /// precomputed collision set buys an attacker 256 byte comparisons.
    pub max_keys_per_object: usize,

    /// Bytes in one line, enforced while reading rather than after.
    ///
    /// Sixteen mebibytes, exactly `trailryx_ingest::Config::max_body`, so one
    /// JSON line admits the same size of export batch as one decompressed HTTP
    /// body. Enforced on bytes read because the alternative is a multi-gigabyte
    /// stream with no newline in it, and a reader that assembles the line first
    /// has already lost.
    ///
    /// There is deliberately no separate cap on a string: unescaping only ever
    /// shrinks, since `\uXXXX` is six bytes in and at most three out and a
    /// surrogate pair is twelve in and four out, so this bound covers it. A
    /// property test asserts the shrinking rather than assuming it.
    pub max_line_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_number_bytes: 1024,
            max_keys_per_object: 256,
            max_line_bytes: 16 * 1024 * 1024,
        }
    }
}
