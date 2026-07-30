//! The pull reader.
//!
//! Shaped after the protobuf reader next door on purpose: a caller walks the
//! structure it expects and skips what it does not recognise, so `otlpjson.rs`
//! can be read side by side with `otlp.rs` and seen to agree. Nothing builds a
//! tree of the whole document, so the peak memory of reading a line is the line.
//!
//! # What the reader owns, so a caller cannot get it wrong
//!
//! - **Depth.** Counted across every container the caller opens *and* every one
//!   [`Reader::skip_value`] walks past, because a limit that only counts what the
//!   caller noticed is not a limit. A hundred thousand opening brackets in a row
//!   are refused at the twenty-sixth, and cost no stack at all: skipping is
//!   iterative over an explicit stack, never recursive.
//! - **Duplicate member names.** Per object, so `{"a":{"b":1},"a":2}` is caught
//!   and `{"a":{"b":1},"c":{"b":2}}` is not. Compared unescaped and byte for
//!   byte, never Unicode-normalised: `"a\\b"` and `"a\b"` unescape to the same
//!   two-character string and are a duplicate, while an NFC and an NFD spelling
//!   of the same word are two different keys, and a reader that folded them would
//!   be making a linguistic decision about evidence.
//! - **Position.** Maintained as it advances. Recovering it afterwards by
//!   rescanning would make a file of bad lines quadratic, and `tests/hostile.rs`
//!   measures the ratio.
//!
//! # The shape of a walk
//!
//! ```ignore
//! let mut r = Reader::new(line, Limits::default(), line_no);
//! let Event::ObjectStart = r.value()? else { return Err(..) };
//! while let Some(name) = r.next_name()? {
//!     match name.as_ref() {
//!         "resourceSpans" => { /* r.value()?, then next_element() */ }
//!         _ => r.skip_value()?,
//!     }
//! }
//! r.finish()?;
//! ```

use crate::number::{self, Number};
use crate::{Bound, JsonError, JsonResult, Limits, Syntax, lex};
use std::borrow::Cow;

/// What a value turned out to be.
///
/// A container start carries nothing: the caller drives it with
/// [`Reader::next_element`] or [`Reader::next_name`]. There are no `ArrayEnd` or
/// `ObjectEnd` variants for the same reason, so a caller cannot forget to check
/// for one.
#[derive(Debug, Clone, PartialEq)]
pub enum Event<'a> {
    Null,
    Bool(bool),
    Number(Number<'a>),
    Str(Cow<'a, str>),
    ArrayStart,
    ObjectStart,
}

impl Event<'_> {
    /// Whether this event opened a container that still has to be finished.
    pub fn is_container(&self) -> bool {
        matches!(self, Self::ArrayStart | Self::ObjectStart)
    }
}

/// What reading cost, and what was in it that this version does not know.
///
/// `unknown_members` is expected to be non-zero against a newer producer and is
/// worth watching all the same: it is the measure of how much of each line we
/// understood.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Members the caller skipped rather than recognised.
    pub unknown_members: u32,
    /// The deepest nesting reached.
    pub max_depth_seen: u32,
}

#[derive(Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    line: u64,
    limits: Limits,
    /// One frame per open container. An array frame holds no names.
    stack: Vec<Frame>,
    stats: Stats,
    /// Reused across strings, so a line of ten thousand escaped strings does not
    /// allocate ten thousand times.
    scratch: String,
    /// Set once the top-level value is complete, so `finish` can tell "nothing
    /// left" from "never started".
    done: bool,
}

#[derive(Debug)]
struct Frame {
    kind: FrameKind,
    /// Member names seen in this object, unescaped. Bounded by
    /// `Limits::max_keys_per_object`.
    names: Vec<String>,
    /// Whether anything has been read from this container yet, which is what
    /// distinguishes a leading comma from a separating one.
    seen_any: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Array,
    Object,
}

impl<'a> Reader<'a> {
    /// `line` is only carried into error positions; the reader never looks at it.
    pub fn new(bytes: &'a [u8], limits: Limits, line: u64) -> Self {
        Self {
            bytes,
            at: 0,
            line,
            limits,
            stack: Vec::new(),
            stats: Stats::default(),
            scratch: String::new(),
            done: false,
        }
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Byte offset within the line, for a caller building its own error.
    pub fn offset(&self) -> usize {
        self.at
    }

    /// Read the next value, at a position where a value belongs.
    ///
    /// After `ArrayStart` or `ObjectStart` the caller must drive the container to
    /// its close with [`Self::next_element`] or [`Self::next_name`], or abandon it
    /// with [`Self::skip_rest`].
    pub fn value(&mut self) -> JsonResult<Event<'a>> {
        // The whole line is checked for UTF-8 once, here, so nothing below has
        // to think about encoding again. `at == 0` is exactly the first call:
        // `new` starts there and every value consumes at least one byte, so no
        // later call can see zero.
        if self.at == 0 {
            lex::check_utf8(self.bytes, self.line)?;
        }
        self.at = lex::skip_whitespace(self.bytes, self.at);
        if self.done {
            // A second top-level value. Tolerating one is exactly how a
            // synthetic audit record gets appended to a legitimate one.
            return Err(self.err(Syntax::TrailingContent));
        }
        let Some(&first) = self.bytes.get(self.at) else {
            return Err(self.err(Syntax::UnexpectedEof));
        };
        let event = match first {
            b'n' => {
                self.literal(b"null")?;
                Event::Null
            }
            b't' => {
                self.literal(b"true")?;
                Event::Bool(true)
            }
            b'f' => {
                self.literal(b"false")?;
                Event::Bool(false)
            }
            b'"' => {
                let bytes = self.bytes;
                let (line, start) = (self.line, self.at);
                let (text, end) = lex::scan_string(bytes, start, line, &mut self.scratch)?;
                self.at = end;
                Event::Str(text)
            }
            b'-' | b'0'..=b'9' => {
                let (value, used) =
                    number::scan(self.bytes, self.at, self.line, self.limits.max_number_bytes)?;
                self.at += used;
                Event::Number(value)
            }
            b'[' => {
                self.open(FrameKind::Array)?;
                Event::ArrayStart
            }
            b'{' => {
                self.open(FrameKind::Object)?;
                Event::ObjectStart
            }
            b',' => return Err(self.err(Syntax::TrailingComma)),
            b':' => return Err(self.err(Syntax::ExpectedColon)),
            // A number this grammar does not have, rather than a byte that
            // cannot start a value: `+1` and `.5` are numbers to `str::parse`,
            // and `NaN`, `Inf` and `Infinity` are numbers to CPython. Naming
            // them as numbers tells a producer which of its two problems it has.
            // A capitalised `NULL` or `True` is not a number, only the wrong
            // case, and gets the plainer answer below.
            b'+' | b'.' => return Err(self.err(Syntax::BadNumber)),
            b'N' | b'I' if self.spells_a_non_json_float() => {
                return Err(self.err(Syntax::BadNumber));
            }
            _ => return Err(self.err(Syntax::UnexpectedByte)),
        };
        if !event.is_container() && self.stack.is_empty() {
            self.done = true;
        }
        Ok(event)
    }

    fn err(&self, s: Syntax) -> JsonError {
        JsonError::syntax(s, self.line, self.at as u64)
    }

    fn spells_a_non_json_float(&self) -> bool {
        let rest = &self.bytes[self.at..];
        rest.starts_with(b"NaN") || rest.starts_with(b"Inf")
    }

    fn literal(&mut self, word: &[u8]) -> JsonResult<()> {
        if self.bytes[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(())
        } else {
            Err(self.err(Syntax::BadLiteral))
        }
    }

    fn frame_kind(&self) -> Option<FrameKind> {
        self.stack.last().map(|f| f.kind)
    }

    /// Open a container at the current byte.
    ///
    /// The bound is checked before the frame is pushed, so a hundred thousand
    /// opening brackets cost twenty-five frames and one refusal rather than a
    /// hundred thousand allocations.
    fn open(&mut self, kind: FrameKind) -> JsonResult<()> {
        if self.stack.len() >= self.limits.max_depth {
            return Err(JsonError::limit(Bound::Depth, self.line, self.at as u64));
        }
        self.at += 1;
        self.stack.push(Frame {
            kind,
            names: Vec::new(),
            seen_any: false,
        });
        let depth = u32::try_from(self.stack.len()).unwrap_or(u32::MAX);
        if depth > self.stats.max_depth_seen {
            self.stats.max_depth_seen = depth;
        }
        Ok(())
    }

    fn close(&mut self) {
        self.stack.pop();
        if self.stack.is_empty() {
            self.done = true;
        }
    }

    /// After `ArrayStart`: is there another element?
    ///
    /// `true` means a value follows and [`Self::value`] must be called. `false`
    /// means the array closed and its frame is gone.
    pub fn next_element(&mut self) -> JsonResult<bool> {
        // Called with no array open, this is the caller's protocol wrong rather
        // than the document's. It still has to be an error and not a panic: this
        // reader is reached from a fuzz target and from a network path.
        if self.frame_kind() != Some(FrameKind::Array) {
            return Err(self.err(Syntax::UnexpectedByte));
        }
        self.at = lex::skip_whitespace(self.bytes, self.at);
        let Some(&b) = self.bytes.get(self.at) else {
            return Err(self.err(Syntax::UnexpectedEof));
        };
        let seen = self.stack.last().is_some_and(|f| f.seen_any);
        match b {
            b']' => {
                self.at += 1;
                self.close();
                Ok(false)
            }
            // `[,1]`: a comma before anything it could separate.
            b',' if !seen => Err(self.err(Syntax::TrailingComma)),
            b',' => {
                let comma = self.at;
                self.at += 1;
                let next = lex::skip_whitespace(self.bytes, self.at);
                // `[1,]`. Looked for here rather than left to `value`, so the
                // error names the comma and not the bracket.
                if self.bytes.get(next) == Some(&b']') {
                    return Err(JsonError::syntax(
                        Syntax::TrailingComma,
                        self.line,
                        comma as u64,
                    ));
                }
                Ok(true)
            }
            // `[1 2]`: two values with no comma between them.
            _ if seen => Err(self.err(Syntax::UnexpectedByte)),
            _ => {
                if let Some(frame) = self.stack.last_mut() {
                    frame.seen_any = true;
                }
                Ok(true)
            }
        }
    }

    /// After `ObjectStart`: the next member name, or `None` at the closing brace.
    ///
    /// The value follows and must be read or skipped before the next call.
    pub fn next_name(&mut self) -> JsonResult<Option<Cow<'a, str>>> {
        // As in `next_element`: no object open is caller protocol, and it is
        // still an error rather than a panic.
        if self.frame_kind() != Some(FrameKind::Object) {
            return Err(self.err(Syntax::UnexpectedByte));
        }
        self.at = lex::skip_whitespace(self.bytes, self.at);
        let Some(&b) = self.bytes.get(self.at) else {
            return Err(self.err(Syntax::UnexpectedEof));
        };
        let seen = self.stack.last().is_some_and(|f| f.seen_any);
        match b {
            b'}' => {
                self.at += 1;
                self.close();
                return Ok(None);
            }
            b',' if !seen => return Err(self.err(Syntax::TrailingComma)),
            b',' => {
                let comma = self.at;
                self.at += 1;
                self.at = lex::skip_whitespace(self.bytes, self.at);
                // `{"a":1,}`.
                if self.bytes.get(self.at) == Some(&b'}') {
                    return Err(JsonError::syntax(
                        Syntax::TrailingComma,
                        self.line,
                        comma as u64,
                    ));
                }
            }
            // `{"a":1 "b":2}`: two members with no comma between them.
            _ if seen => return Err(self.err(Syntax::UnexpectedByte)),
            _ => {}
        }
        match self.bytes.get(self.at) {
            None => return Err(self.err(Syntax::UnexpectedEof)),
            Some(&b'"') => {}
            Some(_) => return Err(self.err(Syntax::ExpectedName)),
        }
        let name = self.member_name()?;
        self.at = lex::skip_whitespace(self.bytes, self.at);
        match self.bytes.get(self.at) {
            None => return Err(self.err(Syntax::UnexpectedEof)),
            Some(&b':') => self.at += 1,
            Some(_) => return Err(self.err(Syntax::ExpectedColon)),
        }
        Ok(Some(name))
    }

    /// Read a member name and record it against the frame.
    ///
    /// The comparison is byte for byte on the unescaped name, and that is the
    /// whole point. `"a\u0062"` and `"ab"` are one name written two ways and so
    /// are a duplicate, while an NFC and an NFD spelling of the same word are two
    /// different names: folding those would be this crate making a linguistic
    /// decision about evidence.
    fn member_name(&mut self) -> JsonResult<Cow<'a, str>> {
        let bytes = self.bytes;
        let (line, start) = (self.line, self.at);
        let (name, end) = lex::scan_string(bytes, start, line, &mut self.scratch)?;
        self.at = end;
        let limit = self.limits.max_keys_per_object;
        let Some(frame) = self.stack.last_mut() else {
            return Err(JsonError::syntax(
                Syntax::UnexpectedByte,
                line,
                start as u64,
            ));
        };
        // The bound first: it describes the whole object, and a `Limit` tells an
        // operator to raise a number where a `Syntax` tells them to fix bytes.
        if frame.names.len() >= limit {
            return Err(JsonError::limit(Bound::ObjectMembers, line, start as u64));
        }
        if frame
            .names
            .iter()
            .any(|seen| seen.as_str() == name.as_ref())
        {
            return Err(JsonError::syntax(Syntax::DuplicateName, line, start as u64));
        }
        frame.names.push(name.as_ref().to_owned());
        frame.seen_any = true;
        Ok(name)
    }

    /// Skip exactly one value, at a position where a value belongs.
    ///
    /// Counts a skipped member towards [`Stats::unknown_members`]. Iterative, so
    /// depth costs no stack.
    pub fn skip_value(&mut self) -> JsonResult<()> {
        self.stats.unknown_members = self.stats.unknown_members.saturating_add(1);
        let opened = self.value()?;
        self.skip_rest(&opened)
    }

    /// Abandon the container `opened` began, having read some of it.
    ///
    /// A no-op when `opened` was a scalar, so a caller handling "a known member
    /// with the wrong type" can write one line: read the value, and if it is not
    /// what was wanted, hand it back here and count it.
    pub fn skip_rest(&mut self, opened: &Event<'a>) -> JsonResult<()> {
        if !opened.is_container() {
            return Ok(());
        }
        // The frame this has to consume is the innermost one, and the only state
        // the walk needs is how far down to stop. Everything else lives in
        // `self.stack`, on the heap, which is what makes a hundred thousand
        // nested brackets cost no stack: the recursive spelling of this loop is
        // the classic way a parser turns a document into a segmentation fault.
        let floor = self.stack.len();
        while floor > 0 && self.stack.len() >= floor {
            let more = match self.frame_kind() {
                Some(FrameKind::Array) => self.next_element()?,
                Some(FrameKind::Object) => self.next_name()?.is_some(),
                None => break,
            };
            if more {
                // A container here pushes a frame and the next turn of the loop
                // drives that one instead, so nesting costs a frame and not a
                // call.
                self.value()?;
            }
        }
        Ok(())
    }

    /// Nothing but whitespace may remain.
    ///
    /// Two complete values on one line are refused here, and that is not
    /// pedantry: tolerating a second value is exactly how a synthetic audit
    /// record gets appended to a legitimate one. A trailing NUL byte is content.
    pub fn finish(self) -> JsonResult<Stats> {
        if !self.done {
            // Either nothing was ever read, or a container is still open.
            return Err(JsonError::syntax(
                Syntax::UnexpectedEof,
                self.line,
                self.at as u64,
            ));
        }
        let end = lex::skip_whitespace(self.bytes, self.at);
        if end < self.bytes.len() {
            return Err(JsonError::syntax(
                Syntax::TrailingContent,
                self.line,
                end as u64,
            ));
        }
        Ok(self.stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Encoding, Kind};

    const LINE: u64 = 11;

    /// Walk a whole document the way `validate` does.
    fn walk(bytes: &[u8], limits: Limits) -> JsonResult<Stats> {
        let mut reader = Reader::new(bytes, limits, LINE);
        let opened = reader.value()?;
        reader.skip_rest(&opened)?;
        reader.finish()
    }

    fn accepts(src: &str) -> Stats {
        walk(src.as_bytes(), Limits::default()).unwrap_or_else(|e| panic!("{src}: {e}"))
    }

    fn refusal(src: &str) -> Kind {
        walk(src.as_bytes(), Limits::default())
            .expect_err("these bytes must be refused")
            .kind
    }

    /// Run `f` on the stack an ingest request gets.
    ///
    /// 128 KiB. The test harness hands a test thread far more than that, so a
    /// deep-nesting test that ran on the harness's stack would prove nothing
    /// about the claim that skipping is iterative.
    fn on_a_request_sized_stack<T, F>(f: F) -> T
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(f)
            .expect("a thread")
            .join()
            .expect("the walk must fit in a 128 KiB stack")
    }

    #[test]
    fn a_bare_scalar_is_a_document() {
        for src in ["null", "true", "false", "42", "-1.5e3", "\"text\"", " 1 "] {
            accepts(src);
        }
    }

    #[test]
    fn the_four_whitespace_bytes_separate_tokens_and_nothing_else_does() {
        accepts("\t\r\n {\r\n \"a\" \t: [ 1 , 2 ] \n} \t");
        // Form feed, vertical tab, NBSP, U+2028 and the ideographic space are
        // whitespace to one predicate or another and not to JSON.
        for src in [
            "\u{0c}1",
            "[1\u{0c}2]",
            "\u{0b}1",
            "\u{a0}1",
            "\u{2028}1",
            "\u{3000}1",
            "[1,\u{a0}2]",
        ] {
            assert!(
                matches!(refusal(src), Kind::Syntax(_)),
                "{src:?} must be refused"
            );
        }
    }

    #[test]
    fn a_caller_reads_the_members_it_knows_and_skips_the_rest() {
        let src = br#"{"known":7,"unknown":{"a":[1,2,{"b":null}]},"also":"skipped"}"#;
        let mut reader = Reader::new(src, Limits::default(), LINE);
        assert_eq!(reader.value().unwrap(), Event::ObjectStart);
        let mut known = None;
        while let Some(name) = reader.next_name().unwrap() {
            if name == "known" {
                match reader.value().unwrap() {
                    Event::Number(n) => known = n.as_u64(),
                    other => panic!("{other:?}"),
                }
            } else {
                reader.skip_value().unwrap();
            }
        }
        let stats = reader.finish().unwrap();
        assert_eq!(known, Some(7));
        assert_eq!(stats.unknown_members, 2);
        // The containers the skip walked past are counted: object, object,
        // array, object.
        assert_eq!(stats.max_depth_seen, 4);
    }

    #[test]
    fn skipping_a_value_the_caller_started_reading_finishes_it() {
        // The one-line answer to "a known member with the wrong type".
        let src = br#"{"a":[1,2,3],"b":1}"#;
        let mut reader = Reader::new(src, Limits::default(), LINE);
        assert_eq!(reader.value().unwrap(), Event::ObjectStart);
        assert_eq!(reader.next_name().unwrap().as_deref(), Some("a"));
        let opened = reader.value().unwrap();
        assert_eq!(opened, Event::ArrayStart);
        assert!(reader.next_element().unwrap());
        assert_eq!(reader.value().unwrap(), Event::Number(number(b"1")));
        reader.skip_rest(&opened).unwrap();
        assert_eq!(reader.next_name().unwrap().as_deref(), Some("b"));
        reader.skip_value().unwrap();
        assert_eq!(reader.next_name().unwrap(), None);
        reader.finish().unwrap();
    }

    fn number(raw: &[u8]) -> Number<'_> {
        let (value, _) = crate::number::scan(raw, 0, LINE, 1024).unwrap();
        value
    }

    #[test]
    fn skipping_a_scalar_that_was_already_read_is_a_no_op() {
        let mut reader = Reader::new(b"1", Limits::default(), LINE);
        let opened = reader.value().unwrap();
        reader.skip_rest(&opened).unwrap();
        reader.skip_rest(&opened).unwrap();
        reader.finish().unwrap();
    }

    #[test]
    fn a_string_value_arrives_unescaped_and_a_plain_one_is_not_copied() {
        let mut reader = Reader::new(br#"["plain","ab\n"]"#, Limits::default(), LINE);
        assert_eq!(reader.value().unwrap(), Event::ArrayStart);
        assert!(reader.next_element().unwrap());
        assert_eq!(reader.value().unwrap(), Event::Str(Cow::Borrowed("plain")));
        assert!(reader.next_element().unwrap());
        assert_eq!(
            reader.value().unwrap(),
            Event::Str(Cow::Owned("ab\n".into()))
        );
        assert!(!reader.next_element().unwrap());
        reader.finish().unwrap();
    }

    #[test]
    fn the_same_member_name_twice_in_one_object_is_fatal() {
        // Last-wins is CVE-2017-12635: a detail of which parser looked at the
        // document decided who was an administrator.
        for src in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":1,"a":1}"#,
            r#"{"":1,"":2}"#,
            r#"{"a":{"b":1},"a":2}"#,
            r#"{"a":1,"b":2,"a":3}"#,
            r#"[{"b":1,"b":2}]"#,
            r#"{"o":{"b":1,"b":2}}"#,
        ] {
            assert_eq!(refusal(src), Kind::Syntax(Syntax::DuplicateName), "{src}");
        }
    }

    #[test]
    fn names_are_compared_unescaped_so_two_spellings_of_one_name_collide() {
        // The comparison happens after unescaping, so the spelling of a name
        // cannot smuggle a second copy of it past the check.
        for src in [
            r#"{"a\u0062":1,"ab":2}"#,
            r#"{"\u0061\u0062":1,"ab":2}"#,
            r#"{"a\\b":1,"a\u005cb":2}"#,
            r#"{"a\/b":1,"a\u002fb":2}"#,
            "{\"\\u00e9\":1,\"\u{e9}\":2}",
        ] {
            assert_eq!(refusal(src), Kind::Syntax(Syntax::DuplicateName), "{src}");
        }
    }

    #[test]
    fn an_nfc_and_an_nfd_spelling_are_two_names_and_are_not_folded() {
        // Deciding these are one key would be this crate making a linguistic
        // judgement about evidence.
        accepts("{\"\u{e9}\":1,\"e\u{301}\":2}");
        accepts("{\"\u{fb01}\":1,\"fi\":2}");
        // Case is not folded either.
        accepts(r#"{"a":1,"A":2}"#);
    }

    #[test]
    fn the_duplicate_check_is_per_object_and_not_per_document() {
        accepts(r#"{"a":{"b":1},"c":{"b":2}}"#);
        accepts(r#"[{"b":1},{"b":2}]"#);
        accepts(r#"{"a":[{"x":1},{"x":2}],"b":{"x":3}}"#);
    }

    #[test]
    fn nesting_is_accepted_at_the_bound_and_refused_one_past_it() {
        let limits = Limits::default();
        // Derived from the default rather than written down again, so moving the
        // bound is one edit. What the test pins is the property, not the number:
        // the bound itself is accepted and one past it is refused.
        let bound = limits.max_depth;
        let deepest = format!("{}{}", "[".repeat(bound), "]".repeat(bound));
        assert_eq!(accepts(&deepest).max_depth_seen, bound as u32);
        let one_too_deep = format!("{}{}", "[".repeat(bound + 1), "]".repeat(bound + 1));
        let err = walk(one_too_deep.as_bytes(), limits).unwrap_err();
        assert_eq!(err.kind, Kind::Limit(Bound::Depth));
        assert_eq!(
            err.byte_in_line, bound as u64,
            "the bracket that was refused"
        );
        // Objects cost the same as arrays, and a mixture counts as both.
        let mixed = "[{\"a\":".repeat(limits.max_depth);
        assert_eq!(
            walk(mixed.as_bytes(), limits).unwrap_err().kind,
            Kind::Limit(Bound::Depth)
        );
    }

    #[test]
    fn a_hundred_thousand_opening_brackets_are_a_bound_and_cost_no_stack() {
        let err = on_a_request_sized_stack(|| {
            let bytes = vec![b'['; 100_000];
            walk(&bytes, Limits::default()).expect_err("depth 100000 is past the bound")
        });
        // A bound and not a syntax error, even though the document is also
        // truncated: depth is reached one bracket past the bound, long before the
        // missing close.
        assert_eq!(err.kind, Kind::Limit(Bound::Depth));
        assert_eq!(err.byte_in_line, Limits::default().max_depth as u64);
    }

    #[test]
    fn a_hundred_thousand_nested_arrays_walk_iteratively_when_the_bound_allows() {
        // The claim under test is that depth costs heap and not stack. With the
        // recursive spelling of `skip_rest` this overflows and the process dies.
        let stats = on_a_request_sized_stack(|| {
            let depth = 100_000;
            let mut bytes = vec![b'['; depth];
            bytes.resize(depth * 2, b']');
            let limits = Limits {
                max_depth: depth + 1,
                ..Limits::default()
            };
            walk(&bytes, limits).expect("a balanced document inside the bound")
        });
        assert_eq!(stats.max_depth_seen, 100_000);
    }

    #[test]
    fn an_object_is_accepted_at_the_member_bound_and_refused_one_past_it() {
        fn object(members: usize) -> String {
            let mut src = String::from("{");
            for i in 0..members {
                if i > 0 {
                    src.push(',');
                }
                src.push_str(&format!("\"k{i}\":0"));
            }
            src.push('}');
            src
        }
        assert_eq!(Limits::default().max_keys_per_object, 256);
        accepts(&object(256));
        assert_eq!(
            refusal(&object(257)),
            Kind::Limit(Bound::ObjectMembers),
            "the 257th member"
        );
        // The bound is per object, so two objects of 256 are not 512.
        accepts(&format!("[{},{}]", object(256), object(256)));
    }

    #[test]
    fn a_number_past_the_length_bound_is_a_limit_inside_a_document_too() {
        let long = format!("[{}]", "1".repeat(1025));
        assert_eq!(refusal(&long), Kind::Limit(Bound::NumberDigits));
        let at_the_bound = format!("[{}]", "1".repeat(1024));
        accepts(&at_the_bound);
    }

    #[test]
    fn content_after_a_complete_value_is_refused_including_a_trailing_nul() {
        for (src, at) in [
            ("1 2", 2),
            ("{\"a\":1} {\"b\":2}", 8),
            ("[1][2]", 3),
            ("[1] // ok", 4),
            ("{\"a\":1}\u{0}", 7),
            ("true\u{0}", 4),
            ("null null", 5),
            ("[1]\r[2]", 4),
        ] {
            let err = walk(src.as_bytes(), Limits::default()).unwrap_err();
            assert_eq!(err.kind, Kind::Syntax(Syntax::TrailingContent), "{src:?}");
            assert_eq!(err.byte_in_line, at, "{src:?}");
        }
    }

    #[test]
    fn a_second_call_to_value_after_a_complete_document_is_refused() {
        let mut reader = Reader::new(b"1 2", Limits::default(), LINE);
        assert_eq!(reader.value().unwrap(), Event::Number(number(b"1")));
        assert_eq!(
            reader.value().unwrap_err().kind,
            Kind::Syntax(Syntax::TrailingContent)
        );
    }

    #[test]
    fn an_empty_or_whitespace_only_document_ends_where_a_value_belongs() {
        for src in ["", " ", "\t", "\r\n", "   \t\r\n  "] {
            assert_eq!(refusal(src), Kind::Syntax(Syntax::UnexpectedEof), "{src:?}");
        }
    }

    #[test]
    fn a_document_that_ends_inside_a_container_is_refused() {
        for src in [
            "[",
            "[1",
            "[1,",
            "{",
            "{\"a\"",
            "{\"a\":",
            "{\"a\":1",
            "{\"a\":1,",
            "[[1]",
        ] {
            assert_eq!(refusal(src), Kind::Syntax(Syntax::UnexpectedEof), "{src:?}");
        }
    }

    #[test]
    fn finishing_with_a_container_still_open_is_not_a_clean_document() {
        let mut reader = Reader::new(b"[1]", Limits::default(), LINE);
        assert_eq!(reader.value().unwrap(), Event::ArrayStart);
        assert_eq!(
            reader.finish().unwrap_err().kind,
            Kind::Syntax(Syntax::UnexpectedEof)
        );
    }

    #[test]
    fn every_way_of_getting_the_punctuation_wrong_is_named() {
        for (src, want) in [
            ("[1,]", Syntax::TrailingComma),
            ("{\"a\":1,}", Syntax::TrailingComma),
            ("[,1]", Syntax::TrailingComma),
            ("{,\"a\":1}", Syntax::TrailingComma),
            ("[1,,2]", Syntax::TrailingComma),
            ("[,]", Syntax::TrailingComma),
            (",", Syntax::TrailingComma),
            ("{\"a\":,}", Syntax::TrailingComma),
            ("{\"a\" 1}", Syntax::ExpectedColon),
            ("{\"a\"::1}", Syntax::ExpectedColon),
            ("{\"a\",1}", Syntax::ExpectedColon),
            (":", Syntax::ExpectedColon),
            ("{:\"a\"}", Syntax::ExpectedName),
            ("{1:2}", Syntax::ExpectedName),
            ("{a:1}", Syntax::ExpectedName),
            ("[1 2]", Syntax::UnexpectedByte),
            ("{\"a\":1 \"b\":2}", Syntax::UnexpectedByte),
            ("]", Syntax::UnexpectedByte),
            ("}", Syntax::UnexpectedByte),
            ("[1:2]", Syntax::UnexpectedByte),
            ("*", Syntax::UnexpectedByte),
            ("/* c */1", Syntax::UnexpectedByte),
            ("'a'", Syntax::UnexpectedByte),
            ("\u{0}1", Syntax::UnexpectedByte),
            ("nul", Syntax::BadLiteral),
            ("tru", Syntax::BadLiteral),
            ("nulll", Syntax::TrailingContent),
            ("True", Syntax::UnexpectedByte),
            ("NULL", Syntax::UnexpectedByte),
            ("bare", Syntax::UnexpectedByte),
            ("[NaN]", Syntax::BadNumber),
            ("[Infinity]", Syntax::BadNumber),
            ("[Inf]", Syntax::BadNumber),
            ("[-NaN]", Syntax::BadNumber),
            ("[-Infinity]", Syntax::BadNumber),
            ("[+1]", Syntax::BadNumber),
            ("[.5]", Syntax::BadNumber),
            ("[1_000]", Syntax::BadNumber),
            ("[0x1f]", Syntax::BadNumber),
        ] {
            assert_eq!(refusal(src), Kind::Syntax(want), "{src:?}");
        }
    }

    #[test]
    fn a_closing_bracket_of_the_wrong_kind_does_not_close_the_container() {
        assert!(matches!(refusal("[1}"), Kind::Syntax(_)));
        assert!(matches!(refusal("{\"a\":1]"), Kind::Syntax(_)));
        assert!(matches!(refusal("[}"), Kind::Syntax(_)));
        assert!(matches!(refusal("{]"), Kind::Syntax(_)));
    }

    #[test]
    fn the_whole_line_is_checked_for_utf8_before_the_grammar_sees_any_of_it() {
        // Where the bad byte sits does not change the class, and that is the
        // point: a reader that checked strings only would report a bad escape
        // or content after the value for these.
        for (bytes, at) in [
            (b"\x80".as_slice(), 0),
            (b"[\"a\xc0\xaf\"]", 3),
            (b"[\"\xed\xa0\x80\"]", 2),
            (b"[\xf4\xbf\xbf\xbf]", 1),
            (b"[1\xff]", 2),
            (b"[1e\xff9]", 3),
            (b"[\"a\\\xff\"]", 4),
            (b"{\"\xff\":1}", 2),
            (b"1\xff", 1),
            (b"[1] \xff", 4),
        ] {
            let err = walk(bytes, Limits::default()).unwrap_err();
            assert_eq!(err.kind, Kind::Encoding(Encoding::InvalidUtf8), "{bytes:?}");
            assert_eq!(err.byte_in_line, at, "{bytes:?}");
            assert_eq!(err.line, LINE, "{bytes:?}");
        }
    }

    #[test]
    fn a_position_is_carried_rather_than_recovered_by_rescanning() {
        let mut reader = Reader::new(b"  [1,22]", Limits::default(), LINE);
        assert_eq!(reader.offset(), 0);
        reader.value().unwrap();
        assert_eq!(reader.offset(), 3);
        assert!(reader.next_element().unwrap());
        reader.value().unwrap();
        assert_eq!(reader.offset(), 4);
        assert!(reader.next_element().unwrap());
        reader.value().unwrap();
        assert_eq!(reader.offset(), 7);
        assert!(!reader.next_element().unwrap());
        assert_eq!(reader.offset(), 8);
    }

    #[test]
    fn an_error_carries_the_line_the_caller_gave_it() {
        let err = walk(b"[1,]", Limits::default()).unwrap_err();
        assert_eq!(err.line, LINE);
        assert_eq!(err.byte_in_line, 2);
        assert_eq!(
            err.to_string(),
            "line 11 byte 2: a comma where a value belongs"
        );
    }

    #[test]
    fn an_empty_container_is_a_container() {
        assert_eq!(accepts("[]").max_depth_seen, 1);
        assert_eq!(accepts("{}").max_depth_seen, 1);
        assert_eq!(accepts("[[],{}]").max_depth_seen, 2);
        assert_eq!(accepts("[ ]").max_depth_seen, 1);
        assert_eq!(accepts("{ }").max_depth_seen, 1);
    }

    #[test]
    fn stats_count_what_a_walk_did_not_understand() {
        let stats = accepts(r#"{"a":1}"#);
        // A generic walk recognises nothing and skips nothing: `skip_rest` reads
        // the members rather than skipping them.
        assert_eq!(stats.unknown_members, 0);
        let mut reader = Reader::new(br#"[1,{"a":2}]"#, Limits::default(), LINE);
        reader.value().unwrap();
        assert!(reader.next_element().unwrap());
        reader.skip_value().unwrap();
        assert!(reader.next_element().unwrap());
        reader.skip_value().unwrap();
        assert!(!reader.next_element().unwrap());
        let stats = reader.finish().unwrap();
        assert_eq!(stats.unknown_members, 2);
        assert_eq!(stats.max_depth_seen, 2);
    }

    #[test]
    fn there_is_no_bound_on_elements_in_one_array() {
        // Only objects have a member cap, because only objects pay for
        // duplicate detection.
        let src = format!("[{}]", "1,".repeat(999));
        accepts(&format!("{}1]", &src[..src.len() - 1]));
        let thousand = format!("[{}1]", "1,".repeat(999));
        accepts(&thousand);
    }

    #[test]
    fn a_raw_control_character_in_a_member_name_is_refused_like_any_string() {
        assert_eq!(
            refusal("{\"a\nb\":1}"),
            Kind::Syntax(Syntax::ControlInString)
        );
        assert_eq!(
            refusal("{\"a\":\"b\rc\"}"),
            Kind::Syntax(Syntax::ControlInString)
        );
    }

    #[test]
    fn a_lone_surrogate_in_a_member_name_is_refused_like_any_string() {
        assert_eq!(
            refusal(r#"{"\ud888":1}"#),
            Kind::Syntax(Syntax::LoneSurrogate)
        );
    }
}
