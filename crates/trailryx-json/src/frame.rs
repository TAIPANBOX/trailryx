//! Lines.
//!
//! Turning a stream of arbitrary read sizes into lines is where a JSON Lines
//! reader actually goes wrong, so the rules are written down and each one is a
//! choice with a consequence rather than a convention.
//!
//! - **The separator is LF.** A CR immediately before it is part of the
//!   terminator. A **lone CR is not a separator**: it is JSON whitespace between
//!   tokens, and inside a string it is an unescaped control character and
//!   therefore an error. So `{"a":1}\r{"a":2}` is *one* line that fails, never
//!   two records. A framer that split on a lone CR would let a value containing
//!   one manufacture a record.
//! - **The final line needs no LF.** A file whose last byte is `}` is complete.
//!   But an *unterminated* final line is reported separately from a malformed
//!   one, because a live file being appended to by a collector that flushes on a
//!   timer is unterminated most of the time, and calling that corruption would
//!   make every tail read look like an incident.
//! - **A blank line is skipped and counted**, and the line number still advances,
//!   so a position in an error still matches what an operator sees in an editor.
//!   Not configurable: a reader whose behaviour on the same bytes depends on a
//!   flag is not deterministic, and determinism is in the pre-push gate.
//! - **One byte-order mark, at absolute offset zero only.** Anywhere else it is
//!   bytes inside a line and therefore a syntax error.
//! - **A UTF-16 or UTF-32 stream is named, not decoded, and the refusal is
//!   latched.** Half-reading UTF-16LE as ASCII is worse than refusing it, because
//!   the interleaved NULs make it look like a truncated ASCII document rather than
//!   the wrong encoding. Latched because the first version refused the mark from
//!   inside the opening path and dropped the rest of that chunk unframed, so how
//!   much of a file reached the store was a function of the read size: measured,
//!   the same forty-kilobyte file behind a UTF-16 mark gave 0 records at a 64 KiB
//!   read and 199 at a two-byte read, and every run reported one or two lost
//!   lines. A stream that is UTF-16 is not a stream with a bad first line.
//! - **The length cap is enforced on bytes read**, not after the line is
//!   assembled. The alternative is a multi-gigabyte stream with no newline in it,
//!   and a framer that assembles first has already lost. On breach: discard to
//!   the next LF, count it, keep reading.
//!
//! # Chunk invariance
//!
//! The framer must produce the same lines regardless of how the bytes were
//! handed to it. That is the single highest-value property here, because the
//! classic bugs all live on a boundary: a chunk that ends between the CR and the
//! LF, or in the middle of a three-byte character, or between the `\u00` and the
//! `41` of an escape. `tests/frame.rs` feeds every fixture at chunk sizes 1, 2,
//! 3, 5, 7, 13, 64, 4096 and 65536 and asserts the results are identical.

use crate::{Encoding, JsonError, JsonResult, Limits};

/// One line, ready to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line<'a> {
    /// The bytes between terminators, with no BOM and no CR or LF.
    pub bytes: &'a [u8],
    /// 1-based, counting blank lines.
    pub number: u64,
    /// Absolute byte offset of the first byte of the line in the stream.
    pub offset: u64,
}

/// What the framing saw that was not a line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameReport {
    /// Empty, or only spaces and tabs. Skipped.
    pub blank_lines: u64,
    /// Over [`Limits::max_line_bytes`], discarded to the next LF.
    pub oversize_lines: u64,
    /// A byte-order mark was present at offset 0 and skipped.
    pub leading_bom: bool,
}

/// Feed bytes, take lines.
///
/// Holds at most one partial line, bounded by [`Limits::max_line_bytes`], which
/// makes the peak memory of the whole reader one line plus one read buffer.
#[derive(Debug)]
pub struct Framer {
    limits: Limits,
    /// The partial line carried from the previous chunk.
    carry: Vec<u8>,
    line_no: u64,
    /// Absolute offset of the next byte to be consumed.
    offset: u64,
    /// Set while discarding an oversize line, until the next LF.
    discarding: bool,
    /// A mark at offset zero said this stream is not UTF-8, so nothing in it can
    /// be read and every later call says so again.
    ///
    /// Latched, and that is the whole point. It used to return the error from the
    /// middle of `open_stream` before the chunk had been framed or accounted for,
    /// so `push` dropped that chunk whole and the caller carried on with the next
    /// one. An adversarial review measured what that means for a caller: the same
    /// forty-kilobyte file behind a UTF-16 mark admitted 0 records at a 64 KiB
    /// read, 118 at 16 KiB, 179 at 4 KiB and 199 at a two-byte read, and every one
    /// of those runs reported one or two lost lines. How much of a file reaches an
    /// audit store must not be a function of the read size.
    refused: Option<Encoding>,
    /// Absolute offset zero has not been passed yet, so a BOM is still possible.
    at_start: bool,
    report: FrameReport,
}

impl Framer {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            carry: Vec::new(),
            line_no: 0,
            offset: 0,
            discarding: false,
            refused: None,
            at_start: true,
            report: FrameReport::default(),
        }
    }

    pub fn report(&self) -> FrameReport {
        self.report
    }

    /// Bytes held in the partial line. Asserted bounded by the hostile tests.
    pub fn carried(&self) -> usize {
        self.carry.len()
    }

    /// How many lines have ended so far, so the line being read is this plus one.
    ///
    /// Written this way round because that is what an error position needs: a
    /// refusal happens on a line that has not ended yet, and a counter of
    /// finished lines is the only one both an error and a `Line` can be derived
    /// from without the two disagreeing by one.
    pub fn line_no(&self) -> u64 {
        self.line_no
    }

    /// Detect a byte-order mark that says this is not UTF-8.
    ///
    /// Checked before anything else and only at absolute offset zero. A BOM-less
    /// UTF-16LE stream is not detected here and does not need to be: it begins
    /// `{\0` and fails closed on the NUL, which is outside a string and therefore
    /// a syntax error rather than a mis-read.
    pub fn sniff_encoding(first: &[u8]) -> Option<Encoding> {
        if first.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
            return Some(Encoding::Utf32Be);
        }
        if first.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
            return Some(Encoding::Utf32Le);
        }
        if first.starts_with(&[0xFE, 0xFF]) {
            return Some(Encoding::Utf16Be);
        }
        if first.starts_with(&[0xFF, 0xFE]) {
            return Some(Encoding::Utf16Le);
        }
        None
    }

    /// Take a chunk. Calls `on_line` for each complete line it produced.
    ///
    /// A callback rather than an iterator because the lines borrow from either
    /// the chunk or the carry buffer, and an iterator holding both would need a
    /// lifetime the caller cannot satisfy while also feeding the next chunk.
    ///
    /// Returns an error only for an encoding the stream cannot be: a malformed
    /// *line* is the caller's business and is reported per line.
    ///
    /// An error from `on_line` is passed straight back and stops this chunk where
    /// the refused line ended: the bytes after it are not framed. A caller that
    /// wants to keep reading past a bad line returns `Ok` and records the refusal
    /// itself, which is what the per-line reporting above means.
    pub fn push<F>(&mut self, chunk: &[u8], mut on_line: F) -> JsonResult<()>
    where
        F: FnMut(Line<'_>) -> JsonResult<()>,
    {
        // The latch first, so a refused stream frames nothing at any read size
        // rather than framing whatever happened to follow the mark in this chunk.
        if let Some(e) = self.refused {
            return Err(self.encoding_error(e));
        }
        let mut rest = chunk;
        if self.at_start {
            rest = self.open_stream(rest)?;
        }

        while !rest.is_empty() {
            if self.discarding {
                match find_lf(rest) {
                    Some(at) => {
                        self.advance(at + 1);
                        rest = &rest[at + 1..];
                        self.discarding = false;
                        // The refused line still occupied a line number. Skipping
                        // it here would put every later position one line off
                        // against what an operator sees in an editor, which is the
                        // whole point of counting blank lines too.
                        self.line_no = self.line_no.saturating_add(1);
                    }
                    None => {
                        self.advance(rest.len());
                        rest = &[];
                    }
                }
                continue;
            }

            // Only the bytes that could still fit under the cap are searched. An
            // LF past that point cannot rescue the line, so scanning a 64 MiB
            // chunk to its end before deciding is work that buys nothing.
            let room = self.limits.max_line_bytes.saturating_sub(self.carry.len());
            let window = &rest[..rest.len().min(room.saturating_add(1))];

            match find_lf(window) {
                Some(at) => {
                    // `at <= room`, so this line is within the cap.
                    let start = self.offset.saturating_sub(self.carry.len() as u64);
                    self.advance(at + 1);
                    let after = &rest[at + 1..];
                    self.line_no = self.line_no.saturating_add(1);
                    let number = self.line_no;

                    if self.carry.is_empty() {
                        // The whole line is in this chunk, so it is handed over
                        // borrowed. Copying every line would double the cost of
                        // the case that is almost all of them.
                        let mut bytes = &rest[..at];
                        if let [head @ .., b'\r'] = bytes {
                            bytes = head;
                        }
                        if is_blank(bytes) {
                            self.report.blank_lines = self.report.blank_lines.saturating_add(1);
                        } else {
                            on_line(Line {
                                bytes,
                                number,
                                offset: start,
                            })?;
                        }
                    } else {
                        self.carry.extend_from_slice(&rest[..at]);
                        if self.carry.last() == Some(&b'\r') {
                            self.carry.pop();
                        }
                        let handed = if is_blank(&self.carry) {
                            self.report.blank_lines = self.report.blank_lines.saturating_add(1);
                            Ok(())
                        } else {
                            on_line(Line {
                                bytes: &self.carry,
                                number,
                                offset: start,
                            })
                        };
                        // Cleared before a refusal escapes, so a caller that keeps
                        // going is never handed this line a second time.
                        self.carry.clear();
                        handed?;
                    }
                    rest = after;
                }
                None if rest.len() > room => {
                    // The cap is on bytes read, so the line is refused here having
                    // held at most `max_line_bytes` of it, and the remainder is
                    // dropped up to the next LF rather than assembled first.
                    self.report.oversize_lines = self.report.oversize_lines.saturating_add(1);
                    self.carry.clear();
                    self.discarding = true;
                    self.advance(window.len());
                    rest = &rest[window.len()..];
                }
                None => {
                    self.carry.extend_from_slice(rest);
                    self.advance(rest.len());
                    rest = &[];
                }
            }
        }
        Ok(())
    }

    /// End of stream.
    ///
    /// If a partial line is held, it is a complete line with no terminator and is
    /// handed over. `unterminated` tells the caller which happened, so a live
    /// tail can distinguish "the producer has not flushed the newline yet" from
    /// "this file ends here".
    pub fn finish<F>(&mut self, mut on_line: F) -> JsonResult<bool>
    where
        F: FnMut(Line<'_>) -> JsonResult<()>,
    {
        // Same latch as `push`, so a refused stream answers the same way however
        // many times it is asked and whatever order the asking happened in.
        if let Some(e) = self.refused {
            return Err(self.encoding_error(e));
        }
        if self.at_start {
            // No more bytes are coming, so a held prefix is all there will ever
            // be: a stream of exactly `FF FE` is UTF-16LE, not a wait for two
            // bytes that never arrive. A truncated `EF BB` is not a mark and
            // stays as line content, because two bytes are not a BOM.
            self.at_start = false;
            if let Some(e) = Self::sniff_encoding(&self.carry) {
                self.refused = Some(e);
                return Err(self.encoding_error(e));
            }
        }

        if self.discarding {
            // The oversize line was counted when it breached. It ended without a
            // terminator, and a tail reader is told so: pending bytes mean the
            // producer is mid-write, whether or not they were usable.
            self.discarding = false;
            self.line_no = self.line_no.saturating_add(1);
            return Ok(true);
        }

        if self.carry.is_empty() {
            return Ok(false);
        }

        // A CR here is content and not half a terminator, because no LF follows
        // it. Stripping it would edit the bytes a later flush is going to
        // complete.
        let start = self.offset.saturating_sub(self.carry.len() as u64);
        self.line_no = self.line_no.saturating_add(1);
        let number = self.line_no;
        let handed = if is_blank(&self.carry) {
            self.report.blank_lines = self.report.blank_lines.saturating_add(1);
            Ok(())
        } else {
            on_line(Line {
                bytes: &self.carry,
                number,
                offset: start,
            })
        };
        // Cleared whatever the caller said, so a second `finish` cannot hand the
        // same tail over twice.
        self.carry.clear();
        handed?;
        Ok(true)
    }

    /// Resolve the first bytes of the stream, once.
    ///
    /// Returns the bytes left to frame. A prefix that could still turn out to be
    /// either of two marks is held in the carry: every such prefix is at most
    /// three bytes and none of them contains an LF, so holding it cannot hide a
    /// line break or grow the carry past its bound.
    ///
    /// A refusal here is about the stream and not about a line, so the framer
    /// does not try to resynchronise afterwards. A caller that ignores it and
    /// keeps pushing gets the mark bytes as line content, which the reader then
    /// refuses as bytes that are not JSON.
    fn open_stream<'c>(&mut self, chunk: &'c [u8]) -> JsonResult<&'c [u8]> {
        let mut head = [0u8; 4];
        let mut len = 0;
        for (slot, &b) in head.iter_mut().zip(self.carry.iter().chain(chunk)) {
            *slot = b;
            len += 1;
        }
        let head = &head[..len];

        if partial_mark(head) {
            self.carry.extend_from_slice(chunk);
            self.advance(chunk.len());
            return Ok(&[]);
        }
        self.at_start = false;

        if let Some(e) = Self::sniff_encoding(head) {
            // Nothing is consumed and nothing is framed: `offset` does not move,
            // the carry is left alone, and the latch makes every later call
            // report the same refusal. A stream that is UTF-16 is not a stream
            // with a bad first line.
            self.refused = Some(e);
            return Err(self.encoding_error(e));
        }

        if head.starts_with(BOM_UTF8) {
            // One mark, and only here. The `head` was built from the carry first,
            // so part of it may already have been held from an earlier chunk.
            self.report.leading_bom = true;
            let from_chunk = BOM_UTF8.len().saturating_sub(self.carry.len());
            self.carry.clear();
            self.advance(from_chunk);
            return Ok(&chunk[from_chunk..]);
        }

        Ok(chunk)
    }

    /// Offsets are maintained as bytes are consumed, never recovered afterwards
    /// by rescanning: a file of a hundred thousand refused lines must cost a
    /// hundred thousand lines and not a hundred thousand files.
    fn advance(&mut self, n: usize) {
        self.offset = self.offset.saturating_add(n as u64);
    }

    /// The error this module raises, so the implementation cannot invent another.
    fn encoding_error(&self, e: Encoding) -> JsonError {
        JsonError::encoding(e, self.line_no.saturating_add(1), 0)
    }
}

/// The UTF-8 mark, which is skipped rather than refused.
const BOM_UTF8: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Every mark a stream can begin with, in the form the framer has to reason
/// about: a *prefix* of one of these is not yet a verdict.
const MARKS: [&[u8]; 5] = [
    &[0x00, 0x00, 0xFE, 0xFF],
    &[0xFF, 0xFE, 0x00, 0x00],
    &[0xFE, 0xFF],
    &[0xFF, 0xFE],
    BOM_UTF8,
];

/// Whether more bytes could still change what `head` says.
///
/// `FF FE` is a complete UTF-16LE mark and also the first half of the UTF-32LE
/// one, so answering on two bytes names the wrong encoding for a stream handed
/// over one byte at a time, and that is a chunk-invariance bug that only shows
/// up on a slow pipe.
fn partial_mark(head: &[u8]) -> bool {
    MARKS
        .iter()
        .any(|m| m.len() > head.len() && m.starts_with(head))
}

/// Empty, or only spaces and tabs.
///
/// Deliberately not "any JSON whitespace": a CR or an LF cannot reach here, and
/// treating anything else as blank would silently drop a line with content in it.
fn is_blank(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, b' ' | b'\t'))
}

fn find_lf(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&b| b == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Kind, Syntax};

    /// The chunk sizes every fixture is fed at. Small primes catch a boundary
    /// landing inside a terminator or a character, and the large ones are the read
    /// sizes a real caller uses.
    const SIZES: [usize; 9] = [1, 2, 3, 5, 7, 13, 64, 4096, 65536];

    /// Everything one run of the framer produced, so a comparison across chunk
    /// sizes cannot pass by comparing only the easy half of it.
    #[derive(Debug, PartialEq, Eq)]
    struct Framed {
        /// Bytes, line number and offset of each line handed over, in order.
        lines: Vec<(Vec<u8>, u64, u64)>,
        report: FrameReport,
        unterminated: bool,
        line_no: u64,
    }

    fn no_lines(l: Line<'_>) -> JsonResult<()> {
        panic!("no line was expected here, got {l:?}");
    }

    fn frame_chunks(chunks: &[&[u8]], limits: Limits) -> JsonResult<Framed> {
        let mut f = Framer::new(limits);
        let mut lines = Vec::new();
        let unterminated = {
            let mut sink = |l: Line<'_>| -> JsonResult<()> {
                lines.push((l.bytes.to_vec(), l.number, l.offset));
                Ok(())
            };
            for c in chunks {
                f.push(c, &mut sink)?;
            }
            f.finish(&mut sink)?
        };
        Ok(Framed {
            lines,
            report: f.report(),
            unterminated,
            line_no: f.line_no(),
        })
    }

    fn by_size(input: &[u8], size: usize, limits: Limits) -> JsonResult<Framed> {
        let chunks: Vec<&[u8]> = input.chunks(size.max(1)).collect();
        frame_chunks(&chunks, limits)
    }

    fn whole(input: &[u8], limits: Limits) -> JsonResult<Framed> {
        frame_chunks(&[input], limits)
    }

    /// Split `input` at the given absolute offsets, dropping empty pieces.
    fn split_at<'a>(input: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        let mut at = 0;
        for &c in cuts {
            out.push(&input[at..c]);
            at = c;
        }
        out.push(&input[at..]);
        out.retain(|piece| !piece.is_empty());
        out
    }

    /// Streams with no encoding refusal in them, so every one can be compared
    /// across chunk sizes as a whole result.
    fn fixtures() -> Vec<&'static [u8]> {
        vec![
            b"",
            b"\n",
            b"{}",
            b"{\"a\":1}\n{\"a\":2}\n",
            b"{\"a\":1}\r\n{\"a\":2}\r\n{\"a\":3}",
            b"{\"a\":1}\n\n  \n\t\n{\"a\":2}",
            b"{\"a\":1}\r{\"a\":2}\n",
            b"\r\n\r\n{}\n",
            b"\xEF\xBB\xBF{\"a\":1}\n{\"b\":2}\n",
            b"{}\n\xEF\xBB\xBF{}\n",
            b"\xEF\xBB\xBF\xEF\xBB\xBF{}\n",
            b"{\"s\":\"\xC3\xA9\xE2\x82\xAC\xF0\x9D\x84\x9E\"}\n{\"t\":\"\\u0041\"}\n",
            b"{}\r",
            b"{}\n   ",
            b"\xEF\xBB",
        ]
    }

    #[test]
    fn the_same_bytes_at_any_chunk_size_produce_the_same_lines() {
        for input in fixtures() {
            let want = whole(input, Limits::default()).expect("no mark in these fixtures");
            for size in SIZES {
                let got = by_size(input, size, Limits::default()).expect("no mark");
                assert_eq!(got, want, "chunk size {size} on {input:?}");
            }
        }
    }

    #[test]
    fn the_same_bytes_at_any_chunk_size_refuse_the_same_oversize_lines() {
        // A cap small enough that the refusal lands in the middle of the sweep
        // rather than needing sixteen mebibytes of fixture.
        let limits = Limits {
            max_line_bytes: 8,
            ..Limits::default()
        };
        let inputs: [&[u8]; 5] = [
            b"12345678\n123456789\n12345678\n",
            b"123456789012345678901234567890\n{}\n",
            b"{}\n1234567890",
            b"1234567\r\n12345678\r\n",
            b"12345678\r\n",
        ];
        for input in inputs {
            let want = whole(input, limits).expect("no mark");
            for size in SIZES {
                let got = by_size(input, size, limits).expect("no mark");
                assert_eq!(got, want, "chunk size {size} on {input:?}");
            }
        }
    }

    #[test]
    fn a_boundary_between_the_cr_and_the_lf_of_every_crlf_changes_nothing() {
        let input: &[u8] = b"{\"a\":1}\r\n\r\n{\"b\":2}\r\n{\"c\":3}\r\n";
        let cuts: Vec<usize> = (0..input.len() - 1)
            .filter(|&i| input[i] == b'\r' && input[i + 1] == b'\n')
            .map(|i| i + 1)
            .collect();
        assert_eq!(cuts.len(), 4, "the fixture must have four CRLFs");
        let got = frame_chunks(&split_at(input, &cuts), Limits::default()).expect("no mark");
        assert_eq!(got, whole(input, Limits::default()).expect("no mark"));
        assert_eq!(got.lines.len(), 3);
        assert_eq!(got.report.blank_lines, 1);
    }

    #[test]
    fn a_boundary_inside_a_multibyte_character_or_an_escape_is_invisible() {
        // Two, three and four byte characters, and a `\u0041` whose `\u00` and
        // `41` end up in different chunks.
        let input = "{\"e\":\"é\",\"c\":\"€\",\"g\":\"𝄞\"}\n{\"a\":\"\\u0041\"}\n".as_bytes();
        assert!(input.windows(4).any(|w| w == br"\u00"));
        let want = whole(input, Limits::default()).expect("no mark");
        for cut in 1..input.len() {
            let got = frame_chunks(&split_at(input, &[cut]), Limits::default()).expect("no mark");
            assert_eq!(got, want, "cut at {cut}");
        }
    }

    #[test]
    fn a_final_line_without_a_newline_frames_identically_to_one_with_it() {
        let without: &[u8] = b"{\"a\":1}\n{\"a\":2}";
        let with: &[u8] = b"{\"a\":1}\n{\"a\":2}\n";
        for size in SIZES.into_iter().chain([without.len()]) {
            let a = by_size(without, size, Limits::default()).expect("no mark");
            let b = by_size(with, size, Limits::default()).expect("no mark");
            assert_eq!(a.lines, b.lines, "chunk size {size}");
            assert_eq!(a.report, b.report);
            assert_eq!(a.line_no, b.line_no);
            assert!(a.unterminated, "no terminator on the last line");
            assert!(!b.unterminated, "the stream ended on a terminator");
        }
    }

    #[test]
    fn finish_reports_an_unterminated_tail_and_the_rest_yields_the_line_once() {
        let head: &[u8] = b"{\"a\":1}\n{\"a\":2";
        let tail: &[u8] = b"}\n";

        // A tail read that stops mid-line is told the last line had no terminator,
        // which is the ordinary state of a file a collector flushes on a timer.
        let stopped = frame_chunks(&[head], Limits::default()).expect("no mark");
        assert!(stopped.unterminated);
        assert_eq!(
            stopped.lines,
            vec![(b"{\"a\":1}".to_vec(), 1, 0), (b"{\"a\":2".to_vec(), 2, 8),]
        );

        // The same bytes with the rest appended produce the second line complete
        // and exactly once.
        let continued = frame_chunks(&[head, tail], Limits::default()).expect("no mark");
        assert!(!continued.unterminated);
        assert_eq!(
            continued.lines,
            vec![(b"{\"a\":1}".to_vec(), 1, 0), (b"{\"a\":2}".to_vec(), 2, 8),]
        );
    }

    #[test]
    fn a_second_finish_does_not_hand_the_tail_over_twice() {
        let mut f = Framer::new(Limits::default());
        let mut seen = 0u32;
        f.push(b"{\"a\":1}", no_lines).expect("no line yet");
        {
            let mut count = |_: Line<'_>| -> JsonResult<()> {
                seen += 1;
                Ok(())
            };
            assert!(f.finish(&mut count).expect("no mark"));
            assert!(!f.finish(&mut count).expect("nothing left"));
        }
        assert_eq!(seen, 1);
    }

    #[test]
    fn a_lone_cr_does_not_split_a_line() {
        let got = whole(b"{\"a\":1}\r{\"a\":2}\n", Limits::default()).expect("no mark");
        assert_eq!(got.lines, vec![(b"{\"a\":1}\r{\"a\":2}".to_vec(), 1, 0)]);
        assert_eq!(got.line_no, 1);
        assert_eq!(got.report, FrameReport::default());
    }

    #[test]
    fn a_blank_line_is_skipped_and_still_advances_the_line_number() {
        let inputs: [&[u8]; 3] = [b"{}\n\n{}\n", b"{}\n \n{}\n", b"{}\n\r\n{}\n"];
        for input in inputs {
            for size in SIZES.into_iter().chain([input.len()]) {
                let got = by_size(input, size, Limits::default()).expect("no mark");
                assert_eq!(got.lines.len(), 2, "{input:?} at chunk size {size}");
                assert_eq!(got.lines[0].1, 1, "{input:?}");
                assert_eq!(got.lines[1].1, 3, "the third line is line 3 in {input:?}");
                assert_eq!(got.report.blank_lines, 1, "{input:?}");
                assert_eq!(got.line_no, 3);
            }
        }
    }

    #[test]
    fn a_byte_order_mark_is_skipped_only_at_offset_zero() {
        let leading =
            whole(b"\xEF\xBB\xBF{\"a\":1}\n{\"b\":2}\n", Limits::default()).expect("utf8");
        assert!(leading.report.leading_bom);
        assert_eq!(
            leading.lines,
            vec![
                (b"{\"a\":1}".to_vec(), 1, 3),
                (b"{\"b\":2}".to_vec(), 2, 11),
            ]
        );

        // Anywhere else it is bytes inside a line, and the reader refuses it.
        let inner = whole(b"{}\n\xEF\xBB\xBF{}\n", Limits::default()).expect("utf8");
        assert!(!inner.report.leading_bom);
        assert_eq!(inner.lines[1], (b"\xEF\xBB\xBF{}".to_vec(), 2, 3));

        // At most one, so the second is content of the first line.
        let twice = whole(b"\xEF\xBB\xBF\xEF\xBB\xBF{}\n", Limits::default()).expect("utf8");
        assert!(twice.report.leading_bom);
        assert_eq!(twice.lines, vec![(b"\xEF\xBB\xBF{}".to_vec(), 1, 3)]);
    }

    #[test]
    fn each_utf16_and_utf32_byte_order_mark_is_named_rather_than_decoded() {
        let cases: [(&[u8], Encoding); 4] = [
            (b"\xFE\xFF\x00{", Encoding::Utf16Be),
            (b"\xFF\xFE{\x00", Encoding::Utf16Le),
            (b"\xFF\xFE\x00\x00{\x00\x00\x00", Encoding::Utf32Le),
            (b"\x00\x00\xFE\xFF\x00\x00\x00{", Encoding::Utf32Be),
        ];
        for (input, want) in cases {
            // One byte at a time is the case that gets this wrong: `FF FE` alone
            // looks like UTF-16LE until the two NULs after it arrive.
            for size in SIZES.into_iter().chain([input.len()]) {
                let err = by_size(input, size, Limits::default())
                    .expect_err("a UTF-16 or UTF-32 mark is refused");
                assert_eq!(err.kind, Kind::Encoding(want), "chunk size {size}");
                assert_eq!((err.line, err.byte_in_line), (1, 0));
            }
        }
    }

    #[test]
    fn a_stream_that_is_only_a_utf16_mark_is_refused_at_end_of_stream() {
        let mut f = Framer::new(Limits::default());
        // Held rather than judged: two more NULs would have made it UTF-32LE.
        f.push(b"\xFF\xFE", no_lines).expect("nothing decided yet");
        let err = f
            .finish(no_lines)
            .expect_err("two bytes are the whole stream");
        assert_eq!(err.kind, Kind::Encoding(Encoding::Utf16Le));
    }

    #[test]
    fn a_single_64_mib_chunk_with_no_newline_holds_no_more_than_the_cap() {
        let limits = Limits::default();
        let mut f = Framer::new(limits);
        let chunk = vec![b'x'; 64 * 1024 * 1024];
        f.push(&chunk, no_lines).expect("no mark");
        assert!(
            f.carried() <= limits.max_line_bytes,
            "held {} bytes for a line that was refused",
            f.carried()
        );
        assert_eq!(f.carried(), 0, "the refused line is discarded, not held");
        assert_eq!(f.report().oversize_lines, 1);
    }

    #[test]
    fn a_stream_with_no_newline_is_refused_within_the_cap_and_then_resynchronises() {
        let limits = Limits::default();
        let mut f = Framer::new(limits);
        let mib = vec![b'a'; 1024 * 1024];
        for pushed in 1..=64u64 {
            f.push(&mib, no_lines).expect("no mark");
            assert!(
                f.carried() <= limits.max_line_bytes,
                "held {} bytes after {pushed} MiB",
                f.carried()
            );
        }
        assert_eq!(f.report().oversize_lines, 1, "one line, not one per chunk");
        assert_eq!(f.line_no(), 0, "the refused line has not ended yet");

        let mut lines = Vec::new();
        f.push(
            b"\n{\"a\":1}\n{\"a\":2}\n",
            |l: Line<'_>| -> JsonResult<()> {
                lines.push((l.bytes.to_vec(), l.number, l.offset));
                Ok(())
            },
        )
        .expect("no mark");
        let refused = 64 * 1024 * 1024u64;
        assert_eq!(
            lines,
            vec![
                (b"{\"a\":1}".to_vec(), 2, refused + 1),
                (b"{\"a\":2}".to_vec(), 3, refused + 9),
            ]
        );
        assert!(!f.finish(no_lines).expect("no mark"));
        assert_eq!(f.report().oversize_lines, 1);
        assert_eq!(f.report().blank_lines, 0);
    }

    #[test]
    fn a_line_of_exactly_the_cap_is_kept_and_one_byte_more_is_refused() {
        let limits = Limits {
            max_line_bytes: 8,
            ..Limits::default()
        };
        let got = whole(b"12345678\n123456789\n12345678\n", limits).expect("no mark");
        assert_eq!(
            got.lines,
            vec![(b"12345678".to_vec(), 1, 0), (b"12345678".to_vec(), 3, 19),]
        );
        assert_eq!(got.report.oversize_lines, 1);
        assert_eq!(got.line_no, 3, "the refused line still took line 2");
    }

    #[test]
    fn the_cr_of_a_crlf_counts_against_the_cap_because_the_cap_is_on_bytes_read() {
        // The framer cannot know a CR is a terminator until the LF arrives, and
        // holding one more byte to find out would put its peak a byte over the
        // bound it advertises. So a CRLF line has one byte less room than an LF
        // one, and that is the whole of the difference.
        let limits = Limits {
            max_line_bytes: 8,
            ..Limits::default()
        };
        let lf = whole(b"12345678\n", limits).expect("no mark");
        assert_eq!(lf.lines, vec![(b"12345678".to_vec(), 1, 0)]);
        assert_eq!(lf.report.oversize_lines, 0);

        let crlf = whole(b"12345678\r\n", limits).expect("no mark");
        assert!(crlf.lines.is_empty());
        assert_eq!(crlf.report.oversize_lines, 1);

        let shorter = whole(b"1234567\r\n", limits).expect("no mark");
        assert_eq!(shorter.lines, vec![(b"1234567".to_vec(), 1, 0)]);
        assert_eq!(shorter.report.oversize_lines, 0);
    }

    #[test]
    fn the_offset_of_each_line_is_its_first_byte_in_the_stream() {
        let input: &[u8] = b"{\"a\":1}\n\n{\"bb\":2}\r\n{\"c\":3}";
        let want = vec![
            (b"{\"a\":1}".to_vec(), 1, 0),
            (b"{\"bb\":2}".to_vec(), 3, 9),
            (b"{\"c\":3}".to_vec(), 4, 19),
        ];
        for size in SIZES.into_iter().chain([input.len()]) {
            let got = by_size(input, size, Limits::default()).expect("no mark");
            assert_eq!(got.lines, want, "chunk size {size}");
            assert!(got.unterminated);
        }
    }

    #[test]
    fn a_line_wholly_inside_the_chunk_is_borrowed_rather_than_copied() {
        let input: &[u8] = b"{\"a\":1}\n{\"a\":2}\n";
        let owned = input.as_ptr_range();
        let mut seen = 0u32;
        let mut f = Framer::new(Limits::default());
        f.push(input, |l: Line<'_>| -> JsonResult<()> {
            assert!(
                owned.contains(&l.bytes.as_ptr()),
                "the line was copied out of the chunk"
            );
            seen += 1;
            Ok(())
        })
        .expect("no mark");
        assert_eq!(seen, 2);
    }

    #[test]
    fn a_line_the_caller_refuses_is_not_held_for_a_second_delivery() {
        let mut f = Framer::new(Limits::default());
        // Split so the line has to come through the carry buffer, which is the
        // path that could keep it.
        f.push(b"{\"a\":", no_lines).expect("no line yet");
        let err = f
            .push(b"1}\n", |l: Line<'_>| -> JsonResult<()> {
                Err(JsonError::syntax(Syntax::UnexpectedByte, l.number, 0))
            })
            .expect_err("the caller refused the line");
        assert_eq!(err.line, 1);
        assert_eq!(f.carried(), 0);
        assert_eq!(f.line_no(), 1);
        assert!(!f.finish(no_lines).expect("nothing left"));
    }

    #[test]
    fn line_no_counts_the_lines_that_have_ended_so_far() {
        let mut f = Framer::new(Limits::default());
        assert_eq!(f.line_no(), 0);
        f.push(b"{}\n", |_: Line<'_>| -> JsonResult<()> { Ok(()) })
            .expect("no mark");
        assert_eq!(f.line_no(), 1);
        f.push(b"{}", no_lines).expect("no mark");
        assert_eq!(f.line_no(), 1, "the second line has not ended yet");
        assert!(
            f.finish(|_: Line<'_>| -> JsonResult<()> { Ok(()) })
                .expect("no mark")
        );
        assert_eq!(f.line_no(), 2);
    }

    #[test]
    fn a_blank_tail_with_no_newline_is_counted_and_still_reported_unterminated() {
        // A producer part way through writing a line has flushed only whitespace.
        // Calling that a finished stream would make a tail read miss the record.
        let got = whole(b"{}\n   ", Limits::default()).expect("no mark");
        assert_eq!(got.lines, vec![(b"{}".to_vec(), 1, 0)]);
        assert_eq!(got.report.blank_lines, 1);
        assert!(got.unterminated);
        assert_eq!(got.line_no, 2);
    }
}
