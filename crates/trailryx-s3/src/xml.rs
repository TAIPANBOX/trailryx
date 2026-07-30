//! Just enough XML to read what S3 answers, and deliberately not a parser.
//!
//! # Why not a real parser
//!
//! S3 answers a listing and an error as XML, and this crate needs five things out
//! of them: a key, a truncation flag, a continuation token, an error code and an
//! error message. A general parser would bring entity expansion, namespaces, DTDs
//! and external references, which is a set of features whose only appearance in
//! this codebase would be as an attack surface, aimed at a document from a store
//! the operator already trusts with the bytes.
//!
//! So this scans for named elements at the top of whatever block it is given, and
//! decodes the five predefined entities. Anything it cannot read, it reports as
//! absent, and the caller treats an absent field as a malformed answer rather than
//! as a default.
//!
//! # The one thing this must get right
//!
//! **A key is not a string until its entities are decoded.** S3 escapes `&`, `<`
//! and `>` in a key, so an agent that writes `a&b` gets `a&amp;b` back in the
//! listing. A lister that skipped decoding would hand back a key that does not
//! exist, and the `get` that followed would answer `None` for an object that is
//! plainly there. That is a data-loss-shaped bug produced by five characters.

/// The text of the first `<tag>...</tag>` in `xml`, entities decoded.
///
/// `None` when the element is absent, and also when it is present but never
/// closed: an unterminated element is a truncated document, not an empty value.
pub fn text_of(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(decode_entities(&xml[start..end]))
}

/// Every `<tag>...</tag>` block in `xml`, as raw slices for a second pass.
///
/// Used for `<Contents>`, whose children have to be read per entry: reading `<Key>`
/// across the whole document would work until a listing had one entry with a key
/// and the next without.
pub fn blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let body = &rest[start + open.len()..];
        let Some(end) = body.find(&close) else {
            // An unclosed final block is a truncated document. Everything before it
            // was whole and is kept; the fragment is dropped rather than guessed at.
            break;
        };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

/// The five predefined XML entities, and nothing else.
///
/// No numeric character references and no DTD-defined entities: S3 uses neither,
/// and an expander is where XML parsers grow their famous holes.
fn decode_entities(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let decoded = [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&apos;", '\''),
        ]
        .iter()
        .find(|(entity, _)| rest.starts_with(entity))
        .copied();
        match decoded {
            Some((entity, ch)) => {
                out.push(ch);
                rest = &rest[entity.len()..];
            }
            // An ampersand that begins nothing recognised is an ampersand. S3 does
            // not send one, and dropping it would corrupt a key more quietly than
            // keeping it.
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_element_yields_its_text() {
        let xml = "<Result><IsTruncated>true</IsTruncated><KeyCount>2</KeyCount></Result>";
        assert_eq!(text_of(xml, "IsTruncated").as_deref(), Some("true"));
        assert_eq!(text_of(xml, "KeyCount").as_deref(), Some("2"));
        assert_eq!(text_of(xml, "NextContinuationToken"), None);
    }

    #[test]
    fn an_unterminated_element_is_absent_rather_than_empty() {
        assert_eq!(text_of("<a><Key>segment-1", "Key"), None);
    }

    #[test]
    fn each_entry_is_read_on_its_own() {
        let xml = "<ListBucketResult>\
                   <Contents><Key>a</Key><Size>1</Size></Contents>\
                   <Contents><Size>2</Size></Contents>\
                   <Contents><Key>c</Key></Contents>\
                   </ListBucketResult>";
        let entries = blocks(xml, "Contents");
        assert_eq!(entries.len(), 3);
        let keys: Vec<Option<String>> = entries.iter().map(|e| text_of(e, "Key")).collect();
        assert_eq!(
            keys,
            vec![Some("a".to_owned()), None, Some("c".to_owned())],
            "an entry without a key must not borrow the next entry's"
        );
    }

    /// The bug this decoding exists to prevent: a key that comes back escaped is a
    /// key that does not exist, and the `get` that follows answers `None` for an
    /// object that is plainly there.
    #[test]
    fn a_key_is_decoded_before_it_is_handed_back() {
        let xml = "<Contents><Key>runs/a&amp;b/&lt;seg&gt;&quot;1&quot;&apos;.trx</Key></Contents>";
        let entry = blocks(xml, "Contents");
        assert_eq!(
            text_of(entry[0], "Key").as_deref(),
            Some(r#"runs/a&b/<seg>"1"'.trx"#)
        );
    }

    #[test]
    fn an_ampersand_that_begins_nothing_is_kept() {
        assert_eq!(
            text_of("<Key>a&b&amp;c</Key>", "Key").as_deref(),
            Some("a&b&c")
        );
        assert_eq!(
            text_of("<Key>a&</Key>", "Key").as_deref(),
            Some("a&"),
            "a trailing ampersand is not a truncated entity to be dropped"
        );
    }

    #[test]
    fn an_error_document_reads_as_a_code_and_a_message() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                   <Error><Code>PreconditionFailed</Code>\
                   <Message>At least one of the pre-conditions you specified did not hold</Message>\
                   <Condition>If-None-Match</Condition></Error>";
        assert_eq!(text_of(xml, "Code").as_deref(), Some("PreconditionFailed"));
        assert!(text_of(xml, "Message").unwrap().contains("pre-conditions"));
    }

    #[test]
    fn an_unclosed_final_block_does_not_lose_the_whole_listing() {
        let xml = "<Contents><Key>a</Key></Contents><Contents><Key>b";
        let entries = blocks(xml, "Contents");
        assert_eq!(entries.len(), 1);
        assert_eq!(text_of(entries[0], "Key").as_deref(), Some("a"));
    }
}
