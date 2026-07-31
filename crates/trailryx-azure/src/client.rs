//! The four operations, against Azure Blob Storage.
//!
//! # What differs from S3, beyond the signature
//!
//! - **A blob has a type.** `Put Blob` refuses without `x-ms-blob-type`, and for
//!   whole objects written in one request that is `BlockBlob`.
//! - **A version is a request header on the way in and a response header on the way
//!   out**, `x-ms-version` and `x-ms-version-id`, and the first is mandatory on every
//!   request. Azure dates its API rather than versioning its URLs.
//! - **A listing is a container-level operation**: `?restype=container&comp=list`,
//!   paged by `marker`, with the next one in `NextMarker`. Unlike Google's, Azure
//!   does return it, so there is nothing to fall back to.
//! - **Conditional create is `If-None-Match: *`**, the same spelling as S3 and a
//!   different spelling from Google, which is the sort of thing that has to be in
//!   one place per cloud rather than in a comment.

use trailryx_contracts::{AdapterError, AdapterResult, ObjectStore, PutOutcome, VersionId};
use trailryx_http::{Client, Http, Method, Request as HttpRequest, Response};

use crate::sharedkey::{self, Credentials, Request as SignedRequest};

/// The API version this adapter speaks.
///
/// Pinned rather than "latest": Azure changes behaviour between dated versions, and
/// the empty-content-length rule in the signature is itself a version boundary. A
/// client that followed the newest version would change its own signature the day
/// Azure shipped one.
pub const API_VERSION: &str = "2021-08-06";

pub type Failure = crate::client::AzureFailure;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AzureFailure {
    Transport(String),
    Store {
        status: u16,
        code: String,
        message: String,
    },
    Malformed(String),
}

impl std::fmt::Display for AzureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(why) => write!(f, "the blob service could not be reached: {why}"),
            Self::Store {
                status,
                code,
                message,
            } => write!(f, "the blob service answered {status} {code}: {message}"),
            Self::Malformed(why) => write!(f, "the blob service's answer was unreadable: {why}"),
        }
    }
}

impl std::error::Error for AzureFailure {}

impl From<AzureFailure> for AdapterError {
    fn from(failure: AzureFailure) -> Self {
        match failure {
            AzureFailure::Transport(_) => {
                Self::Unavailable("the blob service could not be reached")
            }
            AzureFailure::Store { status, .. } if status == 409 || status >= 500 => {
                Self::Unavailable("the blob service answered with a retryable failure")
            }
            AzureFailure::Store { .. } => Self::Rejected("the blob service refused the request"),
            AzureFailure::Malformed(_) => {
                Self::Unavailable("the blob service's answer could not be read")
            }
        }
    }
}

/// Where a timestamp comes from, so nothing here reads a clock for itself.
pub trait Clock {
    /// RFC 1123, which is what Azure dates a request with.
    fn http_date(&mut self) -> String;
}

/// The host's clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn http_date(&mut self) -> String {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        http_date(seconds)
    }
}

/// A fixed instant, so a test can assert on an exact signature.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn http_date(&mut self) -> String {
        http_date(self.0)
    }
}

/// `Sun, 06 Nov 1994 08:49:37 GMT`, the one date format this API takes.
///
/// Written out rather than taken from a library for the same reason the rest of the
/// crate is: it is a dozen lines, and the alternative is a dependency in an adapter
/// that otherwise has none.
pub fn http_date(unix_seconds: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (unix_seconds / 86_400) as i64;
    let rest = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday, which is why the table starts there.
    let weekday = DAYS[(days.rem_euclid(7)) as usize];
    format!(
        "{weekday}, {day:02} {month} {year:04} {h:02}:{m:02}:{s:02} GMT",
        month = MONTHS[(month - 1) as usize],
        h = rest / 3600,
        m = (rest % 3600) / 60,
        s = rest % 60,
    )
}

/// Howard Hinnant's `civil_from_days`, the same arithmetic the rest of the workspace
/// uses for dates, so the two cannot disagree about a leap year.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Azure Blob Storage.
pub struct Azure {
    http: Box<dyn Http + Send>,
    clock: Box<dyn Clock + Send>,
    credentials: Credentials,
    container: String,
    last_failure: Option<AzureFailure>,
}

impl std::fmt::Debug for Azure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Azure")
            .field("account", &self.credentials.account)
            .field("container", &self.container)
            .finish_non_exhaustive()
    }
}

impl Azure {
    /// Against the real service, at `https://<account>.blob.core.windows.net`.
    pub fn new(
        endpoint: &str,
        container: impl Into<String>,
        credentials: Credentials,
    ) -> Result<Self, trailryx_http::UrlError> {
        Ok(Self {
            http: Box::new(Client::new(endpoint)?),
            clock: Box::new(SystemClock),
            credentials,
            container: container.into(),
            last_failure: None,
        })
    }

    /// Against a scripted peer.
    pub fn with_transport(
        http: Box<dyn Http + Send>,
        container: impl Into<String>,
        credentials: Credentials,
    ) -> Self {
        Self {
            http,
            clock: Box::new(SystemClock),
            credentials,
            container: container.into(),
            last_failure: None,
        }
    }

    pub fn with_clock(mut self, clock: Box<dyn Clock + Send>) -> Self {
        self.clock = clock;
        self
    }

    pub fn last_failure(&self) -> Option<&AzureFailure> {
        self.last_failure.as_ref()
    }

    fn send(
        &mut self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<Response, AzureFailure> {
        let date = self.clock.http_date();
        let mut headers: Vec<(String, String)> = vec![
            ("x-ms-date".to_owned(), date),
            ("x-ms-version".to_owned(), API_VERSION.to_owned()),
        ];
        for (name, value) in extra {
            headers.push(((*name).to_owned(), (*value).to_owned()));
        }

        let signed = SignedRequest {
            method: method.as_str().to_owned(),
            path: path.to_owned(),
            query: query.to_vec(),
            headers: headers.clone(),
            content_length: body.len(),
            content_type: None,
        };
        let authorization = sharedkey::authorization(&self.credentials, &signed);

        let target = if query.is_empty() {
            path.to_owned()
        } else {
            let encoded: Vec<String> = query
                .iter()
                .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
                .collect();
            format!("{path}?{}", encoded.join("&"))
        };

        let mut request = HttpRequest::new(method, target).body(body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        request = request.header("Authorization", authorization);

        self.http
            .send(&request)
            .map_err(|e| AzureFailure::Transport(e.to_string()))
    }

    fn refusal(response: &Response) -> AzureFailure {
        let body = String::from_utf8_lossy(&response.body);
        AzureFailure::Store {
            status: response.status,
            // Azure puts its own code in a header as well as in the XML, and the
            // header is there even when the body is not.
            code: response
                .header("x-ms-error-code")
                .map(str::to_owned)
                .or_else(|| text_of(&body, "Code"))
                .unwrap_or_else(|| "unknown".to_owned()),
            message: text_of(&body, "Message").unwrap_or_else(|| body.trim().to_owned()),
        }
    }

    fn blob_path(&self, key: &str) -> String {
        format!("/{}/{key}", self.container)
    }

    pub fn put_blob_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> Result<(PutOutcome, Option<VersionId>), AzureFailure> {
        let path = self.blob_path(key);
        let response = self.send(
            Method::Put,
            &path,
            &[],
            &[
                ("x-ms-blob-type", "BlockBlob"),
                // The same spelling as S3 and a different one from Google, which is
                // exactly why each cloud names it in one place.
                ("if-none-match", "*"),
            ],
            bytes.to_vec(),
        )?;
        match response.status {
            201 | 200 => Ok((
                PutOutcome::Written,
                response
                    .header("x-ms-version-id")
                    .map(|v| VersionId(v.to_owned())),
            )),
            // The race was lost. A normal outcome of two nodes sealing the same
            // segment, not a failure.
            409 | 412 => Ok((PutOutcome::AlreadyExists, None)),
            _ => Err(Self::refusal(&response)),
        }
    }

    pub fn get_blob(&mut self, key: &str) -> Result<Option<Vec<u8>>, AzureFailure> {
        let path = self.blob_path(key);
        let response = self.send(Method::Get, &path, &[], &[], Vec::new())?;
        match response.status {
            200 => Ok(Some(response.body)),
            404 => Ok(None),
            _ => Err(Self::refusal(&response)),
        }
    }

    pub fn get_blob_version(
        &mut self,
        key: &str,
        version: &VersionId,
    ) -> Result<Option<Vec<u8>>, AzureFailure> {
        let path = self.blob_path(key);
        let query = vec![("versionid".to_owned(), version.0.clone())];
        let response = self.send(Method::Get, &path, &query, &[], Vec::new())?;
        match response.status {
            200 => Ok(Some(response.body)),
            404 => Ok(None),
            _ => Err(Self::refusal(&response)),
        }
    }

    pub fn list_blobs(&mut self, prefix: &str) -> Result<Vec<String>, AzureFailure> {
        let path = format!("/{}", self.container);
        let mut keys = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut query = vec![
                ("restype".to_owned(), "container".to_owned()),
                ("comp".to_owned(), "list".to_owned()),
                ("prefix".to_owned(), prefix.to_owned()),
            ];
            if let Some(marker) = &marker {
                query.push(("marker".to_owned(), marker.clone()));
            }
            let response = self.send(Method::Get, &path, &query, &[], Vec::new())?;
            if response.status != 200 {
                return Err(Self::refusal(&response));
            }
            let body = String::from_utf8_lossy(&response.body).into_owned();
            for blob in blocks(&body, "Blob") {
                match text_of(blob, "Name") {
                    Some(name) => keys.push(name),
                    // Reported rather than skipped: a silently short listing is how
                    // a segment goes missing without anybody noticing.
                    None => {
                        return Err(AzureFailure::Malformed(
                            "a listing entry had no <Name>".to_owned(),
                        ));
                    }
                }
            }
            // Azure returns an empty element rather than omitting it, so "no more
            // pages" and "next page" are the same tag with different contents.
            match text_of(&body, "NextMarker") {
                Some(next) if !next.is_empty() => marker = Some(next),
                _ => return Ok(keys),
            }
        }
    }

    fn remember<T>(&mut self, outcome: Result<T, AzureFailure>) -> AdapterResult<T> {
        match outcome {
            Ok(value) => Ok(value),
            Err(failure) => {
                let mapped = AdapterError::from(failure.clone());
                self.last_failure = Some(failure);
                Err(mapped)
            }
        }
    }
}

impl ObjectStore for Azure {
    fn put_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> AdapterResult<(PutOutcome, Option<VersionId>)> {
        let outcome = self.put_blob_if_absent(key, bytes);
        self.remember(outcome)
    }

    fn get(&mut self, key: &str) -> AdapterResult<Option<Vec<u8>>> {
        let outcome = self.get_blob(key);
        self.remember(outcome)
    }

    fn get_version(&mut self, key: &str, version: &VersionId) -> AdapterResult<Option<Vec<u8>>> {
        let outcome = self.get_blob_version(key, version);
        self.remember(outcome)
    }

    fn list(&mut self, prefix: &str) -> AdapterResult<Vec<String>> {
        let outcome = self.list_blobs(prefix);
        self.remember(outcome)
    }
}

/// Percent-encoding for a query value. Unreserved characters stay, everything else
/// goes as uppercase hex, which is the same rule the S3 signer follows.
fn encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// The same five-line XML reader the S3 adapter uses, for the same reason: a general
/// parser would bring entity expansion and namespaces to read three tag names.
fn text_of(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(decode_entities(&xml[start..end]))
}

fn blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let body = &rest[start + open.len()..];
        let Some(end) = body.find(&close) else { break };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
    }
    out
}

fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The date format is one of the few things a signature cannot survive getting
    /// wrong, and it is the same civil arithmetic the rest of the workspace uses.
    #[test]
    fn the_date_is_the_one_format_this_api_takes() {
        // Microsoft's own example timestamp.
        assert_eq!(http_date(1_435_361_952), "Fri, 26 Jun 2015 23:39:12 GMT");
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(http_date(4_107_542_400), "Mon, 01 Mar 2100 00:00:00 GMT");
    }

    #[test]
    fn a_listing_reads_names_and_stops_on_an_empty_marker() {
        let xml = "<EnumerationResults><Blobs>\
                   <Blob><Name>a/1</Name></Blob><Blob><Name>a/2</Name></Blob>\
                   </Blobs><NextMarker /></EnumerationResults>";
        let names: Vec<String> = blocks(xml, "Blob")
            .iter()
            .filter_map(|b| text_of(b, "Name"))
            .collect();
        assert_eq!(names, vec!["a/1", "a/2"]);
        assert_eq!(
            text_of(xml, "NextMarker"),
            None,
            "a self-closing marker is not a marker"
        );
    }
}
