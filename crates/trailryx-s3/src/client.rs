//! The S3 adapter: four operations, one signature, no SDK.
//!
//! # What this implements and what it refuses to guess
//!
//! [`ObjectStore`] is four calls, and the interesting one is `put_if_absent`. It is
//! what publishes a sealed segment atomically with no coordinator: no etcd, no
//! Consul, no lock service. On S3 that is `If-None-Match: *`, which AWS answers with
//! `200` if the key was free and `412 Precondition Failed` if somebody else got
//! there first.
//!
//! Three facts from AWS's own documentation shape the code, and each one is a test:
//!
//! - **`412` means the race was lost, not that the store failed.** It is
//!   [`PutOutcome::AlreadyExists`], which is a normal outcome of two nodes sealing
//!   the same segment, and the loser reads the winner's bytes.
//! - **`409 Conflict` is possible and is retryable.** AWS documents it for a delete
//!   that lands between the check and the write, and says a `PutObject` may simply
//!   be retried. So it maps to `Unavailable`, not to a lost race.
//! - **In a versioned bucket, a conditional write succeeds if the current version
//!   is a delete marker.** So `If-None-Match` does not mean "this key never
//!   existed": an administrator who deletes a segment re-opens its name for a
//!   second, different publication. That is exactly why a published object is read
//!   back by version and not by key, and why [`ObjectStore::get_version`] exists.
//!
//! # The dangerous store, and why the capability is declared rather than assumed
//!
//! Not every S3-compatible store implements conditional writes, and a store that
//! ignores `If-None-Match` answers `200` and **overwrites**. Nothing in the response
//! distinguishes that from a legitimate first write. A segment would be republished
//! with different bytes under a name two nodes both believe they own, and every
//! proof built on it would depend on which copy you happened to read.
//!
//! The precedent worth copying is Rust's `object_store`, whose `S3ConditionalPut` is
//! an explicit setting per backend rather than an assumption, precisely because the
//! backends differ. This crate does the same with [`Conditional`], and adds the step
//! a setting alone cannot give you: [`S3::verify_conditional_writes`] measures the
//! behaviour against the actual endpoint instead of trusting the configuration.
//!
//! # Errors, and what the contract can carry
//!
//! The operations here return [`Failure`], which keeps the status, the store's error
//! code and its message, because an operator debugging `SignatureDoesNotMatch` needs
//! all three. [`AdapterError`] carries a `&'static str`, so the [`ObjectStore`] impl
//! maps a failure onto the contract's vocabulary and the detail stays available on
//! the richer methods. That is a deliberate narrowing at the boundary, not an
//! oversight.

use trailryx_contracts::{AdapterError, AdapterResult, ObjectStore, PutOutcome, VersionId};
use trailryx_http::{Client, Http, Method, Request as HttpRequest, Response};

use crate::sigv4::{self, Credentials, Request as SignedRequest};
use crate::time::amz_timestamp;
use crate::xml;

/// Which cloud is on the other end.
///
/// Google Cloud Storage's XML API **is** the S3 API: the same verbs, the same
/// signature, the same XML. That is why this adapter reaches both rather than
/// existing twice. Four things differ, and each one is here rather than scattered:
/// the header that makes a write conditional, the response header that names the
/// version, the query parameter that asks for one, and how a listing pages.
///
/// Reaching GCS this way needs an **interoperability HMAC key** on the Google side,
/// which an operator creates deliberately and some organisations disable. That is a
/// deployment prerequisite rather than something this code can arrange, and it is
/// the honest cost of not writing a second adapter with OAuth and JWT signing in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    Aws,
    Gcs,
}

impl Flavour {
    /// The header that makes a write happen only if the key is free.
    fn conditional_header(self) -> (&'static str, &'static str) {
        match self {
            // AWS documents `*` as the only value it accepts here.
            Self::Aws => ("if-none-match", "*"),
            // Google documents 0 as "only if the object does not currently exist".
            Self::Gcs => ("x-goog-if-generation-match", "0"),
        }
    }

    /// The response header carrying what the store called the written version.
    fn version_header(self) -> &'static str {
        match self {
            Self::Aws => "x-amz-version-id",
            Self::Gcs => "x-goog-generation",
        }
    }

    /// The query parameter that asks for one specific version.
    fn version_param(self) -> &'static str {
        match self {
            Self::Aws => "versionId",
            Self::Gcs => "generation",
        }
    }
}

/// How a bucket is named in a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressing {
    /// `https://endpoint/bucket/key`. What MinIO and most compatible stores use,
    /// and what a bucket whose name is not DNS-safe requires.
    Path,
    /// `https://bucket.endpoint/key`. AWS's own recommendation, and the only form
    /// some regions accept.
    VirtualHosted,
}

/// How this deployment gets an atomic publication out of its store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conditional {
    /// `If-None-Match: *`, which AWS S3 has supported since August 2024 and which
    /// several compatible stores implement.
    IfNoneMatchStar,
    /// This store does not offer one. `put_if_absent` answers `Unsupported` and
    /// writes nothing, because a plain `PUT` here would be a second publication of
    /// a segment that nobody could detect afterwards.
    Absent,
}

/// Where a timestamp comes from, so nothing in this crate reads a clock for itself.
///
/// A signature is dated, and a signer that called `SystemTime::now` could not be
/// tested against a known-good signature. A fixed clock in a test produces the exact
/// `Authorization` header AWS would expect for that instant.
pub trait Clock {
    fn unix_seconds(&mut self) -> u64;
}

/// The host's clock, used by a deployment and by nothing in a test.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
    }
}

/// A fixed instant, for tests and for reproducing a signature somebody disputes.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn unix_seconds(&mut self) -> u64 {
        self.0
    }
}

/// Why an operation did not produce an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// No answer was obtained: DNS, connection, timeout, framing.
    Transport(String),
    /// The store answered and refused. `code` is its own, like `NoSuchBucket` or
    /// `SignatureDoesNotMatch`, which is the first thing an operator needs.
    Store {
        status: u16,
        code: String,
        message: String,
    },
    /// The store answered something this crate cannot read.
    Malformed(String),
    /// This deployment cannot honour the call, and retrying will not change that.
    Unsupported(&'static str),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(why) => write!(f, "the object store could not be reached: {why}"),
            Self::Store {
                status,
                code,
                message,
            } => write!(f, "the object store answered {status} {code}: {message}"),
            Self::Malformed(why) => write!(f, "the object store's answer was unreadable: {why}"),
            Self::Unsupported(why) => write!(f, "this deployment cannot do that: {why}"),
        }
    }
}

impl std::error::Error for Failure {}

impl From<Failure> for AdapterError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Transport(_) => Self::Unavailable("the object store could not be reached"),
            // A `409` is a race AWS documents as retryable, and a `5xx` is the store
            // having a bad minute. Both come back later; a `4xx` will not.
            Failure::Store { status, .. } if status == 409 || status >= 500 => {
                Self::Unavailable("the object store answered with a retryable failure")
            }
            Failure::Store { .. } => Self::Rejected("the object store refused the request"),
            Failure::Malformed(_) => {
                Self::Unavailable("the object store's answer could not be read")
            }
            Failure::Unsupported(why) => Self::Unsupported(why),
        }
    }
}

/// An S3-compatible object store.
pub struct S3 {
    http: Box<dyn Http + Send>,
    clock: Box<dyn Clock + Send>,
    /// The `Host` header value. It is signed, so it has to be exactly what the
    /// HTTP client will send: a signature over a different host is rejected with
    /// `SignatureDoesNotMatch` and no hint as to which header disagreed.
    host: String,
    bucket: String,
    region: String,
    credentials: Credentials,
    addressing: Addressing,
    conditional: Conditional,
    flavour: Flavour,
    /// `max-keys` on a listing, when something needs the pages small.
    ///
    /// `None` leaves it to the store, which is right in production: the server's
    /// default is a thousand and a smaller number only means more round trips. It
    /// exists because the continuation path is the likeliest place a hand-written
    /// client is wrong, and against a real bucket the only other way to reach it is
    /// to write a thousand and one objects, where every one is a billed request.
    page_size: Option<u32>,
    /// Kept so an operator can print the last refusal after the contract has
    /// narrowed it to a `&'static str`.
    last_failure: Option<Failure>,
}

impl std::fmt::Debug for S3 {
    /// Written by hand so that no future `derive` can start printing credentials.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3")
            .field("host", &self.host)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("addressing", &self.addressing)
            .field("conditional", &self.conditional)
            .field("flavour", &self.flavour)
            .finish_non_exhaustive()
    }
}

/// How much of an object this adapter will read into memory at once.
///
/// A sealed segment is the unit here, and a segment larger than this is a
/// configuration this adapter does not serve rather than an allocation it makes
/// quietly. Ranged reads are the answer when that changes, not a bigger number.
pub const MAX_OBJECT: usize = 256 << 20;

impl S3 {
    /// Against a real endpoint, given as `http://host[:port]`.
    ///
    /// With [`Addressing::VirtualHosted`] the bucket becomes part of the host, which
    /// is why the client is built here rather than handed in: the `Host` header and
    /// the signature have to agree, and the only way to guarantee that is for one
    /// place to decide both.
    pub fn new(
        endpoint: &str,
        bucket: impl Into<String>,
        region: impl Into<String>,
        credentials: Credentials,
        addressing: Addressing,
        conditional: Conditional,
    ) -> Result<Self, trailryx_http::UrlError> {
        let bucket = bucket.into();
        let origin = match addressing {
            Addressing::Path => endpoint.to_owned(),
            Addressing::VirtualHosted => {
                let rest = endpoint
                    .strip_prefix("http://")
                    .ok_or(trailryx_http::UrlError::NotHttp)?;
                format!("http://{bucket}.{rest}")
            }
        };
        let client = Client::new(&origin)?.with_max_response(MAX_OBJECT);
        let host = client.host().to_owned();
        Ok(Self {
            http: Box::new(client),
            clock: Box::new(SystemClock),
            host,
            bucket,
            region: region.into(),
            credentials,
            addressing,
            conditional,
            flavour: Flavour::Aws,
            page_size: None,
            last_failure: None,
        })
    }

    /// Against a scripted peer, for tests and for replaying a real exchange.
    pub fn with_transport(
        http: Box<dyn Http + Send>,
        host: impl Into<String>,
        bucket: impl Into<String>,
        region: impl Into<String>,
        credentials: Credentials,
        addressing: Addressing,
        conditional: Conditional,
    ) -> Self {
        Self {
            http,
            clock: Box::new(SystemClock),
            host: host.into(),
            bucket: bucket.into(),
            region: region.into(),
            credentials,
            addressing,
            conditional,
            flavour: Flavour::Aws,
            page_size: None,
            last_failure: None,
        }
    }

    /// Point this adapter at Google Cloud Storage's XML API instead of S3.
    /// Bound a listing page, so the continuation path can be reached cheaply.
    pub fn with_page_size(mut self, keys: u32) -> Self {
        self.page_size = Some(keys);
        self
    }

    pub fn with_flavour(mut self, flavour: Flavour) -> Self {
        self.flavour = flavour;
        self
    }

    pub fn with_clock(mut self, clock: Box<dyn Clock + Send>) -> Self {
        self.clock = clock;
        self
    }

    /// The last refusal in full, after the contract narrowed it to a static string.
    pub fn last_failure(&self) -> Option<&Failure> {
        self.last_failure.as_ref()
    }

    fn path_for(&self, key: &str) -> String {
        match self.addressing {
            Addressing::Path => format!("/{}/{key}", self.bucket),
            Addressing::VirtualHosted => format!("/{key}"),
        }
    }

    /// Sign a request and send it.
    ///
    /// The signed path and query are re-encoded identically for the request line.
    /// They have to be the same bytes: the service recomputes the signature from
    /// what arrives, so a target that differs from what was signed fails with
    /// `SignatureDoesNotMatch` and says nothing about which byte moved.
    fn send(
        &mut self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        extra_headers: &[(&str, &str)],
        payload: Vec<u8>,
    ) -> Result<Response, Failure> {
        let timestamp = amz_timestamp(self.clock.unix_seconds());
        let payload_hash = sigv4::payload_hash(&payload);

        let mut headers = vec![
            ("host".to_owned(), self.host.clone()),
            ("x-amz-content-sha256".to_owned(), payload_hash.clone()),
            ("x-amz-date".to_owned(), timestamp.clone()),
        ];
        if let Some(token) = self.credentials.session_token() {
            headers.push(("x-amz-security-token".to_owned(), token.to_owned()));
        }
        for (name, value) in extra_headers {
            headers.push(((*name).to_owned(), (*value).to_owned()));
        }

        let signed = sigv4::sign(
            &SignedRequest {
                method: method.as_str().to_owned(),
                path: path.to_owned(),
                query: query.to_vec(),
                headers: headers.clone(),
                payload: payload.clone(),
            },
            &self.credentials,
            &self.region,
            "s3",
            &timestamp,
        );

        let encoded_query = sigv4::canonical_query(query);
        let target = if encoded_query.is_empty() {
            sigv4::uri_encode(path, true)
        } else {
            format!("{}?{encoded_query}", sigv4::uri_encode(path, true))
        };

        let mut request = HttpRequest::new(method, target).body(payload);
        for (name, value) in headers {
            // `host` is signed and must not be sent from here. SigV4 requires it in
            // the canonical request, and the HTTP client writes the real `Host`
            // because it owns the connection, so adding it again put two of them on
            // the wire. RFC 9112 has a server refuse that outright, which Go's HTTP
            // layer does before any S3 code runs: a bare `400 Bad Request` with a
            // plain-text body, no code to report, nothing in the store's log. The
            // fakes in this crate's tests parsed headers into a list and never
            // minded, so every test passed against a client no real endpoint would
            // have accepted. MinIO is what said so.
            if name.eq_ignore_ascii_case("host") {
                continue;
            }
            request = request.header(name, value);
        }
        request = request.header("Authorization", signed.authorization);

        self.http
            .send(&request)
            .map_err(|e| Failure::Transport(e.to_string()))
    }

    /// Turn a refused response into a failure carrying the store's own words.
    fn refusal(response: &Response) -> Failure {
        let body = String::from_utf8_lossy(&response.body);
        Failure::Store {
            status: response.status,
            code: xml::text_of(&body, "Code").unwrap_or_else(|| "unknown".to_owned()),
            message: xml::text_of(&body, "Message").unwrap_or_else(|| body.trim().to_owned()),
        }
    }

    /// Publish an object only if its key is free.
    pub fn put_object_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> Result<(PutOutcome, Option<VersionId>), Failure> {
        if self.conditional == Conditional::Absent {
            return Err(Failure::Unsupported(
                "this store offers no conditional write, so a segment cannot be published \
                 atomically here; an unconditional PUT would overwrite somebody else's \
                 segment and nothing in the answer would say so",
            ));
        }
        let path = self.path_for(key);
        let response = self.send(
            Method::Put,
            &path,
            &[],
            &[self.flavour.conditional_header()],
            bytes.to_vec(),
        )?;
        match response.status {
            200 => Ok((
                PutOutcome::Written,
                response
                    .header(self.flavour.version_header())
                    .map(|v| VersionId(v.to_owned())),
            )),
            // The race was lost. A normal outcome, not a failure: the loser now
            // reads the winner's bytes.
            412 => Ok((PutOutcome::AlreadyExists, None)),
            _ => Err(Self::refusal(&response)),
        }
    }

    /// The current object under a key.
    pub fn get_object(&mut self, key: &str) -> Result<Option<Vec<u8>>, Failure> {
        let path = self.path_for(key);
        let response = self.send(Method::Get, &path, &[], &[], Vec::new())?;
        match response.status {
            200 => Ok(Some(response.body)),
            404 => Ok(None),
            _ => Err(Self::refusal(&response)),
        }
    }

    /// One specific version, whatever has been written over it since.
    pub fn get_object_version(
        &mut self,
        key: &str,
        version: &VersionId,
    ) -> Result<Option<Vec<u8>>, Failure> {
        let path = self.path_for(key);
        let query = vec![(self.flavour.version_param().to_owned(), version.0.clone())];
        let response = self.send(Method::Get, &path, &query, &[], Vec::new())?;
        match response.status {
            200 => Ok(Some(response.body)),
            404 => Ok(None),
            // S3 answers `405` when the named version is a delete marker. That is
            // not "absent": it is a specific version that exists and cannot be read,
            // and answering `None` would let a caller conclude the segment was never
            // published.
            405 => Err(Failure::Store {
                status: 405,
                code: "MethodNotAllowed".to_owned(),
                message: "that version is a delete marker, not an object".to_owned(),
            }),
            // A store without versioning refuses the parameter rather than ignoring
            // it. Reported as unsupported, since no retry will make it versioned.
            400 => Err(Failure::Unsupported(
                "this bucket does not version objects, so a published segment cannot be \
                 read back by version and WORM protects nothing here",
            )),
            _ => Err(Self::refusal(&response)),
        }
    }

    /// Every key under a prefix, following continuation tokens to the end.
    pub fn list_objects(&mut self, prefix: &str) -> Result<Vec<String>, Failure> {
        let path = match self.addressing {
            Addressing::Path => format!("/{}", self.bucket),
            Addressing::VirtualHosted => "/".to_owned(),
        };
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        loop {
            // Two pagination styles, because the two clouds page differently and
            // pretending otherwise means a listing that silently stops after one
            // page on one of them. AWS has the newer continuation tokens; Google's
            // XML API is the original marker-based listing.
            let mut query = match self.flavour {
                Flavour::Aws => vec![
                    ("list-type".to_owned(), "2".to_owned()),
                    ("prefix".to_owned(), prefix.to_owned()),
                ],
                Flavour::Gcs => vec![("prefix".to_owned(), prefix.to_owned())],
            };
            if let Some(keys) = self.page_size {
                query.push(("max-keys".to_owned(), keys.to_string()));
            }
            if let Some(token) = &token {
                let name = match self.flavour {
                    Flavour::Aws => "continuation-token",
                    Flavour::Gcs => "marker",
                };
                query.push((name.to_owned(), token.clone()));
            }
            let response = self.send(Method::Get, &path, &query, &[], Vec::new())?;
            if response.status != 200 {
                return Err(Self::refusal(&response));
            }
            let body = String::from_utf8_lossy(&response.body).into_owned();
            for entry in xml::blocks(&body, "Contents") {
                match xml::text_of(entry, "Key") {
                    Some(key) => keys.push(key),
                    // An entry without a key is a listing this crate cannot read.
                    // Reported rather than skipped: a silently short listing is how
                    // a segment goes missing without anybody noticing.
                    None => {
                        return Err(Failure::Malformed(
                            "a listing entry had no <Key>".to_owned(),
                        ));
                    }
                }
            }
            // Truncation is decided by IsTruncated, and the token is what comes
            // next. A lister that stopped at the first page would answer a
            // completeness question with a thousand keys and no sign of the rest.
            if xml::text_of(&body, "IsTruncated").as_deref() != Some("true") {
                return Ok(keys);
            }
            let next = match self.flavour {
                Flavour::Aws => xml::text_of(&body, "NextContinuationToken"),
                // The marker-based listing returns `NextMarker` only when a
                // delimiter was used, and otherwise expects the client to continue
                // from the last key it received. Both cases are handled, because
                // taking only the first would page correctly right up until the
                // day somebody stops using a delimiter.
                Flavour::Gcs => xml::text_of(&body, "NextMarker").or_else(|| keys.last().cloned()),
            };
            match next {
                Some(next) => token = Some(next),
                None => {
                    return Err(Failure::Malformed(
                        "the store said the listing was truncated and gave nothing to \
                         continue from"
                            .to_owned(),
                    ));
                }
            }
        }
    }

    /// Measure, rather than assume, that this endpoint honours a conditional write.
    ///
    /// A store that ignores `If-None-Match` answers `200` and overwrites, and no
    /// field of that response distinguishes it from a legitimate first write. So the
    /// only honest check is to write the same key twice and require the second to be
    /// refused with `412`.
    ///
    /// This writes one small object at `probe_key`, on purpose and once: a health
    /// check that changes nothing cannot detect this class of store.
    pub fn verify_conditional_writes(&mut self, probe_key: &str) -> Result<(), Failure> {
        let first = self.put_object_if_absent(probe_key, b"trailryx conditional write probe")?;
        let second = self.put_object_if_absent(probe_key, b"trailryx conditional write probe")?;
        match (first.0, second.0) {
            (_, PutOutcome::AlreadyExists) => Ok(()),
            _ => Err(Failure::Unsupported(
                "this endpoint accepted a second conditional write to a key that already \
                 existed, so it ignores If-None-Match; segments published here would \
                 overwrite each other silently and no proof built on them would mean \
                 anything",
            )),
        }
    }

    fn remember<T>(&mut self, outcome: Result<T, Failure>) -> AdapterResult<T> {
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

impl ObjectStore for S3 {
    fn put_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> AdapterResult<(PutOutcome, Option<VersionId>)> {
        let outcome = self.put_object_if_absent(key, bytes);
        self.remember(outcome)
    }

    fn get(&mut self, key: &str) -> AdapterResult<Option<Vec<u8>>> {
        let outcome = self.get_object(key);
        self.remember(outcome)
    }

    fn get_version(&mut self, key: &str, version: &VersionId) -> AdapterResult<Option<Vec<u8>>> {
        let outcome = self.get_object_version(key, version);
        self.remember(outcome)
    }

    fn list(&mut self, prefix: &str) -> AdapterResult<Vec<String>> {
        let outcome = self.list_objects(prefix);
        self.remember(outcome)
    }
}
