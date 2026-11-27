//! HTTP/1.1 message framing, strict enough to face anyone in radio range
//! (SEC-7).
//!
//! Heads must end every line with CRLF, header names must be tokens, and
//! obsolete line folding is refused. A message may carry `Content-Length` or
//! `Transfer-Encoding: chunked`, never both and neither more than once. Chunk
//! sizes must be plain hex. Bodies are decoded incrementally by
//! [`BodyDecoder`], so a caller never has to buffer one whole.

use std::fmt;
use std::ops::Range;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest head (request or status line and headers), and largest chunked
    /// trailer section.
    pub max_head: usize,
    pub max_headers: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_head: 16 << 10,
            max_headers: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    HeadTooLarge,
    TooManyHeaders,
    BodyTooLarge,
    /// The connection ended before the message did.
    Truncated,
    Malformed(&'static str),
}

impl Error {
    /// The status a server answers this error with.
    pub fn status(&self) -> u16 {
        match self {
            Error::HeadTooLarge | Error::TooManyHeaders => 431,
            _ => 400,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::HeadTooLarge => f.write_str("HTTP head too large"),
            Error::TooManyHeaders => f.write_str("too many HTTP headers"),
            Error::BodyTooLarge => f.write_str("HTTP body too large"),
            Error::Truncated => f.write_str("HTTP message truncated"),
            Error::Malformed(what) => write!(f, "malformed HTTP: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// How a message's body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    Length(u64),
    Chunked,
    /// A response body that runs until the connection closes.
    UntilClose,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// The value of a header that appears once. `None` if it's absent or
    /// repeated, so a repeated header can't be read two ways.
    pub fn get(&self, name: &str) -> Option<&str> {
        let mut values = self.all(name);
        let first = values.next()?;
        values.next().is_none().then_some(first)
    }

    pub fn count(&self, name: &str) -> usize {
        self.all(name).count()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    fn all<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> {
        self.0
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub headers: Headers,
    pub body: BodyKind,
    /// `Expect: 100-continue` (UP-3).
    pub expect_continue: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Headers,
    pub body: BodyKind,
}

/// Parses a request head at the start of `buf`. `Ok(None)` means more bytes
/// are needed; `Ok(Some((head, n)))` means the head took the first `n`.
pub fn parse_request(buf: &[u8], limits: &Limits) -> Result<Option<(RequestHead, usize)>, Error> {
    let Some((lines, len)) = split_head(buf, limits)? else {
        return Ok(None);
    };
    let (start, fields) = lines.split_first().unwrap();
    let mut parts = start.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed("bad request line"));
    };
    if method.is_empty() || !method.iter().all(|&b| is_tchar(b)) {
        return Err(Error::Malformed("bad method"));
    }
    if target.first() != Some(&b'/') || !target.iter().all(|&b| b.is_ascii_graphic()) {
        return Err(Error::Malformed("bad request target"));
    }
    if version != b"HTTP/1.1" {
        return Err(Error::Malformed("not HTTP/1.1"));
    }
    let headers = parse_fields(fields, limits)?;
    let body = body_kind(&headers)?.unwrap_or(BodyKind::Length(0));
    let expect_continue = headers
        .all("expect")
        .any(|v| v.eq_ignore_ascii_case("100-continue"));
    Ok(Some((
        RequestHead {
            method: String::from_utf8(method.to_vec()).unwrap(),
            target: String::from_utf8(target.to_vec()).unwrap(),
            headers,
            body,
            expect_continue,
        },
        len,
    )))
}

/// Parses a response head, as [`parse_request`] does a request head.
pub fn parse_response(buf: &[u8], limits: &Limits) -> Result<Option<(ResponseHead, usize)>, Error> {
    let Some((lines, len)) = split_head(buf, limits)? else {
        return Ok(None);
    };
    let (start, fields) = lines.split_first().unwrap();
    let rest = start
        .strip_prefix(b"HTTP/1.1 ")
        .ok_or(Error::Malformed("not HTTP/1.1"))?;
    let code = rest.get(..3).ok_or(Error::Malformed("bad status line"))?;
    if !code.iter().all(u8::is_ascii_digit) || !(rest.len() == 3 || rest[3] == b' ') {
        return Err(Error::Malformed("bad status line"));
    }
    let status = std::str::from_utf8(code).unwrap().parse().unwrap();
    if !(100..=599).contains(&status) {
        return Err(Error::Malformed("bad status code"));
    }
    let headers = parse_fields(fields, limits)?;
    let body = if (100..200).contains(&status) || status == 204 || status == 304 {
        BodyKind::Length(0)
    } else {
        body_kind(&headers)?.unwrap_or(BodyKind::UntilClose)
    };
    Ok(Some((
        ResponseHead {
            status,
            headers,
            body,
        },
        len,
    )))
}

/// A head's lines, and how many bytes the head took.
type Lines<'a> = (Vec<&'a [u8]>, usize);

/// Finds the end of a head and splits it into lines, enforcing CRLF.
fn split_head<'a>(buf: &'a [u8], limits: &Limits) -> Result<Option<Lines<'a>>, Error> {
    let window = &buf[..buf.len().min(limits.max_head)];
    let Some(end) = window.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() >= limits.max_head {
            Err(Error::HeadTooLarge)
        } else {
            Ok(None)
        };
    };
    let head = &buf[..end];
    if head.is_empty() {
        return Err(Error::Malformed("empty start line"));
    }
    let lines = split_crlf(head)?;
    Ok(Some((lines, end + 4)))
}

fn split_crlf(text: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let mut lines = Vec::new();
    let mut rest = text;
    loop {
        match rest.iter().position(|&b| b == b'\r' || b == b'\n') {
            None => {
                lines.push(rest);
                return Ok(lines);
            }
            Some(i) if rest[i] == b'\r' && rest.get(i + 1) == Some(&b'\n') => {
                lines.push(&rest[..i]);
                rest = &rest[i + 2..];
            }
            Some(_) => return Err(Error::Malformed("bare CR or LF")),
        }
    }
}

fn parse_fields(lines: &[&[u8]], limits: &Limits) -> Result<Headers, Error> {
    if lines.len() > limits.max_headers {
        return Err(Error::TooManyHeaders);
    }
    let mut headers = Vec::with_capacity(lines.len());
    for line in lines {
        headers.push(parse_field(line)?);
    }
    Ok(Headers(headers))
}

fn parse_field(line: &[u8]) -> Result<(String, String), Error> {
    if line.first().is_some_and(|&b| b == b' ' || b == b'\t') {
        return Err(Error::Malformed("obsolete line folding"));
    }
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(Error::Malformed("header without a colon"))?;
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
        return Err(Error::Malformed("bad header name"));
    }
    let value = value.trim_ascii();
    if value.iter().any(|&b| b != b'\t' && (b < 0x20 || b == 0x7f)) {
        return Err(Error::Malformed("control character in header value"));
    }
    let value = String::from_utf8(value.to_vec())
        .map_err(|_| Error::Malformed("header value is not UTF-8"))?;
    Ok((String::from_utf8(name.to_vec()).unwrap(), value))
}

/// The body framing a message's headers declare, rejecting anything
/// ambiguous (SEC-7).
fn body_kind(headers: &Headers) -> Result<Option<BodyKind>, Error> {
    let lengths = headers.count("content-length");
    let encodings = headers.count("transfer-encoding");
    match (lengths, encodings) {
        (0, 0) => Ok(None),
        (1, 0) => {
            let value = headers.get("content-length").unwrap();
            if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Malformed("bad Content-Length"));
            }
            Ok(Some(BodyKind::Length(value.parse().unwrap())))
        }
        (0, 1) => {
            if headers
                .get("transfer-encoding")
                .unwrap()
                .eq_ignore_ascii_case("chunked")
            {
                Ok(Some(BodyKind::Chunked))
            } else {
                Err(Error::Malformed("unsupported Transfer-Encoding"))
            }
        }
        (0, _) => Err(Error::Malformed("repeated Transfer-Encoding")),
        (_, 0) => Err(Error::Malformed("repeated Content-Length")),
        _ => Err(Error::Malformed(
            "both Content-Length and Transfer-Encoding",
        )),
    }
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Longest chunk-size line accepted, extensions included.
const MAX_CHUNK_LINE: usize = 1024;

/// Decodes a message body incrementally.
#[derive(Debug, Clone)]
pub struct BodyDecoder {
    state: State,
    /// Most body bytes accepted.
    max: u64,
    total: u64,
    trailer: usize,
    max_trailer: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Length(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkEnd,
    Trailer,
    UntilClose,
    Done,
}

/// The result of one [`BodyDecoder::decode`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Input bytes used, including `data`.
    pub consumed: usize,
    /// Where in the input the body bytes this step decoded are.
    pub data: Range<usize>,
}

impl BodyDecoder {
    /// A decoder for a body of `kind`, failing with [`Error::BodyTooLarge`]
    /// once it holds more than `max` bytes.
    pub fn new(kind: BodyKind, max: u64, limits: &Limits) -> Result<Self, Error> {
        let state = match kind {
            BodyKind::Length(n) if n > max => return Err(Error::BodyTooLarge),
            BodyKind::Length(0) => State::Done,
            BodyKind::Length(n) => State::Length(n),
            BodyKind::Chunked => State::ChunkSize,
            BodyKind::UntilClose => State::UntilClose,
        };
        Ok(BodyDecoder {
            state,
            max,
            total: 0,
            trailer: 0,
            max_trailer: limits.max_head,
        })
    }

    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Body bytes decoded so far.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Decodes from the start of `input`. A step that consumes nothing needs
    /// more input; one with empty `data` may still have made progress through
    /// chunk framing, so callers loop until `consumed` is 0 or the body is
    /// done.
    pub fn decode(&mut self, input: &[u8]) -> Result<Step, Error> {
        let mut pos = 0;
        loop {
            let rest = &input[pos..];
            match self.state {
                State::Done => {
                    return Ok(Step {
                        consumed: pos,
                        data: pos..pos,
                    });
                }
                State::Length(left) | State::ChunkData(left) => {
                    let n = (rest.len() as u64).min(left) as usize;
                    if n == 0 {
                        return Ok(Step {
                            consumed: pos,
                            data: pos..pos,
                        });
                    }
                    self.add(n)?;
                    let left = left - n as u64;
                    self.state = match self.state {
                        State::Length(_) if left == 0 => State::Done,
                        State::Length(_) => State::Length(left),
                        _ if left == 0 => State::ChunkEnd,
                        _ => State::ChunkData(left),
                    };
                    return Ok(Step {
                        consumed: pos + n,
                        data: pos..pos + n,
                    });
                }
                State::UntilClose => {
                    self.add(rest.len())?;
                    return Ok(Step {
                        consumed: input.len(),
                        data: pos..input.len(),
                    });
                }
                State::ChunkSize => {
                    let Some(line) = line(rest, MAX_CHUNK_LINE)? else {
                        return Ok(Step {
                            consumed: pos,
                            data: pos..pos,
                        });
                    };
                    let size = chunk_size(line)?;
                    pos += line.len() + 2;
                    if size > self.max - self.total {
                        return Err(Error::BodyTooLarge);
                    }
                    self.state = if size == 0 {
                        State::Trailer
                    } else {
                        State::ChunkData(size)
                    };
                }
                State::ChunkEnd => {
                    if rest.len() < 2 {
                        return Ok(Step {
                            consumed: pos,
                            data: pos..pos,
                        });
                    }
                    if &rest[..2] != b"\r\n" {
                        return Err(Error::Malformed("chunk data not followed by CRLF"));
                    }
                    pos += 2;
                    self.state = State::ChunkSize;
                }
                State::Trailer => {
                    // The final CRLF may take the count 2 past the cap.
                    let left = self.max_trailer.saturating_sub(self.trailer);
                    let Some(line) = line(rest, left)? else {
                        return Ok(Step {
                            consumed: pos,
                            data: pos..pos,
                        });
                    };
                    self.trailer += line.len() + 2;
                    pos += line.len() + 2;
                    if line.is_empty() {
                        self.state = State::Done;
                    } else {
                        parse_field(line)?;
                    }
                }
            }
        }
    }

    /// Called when the connection ends: fine only for a body that runs until
    /// close or is already complete.
    pub fn finish(&mut self) -> Result<(), Error> {
        match self.state {
            State::Done => Ok(()),
            State::UntilClose => {
                self.state = State::Done;
                Ok(())
            }
            _ => Err(Error::Truncated),
        }
    }

    /// Counts `n` more body bytes. The total never passes `max`, so the
    /// decoder stays consistent after it fails.
    fn add(&mut self, n: usize) -> Result<(), Error> {
        let total = self.total + n as u64;
        if total > self.max {
            return Err(Error::BodyTooLarge);
        }
        self.total = total;
        Ok(())
    }
}

/// A CRLF-terminated line at the start of `input`, without the CRLF.
fn line(input: &[u8], max: usize) -> Result<Option<&[u8]>, Error> {
    let window = &input[..input.len().min(max + 2)];
    match window.iter().position(|&b| b == b'\n') {
        Some(i) if i > 0 && window[i - 1] == b'\r' => {
            let line = &window[..i - 1];
            if line.contains(&b'\r') {
                return Err(Error::Malformed("bare CR"));
            }
            Ok(Some(line))
        }
        Some(_) => Err(Error::Malformed("bare LF")),
        None if input.len() >= max + 2 => Err(Error::HeadTooLarge),
        None => Ok(None),
    }
}

/// `chunk-size [ BWS ";" chunk-ext ]`: 1–16 hex digits, nothing else before
/// the extensions.
fn chunk_size(line: &[u8]) -> Result<u64, Error> {
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 16 {
        return Err(Error::Malformed("bad chunk size"));
    }
    let ext = line[digits..].trim_ascii_start();
    if !(ext.is_empty() || ext[0] == b';') || ext.iter().any(|&b| b < 0x20 && b != b'\t') {
        return Err(Error::Malformed("bad chunk size"));
    }
    Ok(u64::from_str_radix(std::str::from_utf8(&line[..digits]).unwrap(), 16).unwrap())
}

pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "",
    }
}

/// A complete response with a `Content-Length` body.
pub fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

pub const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

/// A `POST` head. The caller adds the framing header.
pub fn post_head(path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = format!("POST {path} HTTP/1.1\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// One chunk of a chunked body. An empty `data` is the last chunk.
pub fn chunk(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(text: &str) -> Result<Option<(RequestHead, usize)>, Error> {
        parse_request(text.as_bytes(), &Limits::default())
    }

    fn body(kind: BodyKind, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut decoder = BodyDecoder::new(kind, 1 << 20, &Limits::default())?;
        let mut out = Vec::new();
        let mut pos = 0;
        while !decoder.is_done() {
            let step = decoder.decode(&input[pos..])?;
            out.extend_from_slice(&input[pos..][step.data]);
            if step.consumed == 0 {
                return Err(Error::Truncated);
            }
            pos += step.consumed;
        }
        Ok(out)
    }

    #[test]
    fn parses_finder_ask_head() {
        let text = "POST /Ask HTTP/1.1\r\nUser-Agent: AirDrop/1.0\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\nrest";
        let (head, n) = request(text).unwrap().unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, "/Ask");
        assert_eq!(head.body, BodyKind::Chunked);
        assert_eq!(
            head.headers.get("content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(&text[n..], "rest");
    }

    #[test]
    fn waits_for_a_whole_head() {
        assert_eq!(request("POST /Ask HTTP/1.1\r\nUser-Agent: x\r\n"), Ok(None));
    }

    // spec: SEC-7
    #[test]
    fn rejects_ambiguous_framing() {
        for text in [
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 1, 1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: +1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length : 1\r\n\r\n",
            "POST / HTTP/1.1\r\nX: a\r\n b\r\n\r\n",
            "POST / HTTP/1.1\nContent-Length: 1\r\n\r\n",
            "POST / HTTP/1.1\r\nX: a\rb\r\n\r\n",
            "POST  / HTTP/1.1\r\n\r\n",
            "POST / HTTP/1.0\r\n\r\n",
            "POST http://x/ HTTP/1.1\r\n\r\n",
            "\r\nPOST / HTTP/1.1\r\n\r\n",
        ] {
            assert!(
                matches!(request(text), Err(Error::Malformed(_))),
                "accepted {text:?}"
            );
        }
    }

    // spec: SEC-7
    #[test]
    fn caps_head_size_and_header_count() {
        let long = format!("POST / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(20000));
        assert_eq!(request(&long), Err(Error::HeadTooLarge));
        let endless = format!("POST / HTTP/1.1\r\nX: {}", "a".repeat(20000));
        assert_eq!(request(&endless), Err(Error::HeadTooLarge));
        let many = format!("POST / HTTP/1.1\r\n{}\r\n", "X: a\r\n".repeat(100));
        assert_eq!(request(&many), Err(Error::TooManyHeaders));
    }

    // spec: HTTP-2a, UP-1a
    #[test]
    fn decodes_both_framings() {
        assert_eq!(body(BodyKind::Length(5), b"helloXX").unwrap(), b"hello");
        assert_eq!(
            body(
                BodyKind::Chunked,
                b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n"
            )
            .unwrap(),
            b"hello world"
        );
        assert_eq!(body(BodyKind::Chunked, b"0\r\n\r\n").unwrap(), b"");
    }

    #[test]
    fn decodes_byte_by_byte() {
        let input = b"5\r\nhello\r\nA\r\n0123456789\r\n0\r\n\r\n";
        let mut decoder = BodyDecoder::new(BodyKind::Chunked, 100, &Limits::default()).unwrap();
        let mut buf = Vec::new();
        let mut out = Vec::new();
        for &b in input {
            buf.push(b);
            loop {
                let step = decoder.decode(&buf).unwrap();
                out.extend_from_slice(&buf[step.data.clone()]);
                buf.drain(..step.consumed);
                if step.consumed == 0 || decoder.is_done() {
                    break;
                }
            }
        }
        assert!(decoder.is_done());
        assert_eq!(out, b"hello0123456789");
    }

    // spec: SEC-7
    #[test]
    fn rejects_bad_chunks() {
        for input in [
            &b"-1\r\n"[..],
            b"x\r\n",
            b" 5\r\nhello\r\n",
            b"5 x\r\nhello\r\n",
            b"5\r\nhelloXX",
            b"5\nhello\r\n",
            b"11111111111111111\r\n",
        ] {
            assert!(
                matches!(body(BodyKind::Chunked, input), Err(Error::Malformed(_))),
                "accepted {input:?}"
            );
        }
    }

    // spec: SEC-3
    #[test]
    fn caps_body_size() {
        let limits = Limits::default();
        assert_eq!(
            BodyDecoder::new(BodyKind::Length(11), 10, &limits).err(),
            Some(Error::BodyTooLarge)
        );
        let mut chunked = BodyDecoder::new(BodyKind::Chunked, 10, &limits).unwrap();
        assert_eq!(chunked.decode(b"b\r\n"), Err(Error::BodyTooLarge));
        let mut until_close = BodyDecoder::new(BodyKind::UntilClose, 10, &limits).unwrap();
        assert_eq!(until_close.decode(&[0; 11]), Err(Error::BodyTooLarge));
    }

    // spec: SEC-7
    #[test]
    fn caps_trailer_size() {
        let limits = Limits {
            max_head: 64,
            ..Limits::default()
        };
        // Trailer lines that each fill what's left of the cap, so the count
        // lands exactly on it, then past it.
        for line in [64, 63, 62] {
            let mut input = b"0\r\n".to_vec();
            input.extend(format!("X: {}\r\n", "a".repeat(line - 3)).bytes());
            input.extend(format!("Y: {}\r\n", "b".repeat(64)).bytes());
            input.extend(b"\r\n");
            let mut decoder = BodyDecoder::new(BodyKind::Chunked, 10, &limits).unwrap();
            assert_eq!(decoder.decode(&input), Err(Error::HeadTooLarge));
        }
    }

    // spec: SEC-3
    #[test]
    fn stays_consistent_after_a_body_too_large() {
        // A rejected step leaves the total where it was, so the limit
        // arithmetic can't underflow if the caller keeps going.
        let mut decoder = BodyDecoder::new(BodyKind::UntilClose, 10, &Limits::default()).unwrap();
        assert_eq!(decoder.decode(&[0; 11]), Err(Error::BodyTooLarge));
        assert_eq!(decoder.total(), 0);
        assert_eq!(decoder.decode(&[0; 4]).map(|s| s.data), Ok(0..4));
        assert_eq!(decoder.total(), 4);
    }

    #[test]
    fn truncated_bodies_fail_at_close() {
        let mut decoder = BodyDecoder::new(BodyKind::Length(10), 10, &Limits::default()).unwrap();
        decoder.decode(b"short").unwrap();
        assert_eq!(decoder.finish(), Err(Error::Truncated));
    }

    #[test]
    fn parses_responses() {
        let (head, _) = parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
            &Limits::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!((head.status, head.body), (200, BodyKind::Length(3)));
        let (head, _) = parse_response(b"HTTP/1.1 403\r\n\r\n", &Limits::default())
            .unwrap()
            .unwrap();
        assert_eq!((head.status, head.body), (403, BodyKind::UntilClose));
        let (head, _) = parse_response(CONTINUE, &Limits::default())
            .unwrap()
            .unwrap();
        assert_eq!((head.status, head.body), (100, BodyKind::Length(0)));
    }
}
