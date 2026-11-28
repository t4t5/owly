//! The receiver's per-connection state machine (§8.2).
//!
//! Feed it the bytes TLS decrypted with [`Connection::receive`], the user's
//! answer with [`Connection::accept`] or [`Connection::decline`], and timer
//! expiries with [`Connection::timeout`]; drain what it wants done with
//! [`Connection::poll`]. It never touches the network or the filesystem: an
//! upload comes out as directories and files to create, which the caller
//! writes into a staging directory.
//!
//! Policy is the caller's: this machine prompts for every `/Ask` and never
//! accepts on its own (ASK-3). It serves Everyone mode only.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::archive::compress::Compressor;
use super::archive::extract::{self, Allowed, RelPath, Rules};
use super::archive::{self, Unpacked, Unpacker};
use super::http::{self, BodyDecoder, RequestHead};
use super::messages::{
    AskRequest, AskResponse, DiscoverRequest, DiscoverResponse, Offer, STATUS_EVERYONE,
};
use super::plist;

/// ASK-2: how long a prompt holds `/Ask` open.
pub const ASK_TIMEOUT: Duration = Duration::from_secs(15);

/// How long to keep reading a body that's still arriving after its archive
/// completed, before closing (UP-11).
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct Limits {
    pub http: http::Limits,
    pub plist: plist::Limits,
    /// Largest `/Upload` body, compressed.
    pub max_upload_body: u64,
    pub extract: extract::Limits,
    /// Largest DVZip chunk (DVZ-3).
    pub max_dvzip_chunk: u32,
    /// Most bytes buffered while a prompt is up, before the connection is
    /// dropped.
    pub max_buffered: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            http: http::Limits::default(),
            plist: plist::Limits::default(),
            max_upload_body: 16 << 30,
            extract: extract::Limits::default(),
            max_dvzip_chunk: 4 << 20,
            max_buffered: 1 << 20,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub computer_name: String,
    pub model_name: String,
    /// `ReceiverMediaCapabilities`, UTF-8 JSON (DISC-3). Leaving out codecs
    /// gets legacy formats, such as JPEG for HEIC.
    pub media_capabilities: Vec<u8>,
    pub ask_timeout: Duration,
    pub limits: Limits,
}

impl Config {
    pub fn new(computer_name: impl Into<String>) -> Self {
        Config {
            computer_name: computer_name.into(),
            model_name: "Linux".into(),
            media_capabilities: br#"{"Version":1}"#.to_vec(),
            ask_timeout: ASK_TIMEOUT,
            limits: Limits::default(),
        }
    }
}

/// What the connection needs done, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Write these bytes to the peer.
    Transmit(Vec<u8>),
    /// Call [`Connection::timeout`] after this long, replacing any earlier
    /// timer. `None` cancels it.
    SetTimer(Option<Duration>),
    /// A sender saw this receiver.
    Discovered(DiscoverRequest),
    /// Ask the user. Answer with [`Connection::accept`] or
    /// [`Connection::decline`]. Every field in it is the sender's, to be
    /// escaped before display (SEC-4).
    Ask(AskRequest),
    /// The sender went away while the prompt was up.
    AskWithdrawn,
    /// An accepted URL share. Offer them; don't open them unasked (SEC-4).
    Urls(Vec<String>),
    /// An accepted upload began: create a fresh staging directory.
    UploadStarted,
    /// Create a directory in staging. Parents may not have entries of their
    /// own; create them too.
    CreateDir(RelPath),
    /// Create a file in staging, without replacing anything. `Data` and
    /// then `EndFile` follow.
    CreateFile(RelPath),
    Data(Vec<u8>),
    EndFile,
    /// Everything is in staging. Move it into place, then call
    /// [`Connection::finish_upload`].
    UploadComplete,
    /// The upload failed: delete staging.
    UploadFailed(String),
    /// Close the connection, after transmitting what came before.
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Accept,
    Decline,
}

#[derive(Debug)]
enum State {
    Head,
    Body {
        route: Route,
        decoder: BodyDecoder,
        body: Vec<u8>,
    },
    Prompting(AskRequest),
    Upload(Box<Upload>),
    /// Waiting for the caller to move the upload into place.
    Finishing {
        body: Option<BodyDecoder>,
    },
    /// The response is out; reading what's left of the body before closing.
    Draining(BodyDecoder),
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Discover,
    Ask,
}

#[derive(Debug)]
struct Upload {
    decoder: BodyDecoder,
    unpacker: Unpacker,
    /// Decoded body bytes not yet taken by the unpacker.
    pending: Vec<u8>,
    pending_pos: usize,
}

/// HTTP-7: which requests this connection has had.
#[derive(Debug, Default)]
struct Slots {
    discover: bool,
    /// The `/Ask` that was accepted.
    ask: Option<AskRequest>,
    /// Whether an `/Ask` has been made, accepted or not.
    asked: bool,
    upload: bool,
}

/// One TLS connection's worth of receiver.
#[derive(Debug)]
pub struct Connection {
    config: Arc<Config>,
    input: Vec<u8>,
    eof: bool,
    state: State,
    slots: Slots,
    events: VecDeque<Event>,
}

impl Connection {
    pub fn new(config: Arc<Config>) -> Self {
        Connection {
            config,
            input: Vec::new(),
            eof: false,
            state: State::Head,
            slots: Slots::default(),
            events: VecDeque::new(),
        }
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed) && self.events.is_empty()
    }

    /// Bytes from the peer.
    pub fn receive(&mut self, data: &[u8]) {
        if !matches!(self.state, State::Closed) {
            self.input.extend_from_slice(data);
        }
    }

    /// The peer closed its side.
    pub fn receive_eof(&mut self) {
        self.eof = true;
    }

    /// The user's answer to the [`Event::Ask`].
    pub fn answer(&mut self, answer: Answer) {
        let State::Prompting(ask) = std::mem::replace(&mut self.state, State::Head) else {
            return;
        };
        self.events.push_back(Event::SetTimer(None));
        match answer {
            Answer::Accept => {
                let body = plist::to_bytes(
                    &AskResponse {
                        receiver_computer_name: self.config.computer_name.clone(),
                        receiver_model_name: self.config.model_name.clone(),
                    }
                    .to_plist(),
                );
                self.transmit(http::response(
                    200,
                    &[("Content-Type", "application/octet-stream")],
                    &body,
                ));
                if let Offer::Urls(urls) = &ask.offer {
                    self.events.push_back(Event::Urls(urls.clone()));
                }
                self.slots.ask = Some(ask);
            }
            // ASK-2: answer a decline rather than leave the sender waiting.
            // Deliberately without the `WWW-Authenticate` RFC 9110 asks a
            // 401 to carry: this isn't an authentication challenge, and
            // senders only read the status (ASK-1).
            Answer::Decline => self.fail(401),
        }
    }

    pub fn accept(&mut self) {
        self.answer(Answer::Accept);
    }

    pub fn decline(&mut self) {
        self.answer(Answer::Decline);
    }

    /// The timer from the last [`Event::SetTimer`] fired.
    pub fn timeout(&mut self) {
        match self.state {
            State::Prompting(_) => self.decline(),
            State::Draining(_) => self.close(),
            _ => {}
        }
    }

    /// The result of moving a completed upload into place.
    pub fn finish_upload(&mut self, result: Result<(), String>) {
        let State::Finishing { body } = std::mem::replace(&mut self.state, State::Head) else {
            return;
        };
        match result {
            Ok(()) => {
                // UP-5.
                self.transmit(http::response(200, &[("Connection", "close")], b""));
                match body {
                    Some(decoder) if !self.eof => {
                        self.events.push_back(Event::SetTimer(Some(DRAIN_TIMEOUT)));
                        self.state = State::Draining(decoder);
                    }
                    _ => self.close(),
                }
            }
            Err(_) => self.fail(500),
        }
    }

    /// The next thing to do, if any.
    pub fn poll(&mut self) -> Option<Event> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Some(event);
            }
            if !self.step() {
                return None;
            }
        }
    }

    fn transmit(&mut self, bytes: Vec<u8>) {
        self.events.push_back(Event::Transmit(bytes));
    }

    fn close(&mut self) {
        if !matches!(self.state, State::Closed) {
            self.state = State::Closed;
            self.input = Vec::new();
            self.events.push_back(Event::Close);
        }
    }

    /// Answers with an error status and closes (SEC-8).
    fn fail(&mut self, status: u16) {
        self.transmit(http::response(status, &[("Connection", "close")], b""));
        self.close();
    }

    /// Makes what progress the input allows. False when stuck.
    fn step(&mut self) -> bool {
        match std::mem::replace(&mut self.state, State::Closed) {
            State::Closed => false,
            State::Head => self.head(),
            State::Body {
                route,
                decoder,
                body,
            } => self.body(route, decoder, body),
            State::Prompting(ask) => {
                self.state = State::Prompting(ask);
                if self.eof {
                    self.events.push_back(Event::SetTimer(None));
                    self.events.push_back(Event::AskWithdrawn);
                    self.close();
                    return true;
                }
                // UP-8 pipelining isn't advertised, so nothing should arrive
                // while the prompt is up; cap whatever does.
                if self.input.len() > self.config.limits.max_buffered {
                    self.events.push_back(Event::SetTimer(None));
                    self.events.push_back(Event::AskWithdrawn);
                    self.fail(400);
                    return true;
                }
                false
            }
            State::Upload(upload) => self.upload(upload),
            State::Finishing { body } => {
                self.state = State::Finishing { body };
                false
            }
            State::Draining(mut decoder) => {
                while !decoder.is_done() {
                    match decoder.decode(&self.input) {
                        Ok(step) if step.consumed > 0 => {
                            self.input.drain(..step.consumed);
                        }
                        Ok(_) if !self.eof => {
                            self.state = State::Draining(decoder);
                            return false;
                        }
                        _ => break,
                    }
                }
                self.events.push_back(Event::SetTimer(None));
                self.close();
                true
            }
        }
    }

    fn head(&mut self) -> bool {
        let limits = &self.config.limits;
        let (head, len) = match http::parse_request(&self.input, &limits.http) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => {
                self.state = State::Head;
                if self.eof {
                    // A clean close between requests, or a truncated head.
                    if self.input.is_empty() {
                        self.close();
                    } else {
                        self.fail(400);
                    }
                    return true;
                }
                return false;
            }
            Err(e) => {
                self.fail(e.status());
                return true;
            }
        };
        self.input.drain(..len);
        self.route(head);
        true
    }

    fn route(&mut self, head: RequestHead) {
        let limits = self.config.limits.clone();
        if head.method == "GET" || head.method == "HEAD" {
            // HTTP-5. A body would need draining; there's no reason for one.
            let keep_alive = head.body == http::BodyKind::Length(0);
            self.transmit(http::response(200, &[], b""));
            if keep_alive {
                self.state = State::Head;
            } else {
                self.close();
            }
            return;
        }
        if head.method != "POST" {
            self.fail(400);
            return;
        }
        let route = match head.target.as_str() {
            "/Discover" => {
                // HTTP-7: only on a fresh connection, so at most once.
                if self.slots.discover || self.slots.asked || self.slots.upload {
                    self.fail(400);
                    return;
                }
                Route::Discover
            }
            "/Ask" => {
                self.slots.discover = false;
                if self.slots.asked || self.slots.upload {
                    self.fail(400);
                    return;
                }
                self.slots.asked = true;
                Route::Ask
            }
            "/Upload" => {
                self.start_upload(head);
                return;
            }
            // HTTP-5: everything else, `/Hello` and `/Exchange` included.
            _ => {
                self.fail(400);
                return;
            }
        };
        match BodyDecoder::new(head.body, limits.plist.max_size as u64, &limits.http) {
            Ok(decoder) => {
                if head.expect_continue {
                    self.transmit(http::CONTINUE.to_vec());
                }
                self.state = State::Body {
                    route,
                    decoder,
                    body: Vec::new(),
                };
            }
            Err(e) => self.fail(e.status()),
        }
    }

    fn body(&mut self, route: Route, mut decoder: BodyDecoder, mut body: Vec<u8>) -> bool {
        let mut progressed = false;
        while !decoder.is_done() {
            match decoder.decode(&self.input) {
                Ok(step) if step.consumed > 0 => {
                    body.extend_from_slice(&self.input[step.data]);
                    self.input.drain(..step.consumed);
                    progressed = true;
                }
                Ok(_) if self.eof => {
                    self.fail(400);
                    return true;
                }
                Ok(_) => {
                    self.state = State::Body {
                        route,
                        decoder,
                        body,
                    };
                    return progressed;
                }
                Err(e) => {
                    self.fail(e.status());
                    return true;
                }
            }
        }
        // An empty body counts as an empty dictionary.
        let value = if body.is_empty() {
            Ok(plist::Value::Dict(plist::Dict::new()))
        } else {
            plist::from_bytes(&body, &self.config.limits.plist)
        };
        let Ok(value) = value else {
            // SEC-6: XML, too deep, too big or malformed.
            self.fail(400);
            return true;
        };
        match route {
            Route::Discover => self.discover(&value),
            Route::Ask => self.ask(&value),
        }
        true
    }

    fn discover(&mut self, value: &plist::Value) {
        let Ok(request) = DiscoverRequest::from_plist(value) else {
            self.fail(400);
            return;
        };
        self.slots.discover = true;
        // Everyone mode: every sender may see this receiver (ID-4).
        let response = DiscoverResponse {
            status_code: Some(STATUS_EVERYONE),
            receiver_computer_name: Some(self.config.computer_name.clone()),
            receiver_model_name: Some(self.config.model_name.clone()),
            receiver_media_capabilities: Some(self.config.media_capabilities.clone()),
            receiver_record: None,
        };
        let body = plist::to_bytes(&response.to_plist());
        self.transmit(http::response(
            200,
            &[("Content-Type", "application/octet-stream")],
            &body,
        ));
        self.events.push_back(Event::Discovered(request));
        self.state = State::Head;
    }

    fn ask(&mut self, value: &plist::Value) {
        let Ok(request) = AskRequest::from_plist(value) else {
            self.fail(400);
            return;
        };
        // ASK-5: every path is checked before anyone is asked about it, and
        // what's written must be what the prompt names: `FileBomPath` is
        // `./<FileName>`, or `./<folder>/<FileName>` for a regular file, as
        // Photos wraps each file of a multi-photo share. Extraction drops the
        // folder.
        if let Offer::Files(files) = &request.offer
            && files.iter().any(|f| {
                let (Ok(name), Ok(path)) =
                    (RelPath::file_name(&f.name), RelPath::parse(&f.bom_path))
                else {
                    return true;
                };
                name != path
                    && !(!f.is_directory
                        && path.components().len() == 2
                        && path.last() == name.last())
            })
        {
            self.fail(400);
            return;
        }
        self.events.push_back(Event::Ask(request.clone()));
        self.events
            .push_back(Event::SetTimer(Some(self.config.ask_timeout)));
        self.state = State::Prompting(request);
    }

    fn start_upload(&mut self, head: RequestHead) {
        // UP-6: only after an accepted `/Ask` on this connection, once.
        let Some(Offer::Files(files)) = self.slots.ask.as_ref().map(|a| &a.offer) else {
            self.fail(400);
            return;
        };
        if self.slots.upload {
            self.fail(400);
            return;
        }
        // UP-1, UP-4.
        let Some(kind) = head
            .headers
            .get("content-type")
            .and_then(Compressor::from_content_type)
        else {
            self.fail(406);
            return;
        };
        // UP-9: an iOS 18 `/Ask` names the upload that belongs to it.
        let ask = self.slots.ask.as_ref().unwrap();
        if let Some(id) = &ask.transfer_id {
            match head.headers.get("transferid") {
                Some(header) if header.eq_ignore_ascii_case(id) => {}
                _ => {
                    self.fail(400);
                    return;
                }
            }
        }
        let allowed = files
            .iter()
            .map(|f| Allowed {
                path: RelPath::parse(&f.bom_path).expect("checked in ask()"),
                is_directory: f.is_directory,
            })
            .collect();
        let config = self.config.clone();
        let limits = &config.limits;
        let decoder = match BodyDecoder::new(head.body, limits.max_upload_body, &limits.http) {
            Ok(decoder) => decoder,
            Err(e) => {
                self.fail(if e == http::Error::BodyTooLarge {
                    413
                } else {
                    e.status()
                });
                return;
            }
        };
        self.slots.upload = true;
        // UP-3.
        if head.expect_continue {
            self.transmit(http::CONTINUE.to_vec());
        }
        self.events.push_back(Event::UploadStarted);
        let unpacker = Unpacker::new(
            kind,
            Rules::new(allowed, limits.extract),
            &limits.extract,
            limits.max_dvzip_chunk,
        );
        self.state = State::Upload(Box::new(Upload {
            decoder,
            unpacker,
            pending: Vec::new(),
            pending_pos: 0,
        }));
    }

    fn upload(&mut self, mut up: Box<Upload>) -> bool {
        loop {
            let step = up.unpacker.next(&up.pending[up.pending_pos..]);
            let (n, step) = match step {
                Ok(step) => step,
                Err(e) => {
                    self.upload_failed(UploadError::Archive(e));
                    return true;
                }
            };
            up.pending_pos += n;
            if let Some(step) = step {
                let event = match step {
                    Unpacked::Dir(path) => Event::CreateDir(path),
                    Unpacked::File(path) => Event::CreateFile(path),
                    Unpacked::Data(data) => Event::Data(data),
                    Unpacked::EndFile => Event::EndFile,
                    // UP-11: done at the archive's trailer, whether or not the
                    // body's own end has arrived.
                    Unpacked::Complete => {
                        self.events.push_back(Event::UploadComplete);
                        let body = (!up.decoder.is_done()).then_some(up.decoder);
                        self.state = State::Finishing { body };
                        return true;
                    }
                };
                self.events.push_back(event);
                self.state = State::Upload(up);
                return true;
            }
            // The unpacker wants more of the body.
            if up.decoder.is_done() {
                let e = up.unpacker.finish().unwrap_err();
                self.upload_failed(UploadError::Archive(e));
                return true;
            }
            match up.decoder.decode(&self.input) {
                Ok(s) if s.consumed > 0 => {
                    up.pending.clear();
                    up.pending.extend_from_slice(&self.input[s.data]);
                    up.pending_pos = 0;
                    self.input.drain(..s.consumed);
                }
                Ok(_) if self.eof => {
                    self.upload_failed(UploadError::Http(http::Error::Truncated));
                    return true;
                }
                Ok(_) => {
                    self.state = State::Upload(up);
                    return false;
                }
                Err(e) => {
                    self.upload_failed(UploadError::Http(e));
                    return true;
                }
            }
        }
    }

    fn upload_failed(&mut self, error: UploadError) {
        let status = match &error {
            UploadError::Http(http::Error::BodyTooLarge)
            | UploadError::Archive(archive::Error::Extract(extract::Error::TooLarge)) => 413,
            UploadError::Http(e) => e.status(),
            UploadError::Archive(_) => 400,
        };
        self.events
            .push_back(Event::UploadFailed(error.to_string()));
        self.fail(status);
    }
}

#[derive(Debug)]
enum UploadError {
    Http(http::Error),
    Archive(archive::Error),
}

impl fmt::Display for UploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UploadError::Http(e) => e.fmt(f),
            UploadError::Archive(e) => e.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn offered(paths: &[(&str, &str, bool)]) -> plist::Value {
        use plist::Value;
        Value::Dict(BTreeMap::from([(
            "Files".into(),
            Value::Array(
                paths
                    .iter()
                    .map(|(name, path, directory)| {
                        Value::Dict(BTreeMap::from([
                            ("FileName".into(), Value::String((*name).into())),
                            ("FileBomPath".into(), Value::String((*path).into())),
                            ("FileIsDirectory".into(), Value::Bool(*directory)),
                        ]))
                    })
                    .collect(),
            ),
        )]))
    }

    // spec: ASK-5
    #[test]
    fn wrapped_photos_reach_the_confirmation_prompt() {
        let mut connection = Connection::new(Arc::new(Config::new("Receiver")));
        connection.ask(&offered(&[
            (
                "one.jpg",
                "./PHMediaFormatConversionRequest-one/one.jpg",
                false,
            ),
            (
                "two.jpg",
                "./PHMediaFormatConversionRequest-two/two.jpg",
                false,
            ),
        ]));
        let Some(Event::Ask(request)) = connection.poll() else {
            panic!("missing prompt")
        };
        assert!(matches!(request.offer, Offer::Files(files) if files.len() == 2));
    }

    /// The response to the prompt, once it's answered or timed out.
    fn prompt_answer(connection: &mut Connection) -> Vec<u8> {
        let mut answer = None;
        while let Some(event) = connection.poll() {
            if let Event::Transmit(bytes) = event {
                answer = Some(bytes);
            }
        }
        answer.expect("no response")
    }

    fn prompting() -> Connection {
        let mut connection = Connection::new(Arc::new(Config::new("Receiver")));
        connection.ask(&offered(&[("photo.jpg", "./photo.jpg", false)]));
        assert!(matches!(connection.poll(), Some(Event::Ask(_))));
        connection
    }

    // spec: ASK-2
    #[test]
    fn a_decline_is_answered_with_401() {
        let mut connection = prompting();
        connection.decline();
        assert!(prompt_answer(&mut connection).starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
        assert!(matches!(connection.state, State::Closed));
    }

    // spec: ASK-2
    #[test]
    fn a_prompt_that_times_out_is_answered_with_401() {
        let mut connection = prompting();
        connection.timeout();
        assert!(prompt_answer(&mut connection).starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
        assert!(matches!(connection.state, State::Closed));
    }

    // spec: ASK-5, SEC-1
    #[test]
    fn wrapped_paths_still_require_safe_paths_and_the_displayed_file_name() {
        for (path, directory) in [
            ("../photo.jpg", false),
            ("/folder/photo.jpg", false),
            ("./folder/../photo.jpg", false),
            ("./folder/deeper/photo.jpg", false),
            ("./folder/other.jpg", false),
            ("./folder/photo.jpg", true),
        ] {
            let mut connection = Connection::new(Arc::new(Config::new("Receiver")));
            connection.ask(&offered(&[("photo.jpg", path, directory)]));
            assert!(
                !connection
                    .events
                    .iter()
                    .any(|event| matches!(event, Event::Ask(_))),
                "accepted {path}"
            );
        }
    }
}
