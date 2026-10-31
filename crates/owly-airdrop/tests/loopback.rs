//! The conformance tests (docs/conformance.md) for layers 3–7, run sender
//! to receiver over TLS on the veth harness. Each test runs in a network namespace of its own.

mod harness;

use std::time::{Duration, Instant};

use flate2::Compression;
use harness::*;
use owly_airdrop::driver::mdns::Mdns;
use owly_airdrop::driver::receiver::ReceiverEvent;
use owly_airdrop::driver::sender::{Payload, Sender};
use owly_airdrop::driver::tls::{self, Identity};
use owly_airdrop::proto::archive::compress::{Compressor, Encoder};
use owly_airdrop::proto::archive::cpio::{Entry, odc_header, odc_trailer};
use owly_airdrop::proto::mdns::{self, BrowseEvent, RECEIVER_FLAGS, Service};
use owly_airdrop::proto::messages::Offer;
use owly_airdrop::proto::plist::{self, Dict, Limits, Value};
use owly_airdrop::proto::sender::{self as sender_proto, Outcome};

fn sender() -> Sender {
    Sender::new(sender_proto::Config::new("Test Sender", "486ac2a94ac6")).unwrap()
}

fn empty_dict() -> Vec<u8> {
    plist::to_bytes(&Value::Dict(Dict::new()))
}

fn decode(body: &[u8]) -> Dict {
    plist::from_bytes(body, &Limits::default())
        .unwrap()
        .as_dict()
        .unwrap()
        .clone()
}

/// An `/Ask` vector's request, by name.
fn ask_vector(name: &str) -> Vec<u8> {
    b64(&vector(&vectors(), "ask", name)["request_b64"])
}

/// Sends an `/Ask` and has the receiver accept it.
async fn ask_accepted(c: &mut Client, r: &mut Running, ask: &[u8]) {
    c.send(ask).await;
    r.accept_next().await;
    let response = c.response().await.unwrap();
    assert_eq!(response.status, 200);
}

/// An `/Ask` for one file, iOS 18 shape, with this transfer ID.
fn ask_for(name: &str, transfer_id: &str) -> Vec<u8> {
    let offer = Offer::Files(vec![owly_airdrop::proto::messages::AskFile {
        name: name.into(),
        file_type: "public.data".into(),
        size: Some(1),
        bom_path: format!("./{name}"),
        is_directory: false,
    }]);
    sender_proto::ask_request(
        &sender_proto::Config::new("Test", "486ac2a94ac6"),
        transfer_id,
        &offer,
    )
}

const ID: &str = "A3F34E01-0000-4000-8000-0000000000AA";

fn entry(name: &str, mode: u32, size: u64) -> Entry {
    Entry {
        name: name.into(),
        mode,
        size,
        nlink: 1,
        ino: 1,
        uid: 501,
        gid: 20,
        mtime: 0,
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Compressor::Gzip, Compression::fast());
    let mut out = e.write(data);
    out.extend(e.finish());
    out
}

/// A gzip odc archive of `(entry, data)`, with the root entry.
fn archive(entries: &[(Entry, &[u8])]) -> Vec<u8> {
    let mut raw = odc_header(&entry(".", 0o040755, 0));
    for (e, data) in entries {
        raw.extend(odc_header(e));
        raw.extend_from_slice(data);
    }
    raw.extend(odc_trailer());
    gzip(&raw)
}

fn upload(transfer_id: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let len = body.len().to_string();
    let mut out = owly_airdrop::proto::http::post_head(
        "/Upload",
        &[
            ("User-Agent", "AirDrop/1.0"),
            ("TransferID", transfer_id),
            ("TotalBytes", "0"),
            ("Content-Type", content_type),
            ("Content-Length", &len),
        ],
    );
    out.extend_from_slice(body);
    out
}

/// The destination holds nothing: no files and no staging left behind.
fn assert_untouched(r: &Running) {
    let left: Vec<_> = std::fs::read_dir(r.dest.path()).unwrap().collect();
    assert!(left.is_empty(), "destination not empty: {left:?}");
}

/// The server still answers a fresh `/Discover` (SEC-8).
async fn still_serving(veth: &Veth) {
    let mut c = connect(veth).await;
    let response = c
        .request(&post("/Discover", &[], &empty_dict()))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
}

// spec: T-DISC-1, T-DISC-3, DISC-1, TLS-2
veth_test! {
    async fn discover_answers_everyone(veth: Veth) {
        let _r = receiver(&veth, config()).await;
        let mut c = connect(&veth).await;
        let response = c.request(&post("/Discover", &[], &empty_dict())).await.unwrap();
        assert_eq!(response.status, 200);
        let d = decode(&response.body);
        assert_eq!(d["StatusCode"].as_integer(), Some(100));
        assert_eq!(d["ReceiverComputerName"].as_str(), Some("Test Receiver"));
        let caps: serde_json::Value = serde_json::from_slice(d["ReceiverMediaCapabilities"].as_data().unwrap()).unwrap();
        assert!(caps["Version"].is_i64());

        // The driver lists it.
        let found = sender().discover(veth.to_b(PORT)).await.unwrap().unwrap();
        assert_eq!(found.computer_name, "Test Receiver");
    }
}

// spec: T-DISC-4, HTTP-2
veth_test! {
    async fn discover_vectors_are_accepted(veth: Veth) {
        let _r = receiver(&veth, config()).await;
        for v in vectors()["discover"].as_array().unwrap() {
            let mut c = connect(&veth).await;
            let response = c.request(&b64(&v["request_b64"])).await.unwrap();
            assert_eq!(response.status, 200, "{}", v["name"]);
            assert!(decode(&response.body).contains_key("ReceiverComputerName"));
        }
    }
}

// spec: T-CONN-1, HTTP-1, HTTP-7
veth_test! {
    async fn discover_ask_upload_on_one_or_two_connections(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let vectors = vectors();
        let upload = vector(&vectors, "upload", "Finder: DVZip, Content-Length, TransferID header");

        // /Discover on connection A, /Ask and /Upload on B.
        let mut a = connect(&veth).await;
        assert_eq!(a.request(&post("/Discover", &[], &empty_dict())).await.unwrap().status, 200);
        drop(a);
        let mut b = connect(&veth).await;
        ask_accepted(&mut b, &mut r, &ask_vector("ios18-hello")).await;
        assert_eq!(b.request(&b64(&upload["request_b64"])).await.unwrap().status, 200);

        // All three on one connection.
        let mut c = connect(&veth).await;
        assert_eq!(c.request(&post("/Discover", &[], &empty_dict())).await.unwrap().status, 200);
        ask_accepted(&mut c, &mut r, &ask_vector("ios18-hello")).await;
        assert_eq!(c.request(&b64(&upload["request_b64"])).await.unwrap().status, 200);

        let names: Vec<_> = r.files().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["hello (1).txt", "hello.txt"]);
    }
}

// spec: T-CONN-2
veth_test! {
    async fn second_discover_is_rejected(veth: Veth) {
        let _r = receiver(&veth, config()).await;
        let mut c = connect(&veth).await;
        assert_eq!(c.request(&post("/Discover", &[], &empty_dict())).await.unwrap().status, 200);
        let second = c.request(&post("/Discover", &[], &empty_dict())).await;
        assert!(second.is_none_or(|r| r.status != 200));
        still_serving(&veth).await;
    }
}

// spec: T-ASK-1, ASK-3
veth_test! {
    async fn declined_ask_gets_no_upload(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let mut c = connect(&veth).await;
        c.send(&ask_vector("ios18-hello")).await;
        r.decline_next().await;
        assert_ne!(c.response().await.unwrap().status, 200);

        // The upload that would have followed, on a fresh connection.
        let upload = vector(&vectors(), "upload", "Finder: DVZip, Content-Length, TransferID header")["request_b64"].clone();
        let mut d = connect(&veth).await;
        assert_ne!(d.request(&b64(&upload)).await.map_or(0, |r| r.status), 200);
        assert_untouched(&r);

        // The driver reports it as declined.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, b"hello").unwrap();
        let send = tokio::spawn(async move {
            sender().send(veth.to_b(PORT), &Payload::Files(vec![path]), RECEIVER_FLAGS, None).await
        });
        r.decline_next().await;
        assert_eq!(send.await.unwrap().unwrap(), Outcome::Declined);
        assert_untouched(&r);
    }
}

// spec: T-ASK-2
veth_test! {
    async fn unanswered_ask_times_out_after_15s(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let mut c = connect(&veth).await;
        c.send(&ask_vector("ios18-hello")).await;
        let started = Instant::now();
        // Hold the request without answering it.
        let ReceiverEvent::Request(request) = r.next(10).await else { panic!() };
        let response = c.response_within(Duration::from_secs(30)).await;
        let waited = started.elapsed();
        assert!(response.is_none_or(|r| r.status != 200));
        assert!(waited > Duration::from_secs(14) && waited < Duration::from_secs(16), "{waited:?}");
        assert!(matches!(r.next(1).await, ReceiverEvent::Withdrawn { .. }));
        drop(request);
    }
}

// spec: T-ASK-3, ASK-4, SEC-4
veth_test! {
    async fn url_share_needs_no_upload(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let url = "https://example.com/a?b=c".to_string();
        let payload = Payload::Urls(vec![url.clone()]);
        let send = tokio::spawn(async move { sender().send(veth.to_b(PORT), &payload, RECEIVER_FLAGS, None).await });
        let ReceiverEvent::Request(request) = r.next(10).await else { panic!() };
        assert_eq!(request.ask.offer, Offer::Urls(vec![url.clone()]));
        request.accept();
        assert_eq!(send.await.unwrap().unwrap(), Outcome::Delivered);
        // The URLs are handed over, not opened, and nothing is written.
        match r.next(5).await {
            ReceiverEvent::Urls { urls, .. } => assert_eq!(urls, [url]),
            other => panic!("{other:?}"),
        }
        assert_untouched(&r);
    }
}

// spec: T-ASK-4, HTTP-2a
veth_test! {
    async fn ask_vectors_parse_to_their_fields(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        for v in vectors()["ask"].as_array().unwrap() {
            let mut c = connect(&veth).await;
            c.send(&b64(&v["request_b64"])).await;
            let ReceiverEvent::Request(request) = r.next(10).await else { panic!() };
            let expect = &v["expect"];
            assert_eq!(request.ask.transfer_id.as_deref(), expect["transfer_id"].as_str(), "{}", v["name"]);
            let Offer::Files(files) = &request.ask.offer else { panic!() };
            let want = expect["files"].as_array().unwrap();
            assert_eq!(files.len(), want.len());
            for (f, w) in files.iter().zip(want) {
                assert_eq!(f.name, w["name"].as_str().unwrap());
                assert_eq!(f.bom_path, w["bom_path"].as_str().unwrap());
                assert_eq!(f.file_type, w["type"].as_str().unwrap());
                assert_eq!(f.size, w["size"].as_u64());
                assert_eq!(f.is_directory, w["is_directory"].as_bool().unwrap());
            }
            request.decline();
            assert_eq!(c.response().await.unwrap().status, 403);
        }
    }
}

// spec: T-ASK-5, ASK-7, TLS-3, HTTP-6
veth_test! {
    async fn sender_sends_the_ios18_ask(veth: Veth) {
        let mut capture = capture(&veth, |_| Some(owly_airdrop::proto::http::response(403, &[], b""))).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("IMG_0049.HEIC");
        std::fs::write(&path, vec![1; 1234]).unwrap();
        let outcome = sender().send(veth.to_b(PORT), &Payload::Files(vec![path]), RECEIVER_FLAGS, None).await.unwrap();
        assert_eq!(outcome, Outcome::Declined);
        let (head, body, has_cert) = capture.requests.recv().await.unwrap();
        assert_eq!(head.target, "/Ask");
        assert_eq!(head.headers.get("user-agent"), Some("AirDrop/1.0"));
        assert!(!has_cert, "the sender presented a client certificate");
        check_ios18_ask(&plist::from_bytes(&body, &Limits::default()).unwrap());
    }
}

// spec: T-ASK-6, ASK-2a
veth_test! {
    async fn sender_gives_up_on_an_unanswered_ask(veth: Veth) {
        let _capture = capture(&veth, |_| None).await;
        let started = Instant::now();
        let outcome = sender()
            .send(veth.to_b(PORT), &Payload::Urls(vec!["https://example.com".into()]), RECEIVER_FLAGS, None)
            .await
            .unwrap();
        assert_eq!(outcome, Outcome::Declined);
        let waited = started.elapsed();
        assert!(waited > Duration::from_secs(15) && waited < Duration::from_secs(30), "{waited:?}");
    }
}

// spec: T-UP-1, UP-5
veth_test! {
    async fn upload_vectors_extract(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let vectors = vectors();
        for v in vectors["upload"].as_array().unwrap() {
            let mut c = connect(&veth).await;
            ask_accepted(&mut c, &mut r, &ask_vector(v["after_ask"].as_str().unwrap())).await;
            let response = c.request(&b64(&v["request_b64"])).await.unwrap();
            assert_eq!(response.status, 200, "{}", v["name"]);
            assert_eq!(response.head.headers.get("connection"), Some("close"));
            assert_eq!(response.body, b"");
            let ReceiverEvent::Received { paths, .. } = r.next(5).await else { panic!() };
            let mut got: Vec<_> = paths
                .iter()
                .map(|p| (p.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read(p).unwrap()))
                .collect();
            got.sort();
            for p in paths {
                std::fs::remove_file(p).unwrap();
            }
            assert_eq!(got, expected_files(v), "{}", v["name"]);
        }
    }
}

// spec: T-UP-2, UP-3
veth_test! {
    async fn expect_continue_gets_100_before_the_body(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let mut c = connect(&veth).await;
        ask_accepted(&mut c, &mut r, &ask_for("x", ID)).await;
        let body = archive(&[(entry("./x", 0o100644, 1), b"x")]);
        let mut request = upload(ID, "application/x-cpio", &body);
        let split = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let body = request.split_off(split);
        let head = String::from_utf8(request).unwrap().replace("\r\n\r\n", "\r\nExpect: 100-continue\r\n\r\n");
        c.send(head.as_bytes()).await;
        c.read_until(b"HTTP/1.1 100 Continue\r\n\r\n").await;
        c.send(&body).await;
        assert_eq!(c.response().await.unwrap().status, 200);
        assert_eq!(r.files(), [("x".to_string(), b"x".to_vec())]);
    }
}

// spec: T-UP-3, UP-4, UP-1
veth_test! {
    async fn unknown_content_type_is_406(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let mut c = connect(&veth).await;
        ask_accepted(&mut c, &mut r, &ask_for("x", ID)).await;
        let body = archive(&[(entry("./x", 0o100644, 1), b"x")]);
        let response = c.request(&upload(ID, "application/zip", &body)).await.unwrap();
        assert_eq!(response.status, 406);
        assert_eq!(response.head.headers.get("connection"), Some("close"));
        assert_untouched(&r);
    }
}

// spec: T-UP-4, UP-6
veth_test! {
    async fn upload_needs_an_accepted_ask_on_its_connection(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let body = archive(&[(entry("./x", 0o100644, 1), b"x")]);

        let mut c = connect(&veth).await;
        assert_ne!(c.request(&upload(ID, "application/x-cpio", &body)).await.map_or(0, |r| r.status), 200);

        let mut a = connect(&veth).await;
        ask_accepted(&mut a, &mut r, &ask_for("x", ID)).await;
        let mut b = connect(&veth).await;
        assert_ne!(b.request(&upload(ID, "application/x-cpio", &body)).await.map_or(0, |r| r.status), 200);
        assert_untouched(&r);
    }
}

// spec: T-UP-7, UP-9, UP-10
veth_test! {
    async fn upload_transfer_id_must_match(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let body = archive(&[(entry("./x", 0o100644, 1), b"x")]);
        let mut c = connect(&veth).await;
        ask_accepted(&mut c, &mut r, &ask_for("x", ID)).await;
        let response = c.request(&upload("A3F34E01-0000-4000-8000-0000000000BB", "application/x-cpio", &body)).await;
        assert_ne!(response.map_or(0, |r| r.status), 200);
        assert_untouched(&r);

        // A legacy /Ask, then an upload with no TransferID.
        let vectors = vectors();
        let legacy = vector(&vectors, "upload", "Legacy form: gzip cpio, chunked, no TransferID");
        let mut c = connect(&veth).await;
        ask_accepted(&mut c, &mut r, &ask_vector("legacy-hello")).await;
        assert_eq!(c.request(&b64(&legacy["request_b64"])).await.unwrap().status, 200);
        assert_eq!(r.files(), expected_files(legacy));
    }
}

// spec: UP-11
veth_test! {
    async fn upload_completes_at_the_archive_trailer(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let mut c = connect(&veth).await;
        ask_accepted(&mut c, &mut r, &ask_for("x", ID)).await;
        let body = archive(&[(entry("./x", 0o100644, 1), b"x")]);
        let mut request = owly_airdrop::proto::http::post_head(
            "/Upload",
            &[("TransferID", ID), ("Content-Type", "application/x-cpio"), ("Transfer-Encoding", "chunked")],
        );
        // The archive's chunk, but not the terminating zero-length one.
        request.extend(owly_airdrop::proto::http::chunk(&body));
        let response = c.request(&request).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(r.files(), [("x".to_string(), b"x".to_vec())]);
    }
}

// spec: T-HTTP-1, HTTP-5, HTTP-4, SEC-8
veth_test! {
    async fn unknown_paths_get_400(veth: Veth) {
        let _r = receiver(&veth, config()).await;
        for path in ["/X", "/Hello", "/Exchange", "/SharedIdentity", "/Error"] {
            let mut c = connect(&veth).await;
            let response = c.request(&post(path, &[], b"x")).await.unwrap();
            assert_eq!(response.status, 400, "{path}");
            assert_eq!(response.body, b"");
        }
        let mut c = connect(&veth).await;
        let get = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(c.request(get).await.unwrap().status, 200);
        still_serving(&veth).await;
    }
}

// spec: T-SEC-1, SEC-1, UP-7, ASK-5
veth_test! {
    async fn unsafe_archives_are_rejected(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let file = 0o100644;
        let cases: Vec<Vec<(Entry, &[u8])>> = vec![
            vec![(entry("./../x", file, 1), b"x")],
            vec![(entry("/etc/x", file, 1), b"x")],
            vec![(entry("./x", 0o120777, 6), b"/etc/x")],
            vec![(entry("./x", file, 1), b"x"), (entry("./not-asked", file, 1), b"y")],
        ];
        for entries in cases {
            let mut c = connect(&veth).await;
            ask_accepted(&mut c, &mut r, &ask_for("x", ID)).await;
            let response = c.request(&upload(ID, "application/x-cpio", &archive(&entries))).await;
            assert_ne!(response.map_or(0, |r| r.status), 200);
            assert!(matches!(r.next(5).await, ReceiverEvent::Failed { .. }));
            assert_untouched(&r);
        }

        // ASK-5: an /Ask naming an unsafe path gets no prompt.
        let mut c = connect(&veth).await;
        let response = c.request(&ask_for("..", ID)).await;
        assert_eq!(response.map_or(0, |r| r.status), 400);

        // Nor does one whose prompt would name another file than the one
        // written.
        let ask = sender_proto::ask_request(
            &sender_proto::Config::new("Test", "486ac2a94ac6"),
            ID,
            &Offer::Files(vec![owly_airdrop::proto::messages::AskFile {
                name: "cat.jpg".into(),
                file_type: "public.jpeg".into(),
                size: Some(1),
                bom_path: "./.bashrc".into(),
                is_directory: false,
            }]),
        );
        let mut c = connect(&veth).await;
        let response = c.request(&ask).await;
        assert_eq!(response.map_or(0, |r| r.status), 400);
    }
}

// spec: T-SEC-2, SEC-3
veth_test! {
    async fn gzip_bombs_fail_cleanly(veth: Veth) {
        let mut config = config();
        config.limits.extract.max_total = 64 << 20;
        let mut r = receiver(&veth, config).await;
        // 10 MB of gzip members of zeros, under an entry header claiming far
        // more than the limit: about 10 GB if it were all inflated.
        let zeros = gzip(&vec![0; 64 << 20]);
        let mut first = odc_header(&entry("./x", 0o100644, 0o77777777777));
        first.extend(vec![0; 1 << 20]);
        let mut body = gzip(&first);
        while body.len() < 10 << 20 {
            body.extend_from_slice(&zeros);
        }
        let mut c = connect(&veth).await;
        ask_accepted(&mut c, &mut r, &ask_for("x", ID)).await;
        let response = c.request(&upload(ID, "application/x-cpio", &body)).await;
        assert_eq!(response.map_or(0, |r| r.status), 413);
        assert_untouched(&r);

        // A header within the limit whose data runs past it.
        let mut raw = Vec::new();
        for i in 0..100 {
            raw.extend(odc_header(&entry(&format!("./d/{i}"), 0o100644, 1 << 20)));
            raw.extend(vec![0; 1 << 20]);
        }
        let ask = sender_proto::ask_request(
            &sender_proto::Config::new("Test", "486ac2a94ac6"),
            ID,
            &Offer::Files(vec![owly_airdrop::proto::messages::AskFile {
                name: "d".into(),
                file_type: "public.folder".into(),
                size: Some(1),
                bom_path: "./d".into(),
                is_directory: true,
            }]),
        );
        let mut c = connect(&veth).await;
        ask_accepted(&mut c, &mut r, &ask).await;
        let response = c.request(&upload(ID, "application/x-cpio", &gzip(&raw))).await;
        assert_eq!(response.map_or(0, |r| r.status), 413);
        assert_untouched(&r);
        still_serving(&veth).await;
    }
}

/// Arrays nested `depth` deep, as a bplist.
fn nested_bplist(depth: usize) -> Vec<u8> {
    let mut value = Value::Array(Vec::new());
    for _ in 1..depth {
        value = Value::Array(vec![value]);
    }
    plist::to_bytes(&value)
}

// spec: T-SEC-3, SEC-6
veth_test! {
    async fn hostile_plists_are_rejected(veth: Veth) {
        let _r = receiver(&veth, config()).await;
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>"#;
        for body in [xml.to_vec(), nested_bplist(200)] {
            let mut c = connect(&veth).await;
            let response = c.request(&post("/Discover", &[], &body)).await.unwrap();
            assert_eq!(response.status, 400);
        }
        still_serving(&veth).await;
    }
}

// spec: T-SEC-4, SEC-7, SEC-8
veth_test! {
    async fn ambiguous_framing_is_rejected(veth: Veth) {
        let _r = receiver(&veth, config()).await;
        let body = empty_dict();
        let requests = [
            format!("POST /Discover HTTP/1.1\r\nContent-Length: {}\r\nContent-Length: 5\r\n\r\n", body.len()).into_bytes(),
            b"POST /Discover HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n".to_vec(),
            b"POST /Discover HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n".to_vec(),
        ];
        for request in requests {
            let mut c = connect(&veth).await;
            assert_eq!(c.request(&request).await.unwrap().status, 400);
        }
        // A Content-Length past the body, then the end of the stream.
        let mut c = connect(&veth).await;
        c.send(b"POST /Discover HTTP/1.1\r\nContent-Length: 1000\r\n\r\nshort").await;
        tokio::io::AsyncWriteExt::shutdown(&mut c.tls).await.unwrap();
        assert_eq!(c.response().await.unwrap().status, 400);
        still_serving(&veth).await;
    }
}

// spec: T-MDNS-1, MDNS-1, MDNS-3, MDNS-5, MDNS-6, NET-1, NET-2
veth_test! {
    async fn receiver_is_found_over_mdns(veth: Veth) {
        let instance = mdns::service_id([0x3f, 0xa9, 0xc0, 0x1b, 0x22, 0xde]);
        let service = Service {
            instance: instance.clone(),
            host: format!("owly-{instance}"),
            port: PORT,
            addr: veth.b.addr,
            flags: RECEIVER_FLAGS,
        };
        let _registration = Mdns::new(veth.b.index).register(service).await.unwrap();
        let mut browse = Mdns::new(veth.a.index).browse().await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(10), browse.events.recv()).await.unwrap().unwrap();
        let BrowseEvent::Found(found) = event else { panic!("{event:?}") };
        assert_eq!(found.instance.len(), 12);
        assert!(found.instance.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(found.addr, veth.b.addr);
        assert_eq!(found.addr.segments()[0], 0xfe80);
        assert_eq!(found.port, PORT);
        assert_ne!(found.flags & (mdns::SUPPORTS_PIPELINING | mdns::SUPPORTS_MIXED_TYPES), 0);
        assert_eq!(found.flags & mdns::SUPPORTS_DVZIP, 0);
        // Exactly one instance.
        assert!(tokio::time::timeout(Duration::from_secs(2), browse.events.recv()).await.is_err());

        // The withdrawn announcement drops it.
        drop(_registration);
        let event = tokio::time::timeout(Duration::from_secs(5), browse.events.recv()).await.unwrap().unwrap();
        assert_eq!(event, BrowseEvent::Lost(instance));
    }
}

// spec: T-MDNS-2
veth_test! {
    async fn announcements_repeat_in_bursts(veth: Veth) {
        use socket2::{Domain, Protocol, Socket, Type};
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket.set_only_v6(true).unwrap();
        socket.set_reuse_address(true).unwrap();
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuse_port(true).unwrap();
        let any = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, mdns::MDNS_PORT));
        socket.bind(&any.into()).unwrap();
        socket.join_multicast_v6(&mdns::MDNS_GROUP, veth.a.index).unwrap();
        socket.set_nonblocking(true).unwrap();
        let listener = tokio::net::UdpSocket::from_std(socket.into()).unwrap();

        let instance = mdns::service_id([0x3f, 0xa9, 0xc0, 0x1b, 0x22, 0xde]);
        let service = Service {
            instance: instance.clone(),
            host: format!("owly-{instance}"),
            port: PORT,
            addr: veth.b.addr,
            flags: RECEIVER_FLAGS,
        };
        let start = Instant::now();
        let _registration = Mdns::new(veth.b.index)
            // owly-radio's burst for a radio sharing the AP's channel.
            .with_burst(Some(mdns::Burst { count: 3, interval: Duration::from_millis(50), pause: Duration::from_secs(3) }))
            .register(service)
            .await
            .unwrap();

        let mut heard = Vec::new();
        let mut buf = vec![0; mdns::MAX_MESSAGE];
        let end = tokio::time::Instant::now() + Duration::from_secs(7);
        while let Ok(received) = tokio::time::timeout_at(end, listener.recv_from(&mut buf)).await {
            let (n, _) = received.unwrap();
            let message = mdns::Message::decode(&buf[..n]).unwrap();
            let ours = message.response
                && message.answers.iter().any(|r| r.name == mdns::Name::instance(&instance));
            if ours {
                heard.push(start.elapsed());
            }
        }

        // Split where the gaps are pauses, not intervals.
        let mut bursts = vec![vec![heard[0]]];
        for w in heard.windows(2) {
            if w[1] - w[0] > Duration::from_secs(1) {
                bursts.push(Vec::new());
            }
            bursts.last_mut().unwrap().push(w[1]);
        }
        assert!(bursts.len() >= 3, "{bursts:?}");
        // The last burst may be cut off by the end of the 7 s.
        for burst in &bursts[..bursts.len() - 1] {
            assert_eq!(burst.len(), 3, "{bursts:?}");
        }
    }
}

// spec: HTTP-1, UP-1a, UP-2a, NET-3
veth_test! {
    async fn sender_delivers_files_and_folders(veth: Veth) {
        let mut r = receiver(&veth, config()).await;
        let src = tempfile::tempdir().unwrap();
        let photo: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
        std::fs::write(src.path().join("photo.jpg"), &photo).unwrap();
        std::fs::create_dir_all(src.path().join("Folder/sub")).unwrap();
        std::fs::write(src.path().join("Folder/a.txt"), b"a").unwrap();
        std::fs::write(src.path().join("Folder/sub/b.txt"), b"b").unwrap();
        std::fs::write(src.path().join("Folder/empty"), b"").unwrap();
        let payload = Payload::Files(vec![src.path().join("photo.jpg"), src.path().join("Folder")]);
        for flags in [RECEIVER_FLAGS, RECEIVER_FLAGS | mdns::SUPPORTS_DVZIP] {
            let (payload, to) = (payload.clone(), veth.to_b(PORT));
            let send = tokio::spawn(async move { sender().send(to, &payload, flags, None).await });
            let ReceiverEvent::Request(request) = r.next(10).await else { panic!() };
            assert_eq!(request.ask.sender_computer_name, "Test Sender");
            request.accept();
            assert_eq!(send.await.unwrap().unwrap(), Outcome::Delivered);
            let ReceiverEvent::Received { paths, .. } = r.next(5).await else { panic!() };
            assert_eq!(paths.len(), 2);
        }
        let files = r.files();
        let names: Vec<_> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "Folder (1)/a.txt",
                "Folder (1)/empty",
                "Folder (1)/sub/b.txt",
                "Folder/a.txt",
                "Folder/empty",
                "Folder/sub/b.txt",
                "photo (1).jpg",
                "photo.jpg",
            ]
        );
        assert_eq!(files[7].1, photo);
        assert_eq!(files[6].1, photo);
    }
}

// spec: TLS-1, TLS-3
veth_test! {
    async fn tls_12_and_13_with_or_without_a_client_certificate(veth: Veth) {
        let _r = receiver(&veth, config()).await;
        for versions in [&[&tls::rustls::version::TLS12][..], &[&tls::rustls::version::TLS13]] {
            let config = tls::client_config_with_versions(None, versions).unwrap();
            let stream = tokio::net::TcpStream::connect(veth.to_b(PORT)).await.unwrap();
            let tls = tokio_rustls::TlsConnector::from(config).connect(tls::server_name(), stream).await.unwrap();
            assert_eq!(tls.get_ref().1.protocol_version(), Some(versions[0].version));
        }
        // A client that presents a certificate is served too.
        let identity = Identity::generate().unwrap();
        let mut c = connect_with(&veth, Some(&identity)).await;
        assert_eq!(c.request(&post("/Discover", &[], &empty_dict())).await.unwrap().status, 200);
        let sender = Sender::with_client_identity(sender_proto::Config::new("x", "000000000000"), Some(&identity)).unwrap();
        assert!(sender.discover(veth.to_b(PORT)).await.unwrap().is_some());
    }
}

// spec: DISC-5
veth_test! {
    async fn discover_at_the_eui64_address(veth: Veth) {
        let _r = receiver(&veth, config()).await;
        // Only the peer's AWDL address is known: its MAC.
        let addr = owly_awdl::MacAddr(veth.b.mac).link_local();
        let target = std::net::SocketAddrV6::new(addr, 8770, 0, veth.a.index);
        assert!(sender().discover(target).await.unwrap().is_some());
    }
}
