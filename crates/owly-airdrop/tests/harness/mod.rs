//! The veth test harness (docs/conformance.md).
//!
//! Each test re-runs itself under `unshare --user --map-root-user --net`, so
//! it gets a network namespace of its own with no root needed, and there
//! connects a veth pair `owa`–`owb` with DAD off. Unlike `::1`, that gives
//! link-local addresses, multicast for mDNS and `%iface` scoping (NET-2), as
//! on `awdl0`. The sender uses `owa`, the receiver `owb`.

#![allow(dead_code)]

use std::net::{Ipv6Addr, SocketAddrV6};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use owly_airdrop::driver::receiver::{Options, Receiver, ReceiverEvent};
use owly_airdrop::driver::tls::{self, Identity};
use owly_airdrop::proto::http;
use owly_airdrop::proto::receiver::Config;
use owly_airdrop::proto::sender::{Response, ResponseReader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const ENV: &str = "OWLY_TEST_NETNS";

#[derive(Debug, Clone)]
pub struct Iface {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub addr: Ipv6Addr,
}

impl Iface {
    pub fn socket(&self, port: u16) -> SocketAddrV6 {
        SocketAddrV6::new(self.addr, port, 0, self.index)
    }
}

#[derive(Debug, Clone)]
pub struct Veth {
    /// The sender's end.
    pub a: Iface,
    /// The receiver's end.
    pub b: Iface,
}

impl Veth {
    /// How the sender, on `a`, addresses `port` on `b` (NET-2).
    pub fn to_b(&self, port: u16) -> SocketAddrV6 {
        SocketAddrV6::new(self.b.addr, port, 0, self.a.index)
    }
}

/// Defines a test that runs in its own namespace on a fresh veth pair.
#[macro_export]
macro_rules! veth_test {
    ($(#[$meta:meta])* async fn $name:ident($veth:ident: Veth) $body:block) => {
        $(#[$meta])*
        #[test]
        #[cfg_attr(not(target_os = "linux"), ignore = "needs Linux network namespaces (unshare, ip)")]
        fn $name() {
            if let Some($veth) = harness::enter(stringify!($name)) {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move $body)
            }
        }
    };
}

/// In the test process, runs the test again inside a namespace and checks
/// it passed, returning `None`. Inside the namespace, sets up the veth pair.
pub fn enter(test: &str) -> Option<Veth> {
    if std::env::var_os(ENV).is_some() {
        install_crypto();
        return Some(setup());
    }
    let exe = std::env::current_exe().unwrap();
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(exe)
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(ENV, "1")
        .status()
        .expect("running unshare (util-linux) for the veth harness");
    assert!(
        status.success(),
        "{test} failed in its network namespace. If unshare itself failed, \
         unprivileged user namespaces may be disabled (kernel.unprivileged_userns_clone)."
    );
    None
}

/// The application's job: rustls's default crypto provider.
pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn ip(args: &[&str]) {
    let status = Command::new("ip")
        .args(args)
        .status()
        .expect("running ip (iproute2)");
    assert!(status.success(), "ip {args:?} failed");
}

fn setup() -> Veth {
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "owa", "type", "veth", "peer", "name", "owb"]);
    let ends = [
        ("owa", [0x02, 0, 0, 0, 0, 0x0a]),
        ("owb", [0x02, 0, 0, 0, 0, 0x0b]),
    ];
    for (name, mac) in ends {
        // Addresses are usable at once, with no 1 s of DAD.
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/accept_dad"), "0").unwrap();
        let mac = mac.map(|b| format!("{b:02x}")).join(":");
        ip(&["link", "set", name, "address", &mac]);
    }
    for (name, _) in ends {
        ip(&["link", "set", name, "up"]);
    }
    let [a, b] = ends.map(|(name, mac)| {
        let addr = owly_awdl::MacAddr(mac).link_local();
        wait_for_address(name, addr);
        Iface {
            name: name.into(),
            index: index(name),
            mac,
            addr,
        }
    });
    Veth { a, b }
}

fn index(name: &str) -> u32 {
    let out = Command::new("ip")
        .args(["-o", "link", "show", "dev", name])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    text.split(':').next().unwrap().trim().parse().unwrap()
}

fn wait_for_address(name: &str, addr: Ipv6Addr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = Command::new("ip")
            .args(["-6", "addr", "show", "dev", name])
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        if text.contains(&format!("{addr}/64")) && !text.contains("tentative") {
            return;
        }
        assert!(Instant::now() < deadline, "{name} never got {addr}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub const PORT: u16 = 8770;

pub struct Running {
    pub events: mpsc::Receiver<ReceiverEvent>,
    pub dest: tempfile::TempDir,
    pub identity: Identity,
}

pub fn config() -> Config {
    Config::new("Test Receiver")
}

/// A receiver on `b`, serving in the background.
pub async fn receiver(veth: &Veth, config: Config) -> Running {
    let dest = tempfile::tempdir().unwrap();
    let identity = Identity::generate().unwrap();
    let options = Options::new(config, dest.path().to_path_buf());
    let (receiver, events) = Receiver::bind(veth.b.socket(PORT), &identity, options)
        .await
        .unwrap();
    tokio::spawn(receiver.run());
    Running {
        events,
        dest,
        identity,
    }
}

impl Running {
    /// The next event, failing the test after `secs`.
    pub async fn next(&mut self, secs: u64) -> ReceiverEvent {
        tokio::time::timeout(Duration::from_secs(secs), self.events.recv())
            .await
            .expect("receiver event timed out")
            .expect("receiver stopped")
    }

    /// The next `/Ask`, skipping other events, such as an earlier
    /// transfer's outcome.
    pub async fn next_request(&mut self) -> owly_airdrop::driver::receiver::Request {
        loop {
            if let ReceiverEvent::Request(r) = self.next(10).await {
                return r;
            }
        }
    }

    pub async fn accept_next(&mut self) {
        self.next_request().await.accept();
    }

    pub async fn decline_next(&mut self) {
        self.next_request().await.decline();
    }

    /// Every file under the destination, with its contents, staging included.
    pub fn files(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        walk(self.dest.path(), self.dest.path(), &mut out);
        out.sort();
        out
    }
}

fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(root, &path, out);
        } else {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            out.push((name, std::fs::read(&path).unwrap()));
        }
    }
}

/// A raw TLS client, for sending exactly the bytes a test wants.
pub struct Client {
    pub tls: TlsStream<TcpStream>,
    reader: ResponseReader,
}

pub async fn connect(veth: &Veth) -> Client {
    connect_with(veth, None).await
}

pub async fn connect_with(veth: &Veth, identity: Option<&Identity>) -> Client {
    let stream = TcpStream::connect(veth.to_b(PORT)).await.unwrap();
    let connector = TlsConnector::from(tls::client_config(identity).unwrap());
    let tls = connector.connect(tls::server_name(), stream).await.unwrap();
    Client {
        tls,
        reader: ResponseReader::new(),
    }
}

impl Client {
    pub async fn send(&mut self, bytes: &[u8]) {
        self.tls.write_all(bytes).await.unwrap();
        // tokio-rustls may hold the tail back until flushed.
        self.tls.flush().await.unwrap();
    }

    /// The next response, or `None` if the connection closed first.
    pub async fn response(&mut self) -> Option<Response> {
        self.response_within(Duration::from_secs(10)).await
    }

    pub async fn response_within(&mut self, limit: Duration) -> Option<Response> {
        let mut buf = vec![0; 16 << 10];
        tokio::time::timeout(limit, async {
            loop {
                let n = self.tls.read(&mut buf).await.unwrap_or(0);
                let result = if n == 0 {
                    self.reader.receive_eof().map(Some)
                } else {
                    self.reader.receive(&buf[..n])
                };
                match result {
                    Ok(Some(r)) => return Some(r),
                    Ok(None) => {}
                    Err(_) => return None,
                }
            }
        })
        .await
        .expect("response timed out")
    }

    /// Reads raw bytes until `want` has arrived.
    pub async fn read_until(&mut self, want: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0; 1024];
        tokio::time::timeout(Duration::from_secs(10), async {
            while !out.windows(want.len()).any(|w| w == want) {
                let n = self.tls.read(&mut buf).await.unwrap();
                assert!(n > 0, "closed before {want:?}");
                out.extend_from_slice(&buf[..n]);
            }
        })
        .await
        .expect("timed out");
        out
    }

    pub async fn request(&mut self, bytes: &[u8]) -> Option<Response> {
        self.send(bytes).await;
        self.response().await
    }
}

/// A request with a `Content-Length` body and Finder's headers.
pub fn post(path: &str, extra: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let len = body.len().to_string();
    let mut headers = vec![
        ("User-Agent", "AirDrop/1.0"),
        ("Content-Type", "application/octet-stream"),
    ];
    headers.extend_from_slice(extra);
    headers.push(("Content-Length", &len));
    let mut out = http::post_head(path, &headers);
    out.extend_from_slice(body);
    out
}

/// A TLS server that records one request and answers it as told, for
/// checking what the sender sends.
pub struct Capture {
    pub requests: mpsc::Receiver<(owly_airdrop::proto::http::RequestHead, Vec<u8>, bool)>,
}

/// Serves on `b`: each request is passed on with its body and whether the
/// client presented a certificate; `answer` decides the reply, or `None` to
/// never reply.
pub async fn capture(veth: &Veth, answer: fn(&str) -> Option<Vec<u8>>) -> Capture {
    let listener = tokio::net::TcpListener::bind(veth.b.socket(PORT))
        .await
        .unwrap();
    let identity = Identity::generate().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(tls::server_config(&identity).unwrap());
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let has_cert = tls.get_ref().1.peer_certificates().is_some();
                let mut input = Vec::new();
                let mut buf = vec![0; 16 << 10];
                loop {
                    let parsed = http::parse_request(&input, &http::Limits::default()).unwrap();
                    if let Some((head, n)) = parsed {
                        let mut decoder =
                            http::BodyDecoder::new(head.body, 1 << 30, &http::Limits::default())
                                .unwrap();
                        input.drain(..n);
                        let mut body = Vec::new();
                        while !decoder.is_done() {
                            let step = decoder.decode(&input).unwrap();
                            body.extend_from_slice(&input[step.data.clone()]);
                            input.drain(..step.consumed);
                            if step.consumed == 0 {
                                let n = tls.read(&mut buf).await.unwrap();
                                if n == 0 {
                                    return;
                                }
                                input.extend_from_slice(&buf[..n]);
                            }
                        }
                        let reply = answer(&head.target);
                        let _ = tx.send((head, body, has_cert)).await;
                        match reply {
                            Some(reply) => tls.write_all(&reply).await.unwrap(),
                            // Hold the connection open, unanswered.
                            None => {
                                tokio::time::sleep(Duration::from_secs(3600)).await;
                            }
                        }
                        continue;
                    }
                    let n = tls.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    input.extend_from_slice(&buf[..n]);
                }
            });
        }
    });
    Capture { requests: rx }
}

pub fn arc<T>(t: T) -> Arc<T> {
    Arc::new(t)
}

/// `tests/vectors/airdrop-vectors.json`.
pub fn vectors() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/airdrop-vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn b64(value: &serde_json::Value) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value.as_str().unwrap())
        .unwrap()
}

/// The vector in `group` called `name`.
pub fn vector<'a>(
    vectors: &'a serde_json::Value,
    group: &str,
    name: &str,
) -> &'a serde_json::Value {
    vectors[group]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("no {group} vector {name}"))
}

/// A vector's `expect.files`, as (path without `./`, data).
pub fn expected_files(vector: &serde_json::Value) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = vector["expect"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let path = f["path"]
                .as_str()
                .unwrap()
                .trim_start_matches("./")
                .to_string();
            (path, b64(&f["data_b64"]))
        })
        .collect();
    files.sort();
    files
}

/// ASK-7's shape, as Finder sends it.
pub fn check_ios18_ask(value: &owly_airdrop::proto::plist::Value) {
    let d = value.as_dict().unwrap();
    let id = d["TransferID"].as_dict().unwrap()["id"].as_str().unwrap();
    assert_eq!(id.len(), 36);
    assert_eq!(id, id.to_uppercase());
    assert!(
        d["TransferType"].as_dict().unwrap()["files"]
            .as_dict()
            .unwrap()
            .is_empty()
    );
    assert_eq!(d["Items"].as_array().unwrap().len(), 0);
    assert_eq!(d["BundleID"].as_str(), Some("com.apple.finder"));
    assert_eq!(d["ConvertMediaFormats"].as_bool(), Some(false));
    for key in ["SenderComputerName", "SenderModelName", "SenderID"] {
        assert!(d[key].as_str().is_some(), "{key}");
    }
    let file = d["Files"].as_array().unwrap()[0].as_dict().unwrap();
    assert_eq!(file["FileName"].as_str(), Some("IMG_0049.HEIC"));
    assert_eq!(file["FileBomPath"].as_str(), Some("./IMG_0049.HEIC"));
    assert_eq!(file["FileType"].as_str(), Some("public.heic"));
    assert_eq!(file["FileSize"].as_integer(), Some(1234));
    assert_eq!(file["FileIsDirectory"].as_bool(), Some(false));
    assert_eq!(file["ShouldConvertMediaFormats"].as_bool(), Some(false));
}
