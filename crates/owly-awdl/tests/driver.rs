//! The driver on a radio of no platform's: two nodes, each spawned
//! on an in-memory [`Air`] that carries its frames to the other, meet, and
//! pass an IPv6 packet from one host's [`Netif`] to the other's. A new
//! transport, an ESP32 over USB say, plugs in where these do.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use owly_awdl::driver::{self, Air, Netif, Received, Running};
use owly_awdl::frame::Frame;
use owly_awdl::{
    Channel, Config, Ipv6Packet, MacAddr, PeerInfo, Presence, RadioConstraints, UNICAST_QUEUE,
};
use tokio::sync::{mpsc, watch};

/// One end of the medium: what it sends, the other hears. While `full`,
/// it has no room for any frame, as a driver whose queue is full.
struct MemAir {
    tx: mpsc::UnboundedSender<Received>,
    rx: mpsc::UnboundedReceiver<Received>,
    sent: Arc<AtomicUsize>,
    full: Arc<AtomicBool>,
}

impl Air for MemAir {
    async fn recv(&mut self) -> io::Result<Received> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| io::Error::other("the other end went"))
    }

    fn send(&mut self, frame: Frame) -> Result<(), Frame> {
        if self.full.load(Ordering::Relaxed) {
            return Err(frame);
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        let _ = self.tx.send(Received {
            bytes: frame.bytes,
            rssi: Some(-40),
        });
        Ok(())
    }
}

/// A host: packets it sends come from `outbound`, and what the node
/// delivers goes to `delivered`.
struct MemNetif {
    outbound: mpsc::UnboundedReceiver<Ipv6Packet>,
    delivered: mpsc::UnboundedSender<Ipv6Packet>,
    up: watch::Sender<Vec<MacAddr>>,
    /// Packets the node has taken from the host.
    read: Arc<AtomicUsize>,
}

impl Netif for MemNetif {
    async fn recv(&mut self) -> io::Result<Ipv6Packet> {
        let p = self
            .outbound
            .recv()
            .await
            .ok_or_else(|| io::Error::other("the host went"))?;
        self.read.fetch_add(1, Ordering::Relaxed);
        Ok(p)
    }

    fn deliver(&mut self, packet: Ipv6Packet) {
        let _ = self.delivered.send(packet);
    }

    fn peer_up(&mut self, mac: MacAddr) {
        self.up.send_modify(|up| up.push(mac));
    }
}

struct Host {
    running: Running,
    peers: watch::Receiver<Vec<PeerInfo>>,
    up: watch::Receiver<Vec<MacAddr>>,
    send: mpsc::UnboundedSender<Ipv6Packet>,
    delivered: mpsc::UnboundedReceiver<Ipv6Packet>,
    sent: Arc<AtomicUsize>,
    full: Arc<AtomicBool>,
    read: Arc<AtomicUsize>,
}

fn mac(n: u8) -> MacAddr {
    MacAddr([0x02, 0, 0, 0, 0, n])
}

fn config(n: u8) -> Config {
    let radio = RadioConstraints {
        channel: Channel(6),
        presence: Presence::Fixed,
    };
    Config::new(mac(n), &format!("node{n}"), radio)
}

fn host(n: u8, tx: mpsc::UnboundedSender<Received>, rx: mpsc::UnboundedReceiver<Received>) -> Host {
    host_with(config(n), tx, rx)
}

fn host_with(
    cfg: Config,
    tx: mpsc::UnboundedSender<Received>,
    rx: mpsc::UnboundedReceiver<Received>,
) -> Host {
    let (peers_tx, peers) = watch::channel(Vec::new());
    let (send, outbound) = mpsc::unbounded_channel();
    let (delivered_tx, delivered) = mpsc::unbounded_channel();
    let (up_tx, up) = watch::channel(Vec::new());
    let sent = Arc::new(AtomicUsize::new(0));
    let full = Arc::new(AtomicBool::new(false));
    let read = Arc::new(AtomicUsize::new(0));
    let air = MemAir {
        tx,
        rx,
        sent: sent.clone(),
        full: full.clone(),
    };
    let netif_read = read.clone();
    let running = driver::spawn(
        cfg,
        move || {
            let netif = MemNetif {
                outbound,
                delivered: delivered_tx,
                up: up_tx,
                read: netif_read,
            };
            Ok((air, netif))
        },
        peers_tx,
    )
    .expect("the node starts");
    Host {
        running,
        peers,
        up,
        send,
        delivered,
        sent,
        full,
        read,
    }
}

/// Two hosts whose nodes have met.
async fn pair() -> (Host, Host) {
    let (a_tx, b_rx) = mpsc::unbounded_channel();
    let (b_tx, a_rx) = mpsc::unbounded_channel();
    let mut a = host(1, a_tx, a_rx);
    let mut b = host(2, b_tx, b_rx);
    let met = tokio::time::timeout(Duration::from_secs(5), async {
        a.peers.wait_for(|p| p.len() == 1).await.unwrap();
        b.peers.wait_for(|p| p.len() == 1).await.unwrap();
    })
    .await;
    assert!(met.is_ok(), "the two never met");
    (a, b)
}

/// Sends `n` echo requests from a to b, numbered from 0.
fn send_many(a: &Host, n: u16) {
    for i in 0..n {
        let p = Ipv6Packet::echo_request(mac(1), mac(2), 0x1234, i, b"numbered");
        a.send.send(p).unwrap();
    }
}

/// The numbers of the echo requests b's host got, in order, once `n` have
/// come or `within` has passed.
async fn received(b: &mut Host, n: usize, within: Duration) -> Vec<u16> {
    let mut got = Vec::new();
    let _ = tokio::time::timeout(within, async {
        while got.len() < n {
            let Some(p) = b.delivered.recv().await else {
                return;
            };
            if p.data.ends_with(b"numbered") {
                // The ICMPv6 sequence number, after the 40-byte IPv6 header.
                got.push(u16::from_be_bytes([p.data[46], p.data[47]]));
            }
        }
    })
    .await;
    got
}

#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_on_an_in_memory_air_meet_and_pass_ipv6() {
    let (a, mut b) = pair().await;
    assert_eq!(a.peers.borrow()[0].mac, mac(2));
    assert_eq!(a.peers.borrow()[0].rssi, Some(-40));
    assert_eq!(*b.up.borrow(), [mac(1)], "b's host heard of a");
    assert!(a.sent.load(std::sync::atomic::Ordering::Relaxed) > 0);

    let packet = Ipv6Packet::echo_request(mac(1), mac(2), 0x1234, 1, b"from a to b");
    a.send.send(packet).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), b.delivered.recv())
        .await
        .expect("b's host got nothing")
        .unwrap();
    assert!(got.data.ends_with(b"from a to b"));
    assert_eq!(got.src, mac(1));

    a.running.stop();
    b.running.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn unicast_groups_sends_group_frames_to_each_peer_instead() {
    let (a_tx, mut from_a) = mpsc::unbounded_channel::<Received>();
    let (to_b, b_rx) = mpsc::unbounded_channel();
    let (b_tx, a_rx) = mpsc::unbounded_channel();
    let mut cfg = config(1);
    cfg.unicast_groups = true;
    let a = host_with(cfg, a_tx, a_rx);
    let mut b = host(2, b_tx, b_rx);
    let receivers = Arc::new(std::sync::Mutex::new(Vec::new()));
    let tap = receivers.clone();
    tokio::spawn(async move {
        while let Some(frame) = from_a.recv().await {
            tap.lock().unwrap().push(frame.bytes[4..10].to_vec());
            let _ = to_b.send(frame);
        }
    });
    let met =
        tokio::time::timeout(Duration::from_secs(5), b.peers.wait_for(|p| p.len() == 1)).await;
    assert!(met.is_ok(), "b never heard a");

    let receivers = receivers.lock().unwrap();
    assert!(!receivers.is_empty());
    assert!(
        receivers.iter().all(|r| r[..] == mac(2).0),
        "a sent to {receivers:02x?}"
    );
    drop(receivers);
    a.running.stop();
    b.running.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn unicast_groups_never_recurses_on_a_spoofed_multicast_peer() {
    let (a_tx, mut from_a) = mpsc::unbounded_channel::<Received>();
    let (to_a, a_rx) = mpsc::unbounded_channel();
    let mut cfg = config(1);
    cfg.unicast_groups = true;
    let mut a = host_with(cfg, a_tx, a_rx);

    // A valid advertisement with an invalid transmitter address can still
    // reach the peer table. It must never become another group transmission.
    let mut spoofed = config(2);
    spoofed.addr = MacAddr::BROADCAST;
    let mut sender = owly_awdl::Node::new(spoofed, owly_awdl::Time(1));
    for action in sender.handle(owly_awdl::Input::Timer(owly_awdl::Time(1))) {
        if let owly_awdl::Action::Transmit { frame, .. } = action {
            to_a.send(Received {
                bytes: frame.bytes,
                rssi: Some(-40),
            })
            .unwrap();
        }
    }
    tokio::time::timeout(Duration::from_secs(2), a.peers.wait_for(|p| !p.is_empty()))
        .await
        .expect("the spoofed peer was never processed")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(from_a.try_recv().is_err(), "sent to a group address");
    assert!(a.running.failed().borrow().is_none());
    a.running.stop();
}

#[test]
fn a_transport_that_cant_open_fails_the_spawn() {
    let (peers, _) = watch::channel(Vec::new());
    let opened = driver::spawn(
        config(1),
        || -> io::Result<(MemAir, MemNetif)> { Err(io::Error::other("no radio plugged in")) },
        peers,
    );
    assert_eq!(
        opened.err().map(|e| e.to_string()),
        Some("no radio plugged in".to_string())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_whose_air_fails_says_why() {
    let (a, b) = pair().await;
    let mut failed = a.running.failed();
    assert_eq!(*failed.borrow(), None);
    // b's air goes with its node, and a hears nothing more.
    b.running.stop();
    let why = tokio::time::timeout(Duration::from_secs(5), failed.wait_for(Option::is_some))
        .await
        .expect("a's node stops")
        .unwrap()
        .clone();
    assert_eq!(why.as_deref(), Some("the other end went"));
    a.running.stop();
}

// patch owl-07: unicast the radio has no room for is kept, not dropped
// after 100 ms, which lost the phone the TCP ACKs it was waiting for.
#[tokio::test(flavor = "multi_thread")]
async fn unicast_waits_while_the_radio_is_full_and_none_is_lost() {
    let (a, mut b) = pair().await;
    a.full.store(true, Ordering::Relaxed);
    send_many(&a, 20);
    tokio::time::sleep(Duration::from_millis(300)).await;
    a.full.store(false, Ordering::Relaxed);
    let got = received(&mut b, 20, Duration::from_secs(3)).await;
    assert_eq!(got, (0..20).collect::<Vec<_>>());
    a.running.stop();
    b.running.stop();
}

// Legacy stopped reading awdl0 while it held a frame: the host keeps what
// the node can't, rather than the node dropping its oldest.
#[tokio::test(flavor = "multi_thread")]
async fn the_host_is_not_read_while_the_queue_is_full() {
    let (a, mut b) = pair().await;
    a.full.store(true, Ordering::Relaxed);
    send_many(&a, 1000);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let read = a.read.load(Ordering::Relaxed);
    assert!(read > 0 && read <= UNICAST_QUEUE, "read {read}");
    a.full.store(false, Ordering::Relaxed);
    let got = received(&mut b, 1000, Duration::from_secs(5)).await;
    assert_eq!(got, (0..1000).collect::<Vec<_>>());
    a.running.stop();
    b.running.stop();
}
