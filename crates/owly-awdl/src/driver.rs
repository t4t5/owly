//! The driver (the `driver` feature): a [`Node`] run on any radio that can
//! inject and capture 802.11 frames, on std and tokio.
//!
//! A backend brings such a radio up, then hands the driver its two ends:
//! the [`Air`], where the node's frames go out and the peers' come in, and
//! the [`Netif`], the host's network interface for the link (a TAP device
//! on Linux), where IPv6 packets come and go. A monitor interface on the
//! computer and a radio elsewhere, an ESP32 over USB say, differ only in
//! their `Air`.
//!
//! [`spawn`] runs the node on a thread of its own with a single-threaded
//! tokio runtime, so nothing else in the process delays its timers. It logs
//! how late they fire.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::string::{String, ToString};
use std::time::{Duration, Instant};
use std::vec::Vec;

use tokio::sync::watch;

use crate::frame::Frame;
use crate::{Action, Config, Input, Ipv6Packet, MacAddr, Node, PeerInfo, Time, UNICAST_QUEUE};

/// Unicast the radio couldn't take is kept for its peer's next slot, as
/// legacy kept it (patch `owl-07`: dropped, 8383 frames in one 34 MB receive
/// on an Intel card, among them the TCP ACKs the phone was waiting for, so
/// uploads died just short of the end), for at most this long: the node's
/// own expiry for packets waiting on a slot.
const UNICAST_HOLD_US: u64 = 2_000_000;
/// Multicast the radio couldn't take is tried again while its slot lasts,
/// for at most this long.
const RETRY_US: u64 = 100_000;
/// How soon to try again once the radio's queue was full.
const RETRY_PAUSE: Duration = Duration::from_micros(500);
const STATS_EVERY: Duration = Duration::from_secs(10);

/// A frame heard on the air.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// From the 802.11 MAC header on, without FCS.
    pub bytes: Vec<u8>,
    /// dBm, when the radio reports it.
    pub rssi: Option<i8>,
}

/// Where the node's frames go out and the peers' come in: a radio that
/// injects and captures 802.11 frames, wrapped however it needs them
/// (radiotap, on a Linux monitor interface).
pub trait Air {
    /// The next frame heard. Dropping the future before it's done loses no
    /// frame, since the driver races it against its timers.
    fn recv(&mut self) -> impl Future<Output = io::Result<Received>>;

    /// Hands a frame to the radio without waiting, at its rate and with or
    /// without an ACK as it says. Gives it back when the radio's queue is
    /// full, to be tried again; a frame the radio refuses for any other
    /// reason is the radio's to log, and dropped.
    fn send(&mut self, frame: Frame) -> Result<(), Frame>;
}

/// The host's end of the link: the network interface its IPv6 sockets use
/// (a TAP device on Linux, a Wintun adapter on Windows).
pub trait Netif {
    /// The next IPv6 packet the host sends on the link. Dropping the future
    /// loses no packet, as with [`Air::recv`].
    fn recv(&mut self) -> impl Future<Output = io::Result<Ipv6Packet>>;

    /// Hands the host a packet from a peer. One it can't take now is
    /// dropped, as a full queue would drop it.
    fn deliver(&mut self, packet: Ipv6Packet);

    /// A peer turned valid, and may be reached from now on: an interface
    /// that keeps neighbour entries gets one for its link-local address
    /// (NET-2).
    fn peer_up(&mut self, _mac: MacAddr) {}

    /// A peer went away.
    fn peer_down(&mut self, _mac: MacAddr) {}
}

/// A node running on its own thread.
pub struct Running {
    stop: watch::Sender<bool>,
    failed: watch::Receiver<Option<String>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Starts a node with `cfg` on a thread of its own, between the [`Air`] and
/// [`Netif`] that `open` makes, publishing its valid peers on `peers`.
/// `open` runs on that thread, inside its runtime, so it can register
/// descriptors with it; when it fails, so does this.
pub fn spawn<A, N, F>(
    cfg: Config,
    open: F,
    peers: watch::Sender<Vec<PeerInfo>>,
) -> io::Result<Running>
where
    A: Air + 'static,
    N: Netif + 'static,
    F: FnOnce() -> io::Result<(A, N)> + Send + 'static,
{
    let (stop, stopped) = watch::channel(false);
    let (failed_tx, failed) = watch::channel(None);
    let (opened_tx, opened) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name("owly-awdl".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = opened_tx.send(Err(e));
                    return;
                }
            };
            let _entered = rt.enter();
            let (air, netif) = match open() {
                Ok(ends) => {
                    let _ = opened_tx.send(Ok(()));
                    ends
                }
                Err(e) => {
                    let _ = opened_tx.send(Err(e));
                    return;
                }
            };
            let result = rt.block_on(run(Driver {
                node: Node::new(cfg, Time(1)),
                epoch: Instant::now(),
                air,
                netif,
                peers,
                stopped,
                unicast: VecDeque::new(),
                multicast: VecDeque::new(),
                full: false,
                overlap: None,
                tx: TxStats::default(),
                timer: Time(1),
                lateness: Lateness::default(),
            }));
            if let Err(why) = result {
                tracing::warn!("AWDL stopped: {why}");
                failed_tx.send_replace(Some(why));
            }
        })?;
    let running = Running {
        stop,
        failed,
        thread: Some(thread),
    };
    match opened.recv() {
        Ok(Ok(())) => Ok(running),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::other("the AWDL thread ended before it started")),
    }
}

impl Running {
    /// Why the node stopped by itself, once it has: the radio or the host's
    /// interface failed.
    pub fn failed(&self) -> watch::Receiver<Option<String>> {
        self.failed.clone()
    }

    /// Stops the node, and waits for its thread, which drops the [`Air`]
    /// and [`Netif`].
    pub fn stop(mut self) {
        let _ = self.stop.send(true);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

/// How late the node's timers fire, in µs.
#[derive(Default)]
struct Lateness {
    count: u64,
    total: u64,
    max: u64,
}

/// What the radio refused.
#[derive(Default)]
struct TxStats {
    /// Frames it had no room for, each time.
    again: u64,
    /// Frames given up on: action frames at once, others when their peer
    /// went or their time ran out.
    dropped: u64,
}

struct Driver<A, N> {
    node: Node,
    epoch: Instant,
    air: A,
    netif: N,
    peers: watch::Sender<Vec<PeerInfo>>,
    stopped: watch::Receiver<bool>,
    /// Data frames the radio had no room for, with when the node sent them.
    unicast: VecDeque<(Time, Frame)>,
    multicast: VecDeque<(Time, Frame)>,
    /// The radio's queue was full at the last try.
    full: bool,
    /// The no-overlap last logged.
    overlap: Option<(MacAddr, u8)>,
    tx: TxStats,
    timer: Time,
    lateness: Lateness,
}

impl<A: Air, N: Netif> Driver<A, N> {
    fn now(&self) -> Time {
        Time(self.epoch.elapsed().as_micros() as u64 + 1)
    }

    fn instant(&self, t: Time) -> tokio::time::Instant {
        tokio::time::Instant::from_std(self.epoch + Duration::from_micros(t.0.saturating_sub(1)))
    }

    fn handle(&mut self, input: Input) {
        let actions: Vec<Action> = self.node.handle(input).collect();
        for a in actions {
            match a {
                Action::Transmit { at, frame } => self.transmit(at, frame),
                Action::ArmTimer(t) => self.timer = t,
                Action::PeerUp(p) => {
                    tracing::info!("add peer {} ({})", p.mac, p.name);
                    self.netif.peer_up(p.mac);
                    self.publish_peers();
                }
                Action::PeerDown(m) => {
                    tracing::info!("remove peer {m}");
                    self.netif.peer_down(m);
                    self.publish_peers();
                }
                Action::Deliver(p) => self.netif.deliver(p),
            }
        }
        self.log_overlap();
    }

    /// Says when a shared radio's channel stops or starts overlapping the
    /// master's sequence, as legacy's `NO OVERLAP` line did: the phone then
    /// never addresses us, and nothing else explains the silence.
    fn log_overlap(&mut self) {
        let now = self.node.no_overlap();
        if now == self.overlap {
            return;
        }
        match now {
            Some((master, wants)) => tracing::info!(
                "NO OVERLAP with {master} on ch {} - peer wants ch {wants}",
                self.node.config().radio.channel.0
            ),
            None => tracing::info!("overlap with the master's sequence again"),
        }
        self.overlap = now;
    }

    fn transmit(&mut self, at: Time, frame: Frame) {
        let cfg = self.node.config();
        if cfg.unicast_groups && frame.to.is_multicast() {
            let no_ack = cfg.no_ack;
            // A peer address comes from the air. A group address would
            // recurse into this branch and could never be a unicast copy.
            let peers: Vec<MacAddr> = self
                .node
                .peers()
                .map(|p| p.mac)
                .filter(|mac| !mac.is_multicast())
                .collect();
            for mac in peers {
                let mut copy = frame.clone();
                copy.bytes[4..10].copy_from_slice(&mac.0);
                copy.to = mac;
                copy.no_ack = no_ack;
                self.transmit(at, copy);
            }
            return;
        }
        if frame.is_action() {
            // Built for this moment, its sync TLVs and timestamp with it: by
            // the next try it would be stale, and the next PSF or MIF is
            // never far off. Legacy dropped them too.
            if self.air.send(frame).is_err() {
                self.full = true;
                self.tx.again += 1;
                self.tx.dropped += 1;
            }
            return;
        }
        let queue = if frame.to.is_multicast() {
            &mut self.multicast
        } else {
            &mut self.unicast
        };
        if !queue.is_empty() {
            // In order behind those already waiting.
            queue.push_back((at, frame));
            return;
        }
        if let Err(frame) = self.air.send(frame) {
            self.full = true;
            self.tx.again += 1;
            queue.push_back((at, frame));
        }
    }

    /// Tries again what the radio had no room for, while it may still go,
    /// until the radio refuses one again.
    fn flush_retries(&mut self) {
        let now = self.now();
        self.full = false;
        while let Some((at, frame)) = self.multicast.pop_front() {
            // Only while its slot lasts.
            if now.since(at) > RETRY_US || !self.node.may_send(frame.to, now) {
                self.tx.dropped += 1;
                continue;
            }
            if let Err(frame) = self.air.send(frame) {
                self.multicast.push_front((at, frame));
                self.full = true;
                self.tx.again += 1;
                break;
            }
        }
        // Unicast waits for its peer's next slot, in order for each peer.
        let mut kept = VecDeque::new();
        while let Some((at, frame)) = self.unicast.pop_front() {
            match self.node.send_wait(frame.to, now) {
                None => self.tx.dropped += 1,
                Some(_) if now.since(at) > UNICAST_HOLD_US => self.tx.dropped += 1,
                Some(0) if !self.full => {
                    if let Err(frame) = self.air.send(frame) {
                        self.full = true;
                        self.tx.again += 1;
                        kept.push_back((at, frame));
                    }
                }
                Some(_) => kept.push_back((at, frame)),
            }
        }
        self.unicast = kept;
    }

    /// When to try the frames waiting again, if any are.
    fn retry_at(&self) -> Option<tokio::time::Instant> {
        if self.full || !self.multicast.is_empty() {
            return Some(tokio::time::Instant::now() + RETRY_PAUSE);
        }
        let now = self.now();
        // A peer that's gone (no wait) has its frames dropped at once.
        let wait = self
            .unicast
            .iter()
            .map(|(_, f)| self.node.send_wait(f.to, now).unwrap_or(0))
            .min()?;
        Some(self.instant(now.plus(wait.max(1))))
    }

    /// Whether to read the host's next packet. Not while as many as the
    /// node queues wait already, as legacy stopped reading `awdl0` while it
    /// held a frame: the host's queue holds them meanwhile, and drops the newest
    /// when full rather than the node dropping its oldest.
    fn takes_outbound(&self) -> bool {
        self.node.backlog() + self.unicast.len() < UNICAST_QUEUE
    }

    fn publish_peers(&self) {
        let peers: Vec<PeerInfo> = self
            .node
            .peers()
            .filter(|p| p.valid)
            .map(|p| p.info())
            .collect();
        self.peers.send_if_modified(|p| {
            let changed = *p != peers;
            if changed {
                p.clone_from(&peers);
            }
            changed
        });
    }

    fn log_stats(&mut self) {
        let s = self.node.stats();
        let l = &self.lateness;
        tracing::info!(
            "STATS tx_action {} tx_unicast {} tx_multicast {} tx_amsdu {} | radio full {} gave up {} | rx_action {} rx_data {} rx_malformed {} delivered {} | dropped no_peer {} queue {} expired {} | syn held {} released {} | no_overlap {} | timer late avg {} µs max {} µs",
            s.tx_action,
            s.tx_unicast,
            s.tx_multicast,
            s.tx_amsdu,
            self.tx.again,
            self.tx.dropped,
            s.rx_action,
            s.rx_data,
            s.rx_malformed,
            s.delivered,
            s.dropped_no_peer,
            s.dropped_queue_full,
            s.dropped_expired,
            s.syn_held,
            s.syn_released,
            s.no_overlap,
            l.total.checked_div(l.count).unwrap_or(0),
            l.max,
        );
        self.lateness = Lateness::default();
    }
}

async fn run<A: Air, N: Netif>(mut d: Driver<A, N>) -> Result<(), String> {
    let mut stats = tokio::time::interval(STATS_EVERY);
    let mut peers = tokio::time::interval(Duration::from_secs(1));
    let now = d.now();
    d.handle(Input::Timer(now));
    loop {
        let wake = match d.retry_at() {
            Some(retry) => d.instant(d.timer).min(retry),
            None => d.instant(d.timer),
        };
        tokio::select! {
            biased;
            _ = d.stopped.changed() => return Ok(()),
            r = d.air.recv() => match r {
                Ok(rx) => {
                    let now = d.now();
                    d.handle(Input::Frame { rx_time: now, rssi: rx.rssi, bytes: &rx.bytes });
                }
                Err(e) => return Err(e.to_string()),
            },
            r = d.netif.recv(), if d.takes_outbound() => match r {
                Ok(packet) => {
                    let now = d.now();
                    d.handle(Input::Outbound { now, packet });
                }
                Err(e) => return Err(e.to_string()),
            },
            _ = tokio::time::sleep_until(wake) => {
                let now = d.now();
                if now >= d.timer {
                    let late = now.since(d.timer);
                    let l = &mut d.lateness;
                    l.count += 1;
                    l.total += late;
                    l.max = l.max.max(late);
                    d.handle(Input::Timer(now));
                }
            }
            _ = stats.tick() => d.log_stats(),
            _ = peers.tick() => d.publish_peers(),
        }
        d.flush_retries();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_map_onto_instants() {
        let t = Time(1_000_001);
        let epoch = Instant::now();
        let at = epoch + Duration::from_micros(t.0 - 1);
        assert_eq!(at.duration_since(epoch), Duration::from_secs(1));
    }
}
