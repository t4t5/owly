//! [`Node`]: an AWDL node as a state machine driven by explicit time.
//!
//! It runs what legacy's daemon ran on its event loop: a
//! PSF every 110 TU and a MIF in the middle of every slot, the peer table
//! swept and the election run every second, the channel sequence derived
//! from the sync master's, and data sent only in the slots a peer shares
//! with us, clear of the slot edges. Beyond legacy it holds a peer's TCP SYN
//! until the peer is valid, and sends each valid peer an ICMPv6 echo now
//! and then.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use crate::channel::{Channel, Sequence};
use crate::election::{Election, Ranking};
use crate::frame::{self, Frame, Received};
use crate::ip::Ipv6Packet;
use crate::peer::{Peer, PeerInfo};
use crate::rate::TxRate;
use crate::sync::{Clock, MULTICAST_GUARD_US, SLOT_US, UNICAST_GUARD_US};
use crate::tlv::{self, Advert, HtCapabilities, Own};
use crate::{MacAddr, TU, Time};

/// What a node is given.
#[derive(Debug)]
pub enum Input<'a> {
    /// A frame the radio received at `rx_time`, from its 802.11 MAC header
    /// on, without FCS, with its signal strength if the radio reports it.
    Frame {
        rx_time: Time,
        rssi: Option<i8>,
        bytes: &'a [u8],
    },
    /// The timer the node last asked for expired; or just the time now.
    Timer(Time),
    /// A packet the IP stack wants sent.
    Outbound { now: Time, packet: Ipv6Packet },
}

/// What a node asks of its host, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send `frame` now. `at` is the time the node decided to, from the
    /// input it was handling.
    Transmit { at: Time, frame: Frame },
    /// Call back with [`Input::Timer`] at this time, replacing any timer
    /// asked for before. Every input's actions end with one.
    ArmTimer(Time),
    /// A peer turned valid: give it a neighbour entry (NET-2), before the
    /// packets that follow.
    PeerUp(PeerInfo),
    /// A valid peer went quiet and was dropped.
    PeerDown(MacAddr),
    /// Hand this packet to the IP stack.
    Deliver(Ipv6Packet),
}

/// How a radio is present on AWDL: the one channel it stays on, and how.
/// Neither presence hops; a
/// radio that does would bring a third.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioConstraints {
    pub channel: Channel,
    pub presence: Presence,
}

/// How the radio's channel relates to the slots it advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The radio stays on `channel`, which it shares with something else
    /// (an AP), and advertises the master's slots on it and no others
    /// (AWDL-12). It ranks masters by counter first, as legacy did in shared
    /// mode.
    Share,
    /// The radio stays on `channel` and has it to itself: it advertises it
    /// in every slot (AWDL-12), sends multicast in any slot and unicast in
    /// every slot a peer is there. It ranks masters by metric first, as Apple
    /// devices do (AWDL-9), so it can impose its schedule.
    Fixed,
}

impl Presence {
    /// How a radio present this way ranks masters.
    pub const fn ranking(self) -> Ranking {
        match self {
            Presence::Share => Ranking::CounterFirst,
            Presence::Fixed => Ranking::MetricFirst,
        }
    }
}

/// A node's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The AWDL address (AWDL-2).
    pub addr: MacAddr,
    /// The host name for the ARPA TLV.
    pub name: String,
    pub radio: RadioConstraints,
    /// The data rate towards peers that receive it (see [`TxRate::for_peer`]).
    pub rate: TxRate,
    /// Send unicast data once, without waiting for an ACK. On by default
    /// for [`Presence::Fixed`], as legacy sent on every fixed radio (patch
    /// `owl-05`): a peer visits our channel for a slot or two, and a frame
    /// the hardware retries past the visit (15 times over 75-140 ms on an
    /// AX201) holds up every frame behind it. Lost, it costs a TCP
    /// retransmission instead.
    pub no_ack: bool,
    /// Accept a peer's Block Ack session (AWDL-15).
    pub accept_addba: bool,
    /// Send unicast packets to one peer as A-MSDUs, up to the peer's limit.
    pub amsdu: bool,
    /// The largest frame the radio takes, MAC header included.
    pub max_frame: usize,
    /// Peers heard more weakly than this, in dBm, aren't taken on; known
    /// ones are kept down to 5 dB below. `None` takes any.
    pub rssi_threshold: Option<i8>,
    /// Send each valid peer an ICMPv6 echo every few seconds.
    pub neighbour_echo: bool,
    /// Most peers tracked: [`MAX_PEERS`] by default.
    pub max_peers: usize,
    /// Custom sync master election metric.
    pub election_metric: Option<u32>,
}

impl Config {
    /// Legacy's defaults.
    pub fn new(addr: MacAddr, name: &str, radio: RadioConstraints) -> Config {
        let no_ack = radio.presence == Presence::Fixed;
        Config {
            addr,
            name: name.into(),
            radio,
            rate: TxRate::BASIC,
            no_ack,
            accept_addba: false,
            amsdu: false,
            max_frame: 2304,
            rssi_threshold: Some(-65),
            neighbour_echo: true,
            max_peers: MAX_PEERS,
            election_metric: None,
        }
    }
}

/// Counters, for diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub rx_action: u64,
    pub rx_data: u64,
    pub rx_malformed: u64,
    pub tx_action: u64,
    pub tx_unicast: u64,
    pub tx_multicast: u64,
    pub tx_amsdu: u64,
    pub delivered: u64,
    pub dropped_no_peer: u64,
    pub dropped_queue_full: u64,
    pub dropped_expired: u64,
    pub syn_held: u64,
    pub syn_released: u64,
    pub no_overlap: u64,
    pub peers_evicted: u64,
}

/// Announced in the Version TLV: macOS, as legacy announced.
const DEVCLASS: u8 = tlv::devclass::MACOS;
/// What the HT Capabilities TLV announces.
const HT: HtCapabilities = HtCapabilities::ONE_STREAM;
/// PSFs every 110 TU (§3.2).
const PSF_INTERVAL_TU: u16 = 110;
/// Peers unheard for this long are dropped: 5 s, as legacy patch `owl-07`
/// raised it from 2, since a busy iPhone can miss several of our slots in a
/// row.
const PEER_TIMEOUT_US: u64 = 5_000_000;
/// How often the peer table is swept and the election run.
const TICK_US: u64 = 1_000_000;
/// How often each valid peer gets an ICMPv6 echo.
const ECHO_US: u64 = 3_000_000;
/// The echoes' identifier and payload.
const ECHO_ID: u16 = 0x4f77;
const ECHO_PAYLOAD: &[u8] = b"owly";
/// Packets waiting longer than this for their slot are dropped.
const PACKET_EXPIRY_US: u64 = 2_000_000;
/// A held SYN waits this long for its peer to turn valid.
const SYN_HOLD_US: u64 = 2_000_000;
/// Unicast packets waiting for their peer's slot at most. Beyond it the
/// oldest is dropped, so a host should stop handing in packets while
/// [`Node::backlog`] is this long, as legacy stopped reading `awdl0`.
pub const UNICAST_QUEUE: usize = 128;
/// Multicast packets waiting at most, as many as legacy kept.
const MULTICAST_QUEUE: usize = 16;
const HELD_SYNS: usize = 128;
/// Most peers tracked by default. A new one beyond this takes the place of
/// the peer heard from longest ago, so spoofed peers can't lock a real one
/// out: a real peer is heard every few hundred milliseconds, and keeping
/// hundreds of fakes fresher than that takes more airtime than the channel
/// has (SEC-11).
pub const MAX_PEERS: usize = 512;
/// Frames sent for one input at most; the rest follow half a millisecond
/// later, so the host's queue isn't flooded.
const BURST: usize = 64;
const BURST_PAUSE_US: u64 = 500;
/// The most packets in one A-MSDU.
const AMSDU_PACKETS: usize = 8;
/// What a peer that announces no HT capabilities is assumed to take.
const AMSDU_DEFAULT_MAX: usize = 3839;

struct Queued {
    packet: Ipv6Packet,
    at: Time,
}

/// An AWDL node.
pub struct Node {
    cfg: Config,
    clock: Clock,
    election: Election,
    sequence: Sequence,
    peers: BTreeMap<MacAddr, Peer>,
    unicast: VecDeque<Queued>,
    multicast: VecDeque<Queued>,
    held: VecDeque<Queued>,
    seq: u16,
    awdl_seq: u16,
    echo_seq: u16,
    next_psf: Time,
    next_mif: Time,
    next_tick: Time,
    next_echo: Time,
    /// Set when a burst was cut short.
    resume: Option<Time>,
    /// The sync master and its channel, while its sequence has no slot on
    /// ours (a shared radio).
    no_overlap: Option<(MacAddr, u8)>,
    stats: Stats,
}

impl Node {
    pub fn new(cfg: Config, now: Time) -> Node {
        let clock = Clock::new(now);
        let mut election = Election::own(cfg.addr);
        if let Some(metric) = cfg.election_metric {
            election.set_metric(metric);
        }
        Node {
            election,
            sequence: Sequence::fixed(cfg.radio.channel),
            next_psf: now.plus(PSF_INTERVAL_TU as u64 * TU),
            next_mif: now,
            next_tick: now.plus(TICK_US),
            next_echo: now.plus(ECHO_US),
            clock,
            cfg,
            peers: BTreeMap::new(),
            unicast: VecDeque::new(),
            multicast: VecDeque::new(),
            held: VecDeque::new(),
            seq: 0,
            awdl_seq: 0,
            echo_seq: 0,
            resume: None,
            no_overlap: None,
            stats: Stats::default(),
        }
    }

    /// Takes one input and returns what to do about it, ending with the
    /// time to be called back.
    pub fn handle(&mut self, input: Input) -> impl Iterator<Item = Action> + use<> {
        let mut out = Vec::new();
        let now = match input {
            Input::Frame {
                rx_time,
                rssi,
                bytes,
            } => {
                self.receive(rx_time, rssi, bytes, &mut out);
                rx_time
            }
            Input::Timer(now) => now,
            Input::Outbound { now, packet } => {
                self.enqueue(now, packet, &mut out);
                now
            }
        };
        self.service(now, &mut out);
        out.push(Action::ArmTimer(self.deadline(now)));
        out.into_iter()
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    pub fn peer(&self, mac: MacAddr) -> Option<&Peer> {
        self.peers.get(&mac)
    }

    pub fn election(&self) -> &Election {
        &self.election
    }

    /// The channel sequence it advertises.
    pub fn sequence(&self) -> &Sequence {
        &self.sequence
    }

    pub fn clock(&self) -> &Clock {
        &self.clock
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Whether a frame to `to` may go now: for a host that couldn't send
    /// one when asked and wants to try again.
    pub fn may_send(&self, to: MacAddr, now: Time) -> bool {
        self.send_wait(to, now) == Some(0)
    }

    /// How long until a frame to `to` may go, 0 for now; `None` when `to`
    /// is no longer a peer, so the frame never will.
    pub fn send_wait(&self, to: MacAddr, now: Time) -> Option<u64> {
        if to.is_multicast() {
            return Some(self.multicast_wait(now));
        }
        self.peers.get(&to).map(|p| self.unicast_wait(p, now))
    }

    /// Unicast packets waiting for their peer's slot (see [`UNICAST_QUEUE`]).
    pub fn backlog(&self) -> usize {
        self.unicast.len()
    }

    /// While the radio shares its channel and the sync master's sequence has
    /// no slot on it: the master, and the channel it's on most. The node
    /// keeps advertising what it had meanwhile.
    pub fn no_overlap(&self) -> Option<(MacAddr, u8)> {
        self.no_overlap
    }

    fn next_seq(&mut self) -> u16 {
        let s = self.seq;
        self.seq = (s + 1) & 0x0fff;
        s
    }

    fn fixed(&self) -> bool {
        self.cfg.radio.presence == Presence::Fixed
    }

    fn receive(&mut self, now: Time, rssi: Option<i8>, bytes: &[u8], out: &mut Vec<Action>) {
        let parsed = match frame::parse(bytes) {
            Ok(p) => p,
            Err(_) => {
                self.stats.rx_malformed += 1;
                return;
            }
        };
        match parsed {
            Received::Action {
                header,
                subtype,
                tlvs,
                ..
            } if header.src != self.cfg.addr => {
                self.rx_action(now, rssi, header.src, subtype, tlvs, out)
            }
            Received::AddBaRequest {
                header,
                token,
                params,
                timeout,
            } if self.cfg.accept_addba
                && header.dst == self.cfg.addr
                && self.peers.contains_key(&header.src) =>
            {
                let seq = self.next_seq();
                let bytes =
                    frame::addba_response(self.cfg.addr, header.src, seq, token, params, timeout);
                out.push(Action::Transmit {
                    at: now,
                    frame: Frame {
                        bytes,
                        to: header.src,
                        rate: TxRate::BASIC,
                        no_ack: false,
                    },
                });
            }
            Received::Data {
                header,
                amsdu,
                body,
            } if header.src != self.cfg.addr => self.rx_data(now, &header, amsdu, body, out),
            _ => {}
        }
    }

    fn rx_action(
        &mut self,
        now: Time,
        rssi: Option<i8>,
        src: MacAddr,
        subtype: u8,
        tlvs: &[u8],
        out: &mut Vec<Action>,
    ) {
        let known = self.peers.contains_key(&src);
        if let (Some(threshold), Some(r)) = (self.cfg.rssi_threshold, rssi) {
            let floor = if known {
                threshold.saturating_sub(5)
            } else {
                threshold
            };
            if r < floor {
                return;
            }
        }
        // Parsed whole before anything changes.
        let Ok(advert) = Advert::parse(tlvs) else {
            self.stats.rx_malformed += 1;
            return;
        };
        if !known && self.peers.len() >= self.cfg.max_peers.max(1) {
            self.evict_stalest(out);
        }
        self.stats.rx_action += 1;
        let ours = self.election.sync == src;
        let peer = self.peers.entry(src).or_insert_with(|| Peer::new(src, now));
        peer.last_seen = now;
        if rssi.is_some() {
            peer.rssi = rssi;
        }
        let up = peer.absorb(&advert, subtype == frame::subtype::MIF);
        if let Some(s) = advert.sync {
            peer.sync_offset_us =
                Some(self.clock.error_tu(now, s.next_tu, s.aw_counter) * TU as i64);
            // AWDL-7: follow the master's schedule.
            if ours {
                self.clock.update(now, s.next_tu, s.aw_counter);
            }
        }
        if up {
            let info = peer.info();
            out.push(Action::PeerUp(info));
            self.release_syns(src, out);
        }
    }

    fn rx_data(
        &mut self,
        now: Time,
        header: &frame::Header,
        amsdu: bool,
        body: &[u8],
        out: &mut Vec<Action>,
    ) {
        let msdus = match frame::msdus(header, amsdu, body) {
            Ok(m) => m,
            Err(_) => {
                self.stats.rx_malformed += 1;
                return;
            }
        };
        self.stats.rx_data += 1;
        let src = header.src;
        let peer = self.peers.get_mut(&src);
        let (known, valid) = match peer {
            Some(p) => {
                // Data proves a peer is still there: an iPhone deep in a
                // transfer can go seconds between the action frames we hear
                // (patch `owl-07`).
                p.last_seen = now;
                (true, p.valid)
            }
            None => (false, false),
        };
        for m in msdus {
            // NET-3: IPv6 only. And never another node's unicast, which a
            // monitor hears too.
            if m.ethertype != 0x86dd || !(m.dst == self.cfg.addr || m.dst.is_multicast()) {
                continue;
            }
            let packet = Ipv6Packet {
                dst: m.dst,
                src: m.src,
                data: m.payload.to_vec(),
            };
            if valid {
                if packet.dst == self.cfg.addr && packet.is_echo_reply(ECHO_ID) {
                    continue;
                }
                self.stats.delivered += 1;
                out.push(Action::Deliver(packet));
            } else if packet.is_bare_syn_to(self.cfg.addr) {
                // A phone can open its connection before the MIF that makes
                // it valid. Delivered now, the kernel's answer would wait on
                // a neighbour entry that doesn't exist yet.
                self.hold_syn(now, packet);
            } else if known {
                // Legacy handed on data from any peer in its table.
                self.stats.delivered += 1;
                out.push(Action::Deliver(packet));
            }
        }
    }

    fn hold_syn(&mut self, now: Time, packet: Ipv6Packet) {
        if self.held.iter().any(|q| q.packet == packet) {
            return;
        }
        if self.held.len() == HELD_SYNS {
            self.held.pop_front();
        }
        self.stats.syn_held += 1;
        self.held.push_back(Queued { packet, at: now });
    }

    fn release_syns(&mut self, src: MacAddr, out: &mut Vec<Action>) {
        let held = core::mem::take(&mut self.held);
        for q in held {
            if q.packet.src == src {
                self.stats.syn_released += 1;
                self.stats.delivered += 1;
                out.push(Action::Deliver(q.packet));
            } else {
                self.held.push_back(q);
            }
        }
    }

    fn enqueue(&mut self, now: Time, packet: Ipv6Packet, out: &mut Vec<Action>) {
        if packet.dst == self.cfg.addr {
            out.push(Action::Deliver(packet));
            return;
        }
        let queue = if packet.dst.is_multicast() {
            if self.multicast.len() == MULTICAST_QUEUE {
                self.multicast.pop_front();
                self.stats.dropped_queue_full += 1;
            }
            &mut self.multicast
        } else {
            if !self.peers.contains_key(&packet.dst) {
                self.stats.dropped_no_peer += 1;
                return;
            }
            if self.unicast.len() == UNICAST_QUEUE {
                self.unicast.pop_front();
                self.stats.dropped_queue_full += 1;
            }
            &mut self.unicast
        };
        queue.push_back(Queued { packet, at: now });
    }

    fn service(&mut self, now: Time, out: &mut Vec<Action>) {
        if now >= self.next_tick {
            self.tick(now, out);
            while self.next_tick <= now {
                self.next_tick = self.next_tick.plus(TICK_US);
            }
        }
        if now >= self.next_psf {
            let f = self.action_frame(now, frame::subtype::PSF);
            out.push(Action::Transmit { at: now, frame: f });
            let interval = PSF_INTERVAL_TU as u64 * TU;
            while self.next_psf <= now {
                self.next_psf = self.next_psf.plus(interval);
            }
        }
        if now >= self.next_mif {
            // In the middle of the slot.
            let f = self.action_frame(now, frame::subtype::MIF);
            out.push(Action::Transmit { at: now, frame: f });
            self.next_mif = now.plus(self.clock.next_slot_us(now) + SLOT_US / 2);
        }
        if self.cfg.neighbour_echo && now >= self.next_echo {
            self.next_echo = now.plus(ECHO_US);
            self.echo_seq = self.echo_seq.wrapping_add(1);
            let peers: Vec<MacAddr> = self
                .peers
                .values()
                .filter(|p| p.valid)
                .map(|p| p.mac)
                .collect();
            for mac in peers {
                let p = Ipv6Packet::echo_request(
                    self.cfg.addr,
                    mac,
                    ECHO_ID,
                    self.echo_seq,
                    ECHO_PAYLOAD,
                );
                self.enqueue(now, p, out);
            }
        }
        self.resume = None;
        let mut sent = 0;
        self.send_multicast(now, &mut sent, out);
        self.send_unicast(now, &mut sent, out);
        if sent >= BURST {
            self.resume = Some(now.plus(BURST_PAUSE_US));
        }
    }

    /// Drops the peer heard from longest ago. The election runs without it
    /// at the next tick, as for one that timed out.
    fn evict_stalest(&mut self, out: &mut Vec<Action>) {
        let Some(stalest) = self.peers.values().min_by_key(|p| p.last_seen) else {
            return;
        };
        let (mac, valid) = (stalest.mac, stalest.valid);
        self.peers.remove(&mac);
        self.stats.peers_evicted += 1;
        if valid {
            out.push(Action::PeerDown(mac));
        }
    }

    fn tick(&mut self, now: Time, out: &mut Vec<Action>) {
        let gone: Vec<(MacAddr, bool)> = self
            .peers
            .values()
            .filter(|p| now.since(p.last_seen) > PEER_TIMEOUT_US)
            .map(|p| (p.mac, p.valid))
            .collect();
        for (mac, valid) in gone {
            self.peers.remove(&mac);
            if valid {
                out.push(Action::PeerDown(mac));
            }
        }
        // Packets for a peer that's gone never go, and would hold up the
        // host until they expired.
        let before = self.unicast.len();
        let peers = &self.peers;
        self.unicast.retain(|q| peers.contains_key(&q.packet.dst));
        self.stats.dropped_no_peer += (before - self.unicast.len()) as u64;
        let expired = |q: &Queued, limit: u64| now.since(q.at) >= limit;
        let before = self.unicast.len() + self.multicast.len();
        self.unicast.retain(|q| !expired(q, PACKET_EXPIRY_US));
        self.multicast.retain(|q| !expired(q, PACKET_EXPIRY_US));
        self.stats.dropped_expired += (before - self.unicast.len() - self.multicast.len()) as u64;
        self.held.retain(|q| !expired(q, SYN_HOLD_US));
        let ranking = self.cfg.radio.presence.ranking();
        self.election.run(
            self.peers.values().filter(|p| p.valid).map(|p| &p.election),
            ranking,
        );
        self.adopt_sequence();
    }

    /// The sequence to advertise: derived from the sync master's, as the
    /// radio's presence allows.
    fn adopt_sequence(&mut self) {
        let home = self.cfg.radio.channel;
        let master = if self.election.is_master() {
            None
        } else {
            self.peers.get(&self.election.sync).and_then(|p| p.sequence)
        };
        self.no_overlap = None;
        self.sequence = match (self.cfg.radio.presence, master) {
            (Presence::Fixed, _) | (_, None) => Sequence::fixed(home),
            (Presence::Share, Some(theirs)) => {
                let (ours, kept) = theirs.intersect(home.0);
                if kept == 0 {
                    // Rather than announce that we're never available,
                    // which would have the phone stop addressing us, keep
                    // what we had.
                    self.stats.no_overlap += 1;
                    self.no_overlap = Some((self.election.sync, theirs.dominant(0)));
                    return;
                }
                ours
            }
        };
    }

    fn action_frame(&mut self, now: Time, subtype: u8) -> Frame {
        let seq = self.next_seq();
        if self.election.is_master() && self.election.custom_metric {
            let counter = (now.micros() / 3_140_000) as u32;
            self.election.master_counter = counter;
            self.election.self_counter = counter;
        }
        let ht = if self.election.custom_metric {
            HtCapabilities::TWO_STREAM_SGI
        } else {
            HT
        };
        let own = Own {
            addr: self.cfg.addr,
            name: &self.cfg.name,
            devclass: DEVCLASS,
            channel: self.cfg.radio.channel.0,
            master_channel: self.cfg.radio.channel,
            next_tu: self.clock.next_slot_tu(now),
            aw_counter: self.clock.current_aw(now),
            psf_interval_tu: PSF_INTERVAL_TU,
            sequence: &self.sequence,
            election: &self.election,
            ht: Some(ht),
            tuned: self.election.custom_metric,
        };
        let mif = subtype == frame::subtype::MIF;
        let bytes = frame::action_frame(self.cfg.addr, seq, subtype, now.micros() as u32, |out| {
            tlv::put_all(out, &own, mif)
        });
        self.stats.tx_action += 1;
        Frame {
            bytes,
            to: MacAddr::BROADCAST,
            rate: TxRate::BASIC,
            no_ack: false,
        }
    }

    /// The channel we're on in slot `slot` as far as sending goes.
    fn own_channel(&self, slot: usize) -> u8 {
        if self.fixed() {
            self.cfg.radio.channel.0
        } else {
            self.sequence.channel(slot)
        }
    }

    fn same_channel(&self, peer: &Peer, t: Time) -> bool {
        let slot = self.clock.slot(t);
        let own = self.own_channel(slot);
        let theirs = peer.sequence.map_or(0, |s| s.channel(slot));
        own != 0 && own == theirs
    }

    /// AWDL-16: how long until unicast to `peer` may go, 0 for now: in a
    /// slot both are on the same channel, clear of the 3 TU guard at its
    /// edges unless the neighbouring slot is shared too.
    fn unicast_wait(&self, peer: &Peer, now: Time) -> u64 {
        let next = self.clock.next_slot_us(now);
        if !self.same_channel(peer, now) {
            return next;
        }
        let g = UNICAST_GUARD_US;
        if next < g {
            if self.same_channel(peer, now.plus(SLOT_US)) {
                0
            } else {
                next + g
            }
        } else if SLOT_US - next < g {
            if self.same_channel(peer, now.minus(SLOT_US)) {
                0
            } else {
                g - (SLOT_US - next)
            }
        } else {
            0
        }
    }

    /// AWDL-16: how long until multicast may go: in slots 0 and 10, where
    /// Apple devices send it, clear of a 16 TU guard. A fixed radio sends
    /// it in any slot with the unicast guard, since the first AW may be all
    /// a peer spends on its channel (patch `owl-03`).
    fn multicast_wait(&self, now: Time) -> u64 {
        let guard = if self.fixed() {
            UNICAST_GUARD_US
        } else {
            MULTICAST_GUARD_US
        };
        let wait = self.clock.edge_wait(now, guard);
        if wait > 0 || self.fixed() || matches!(self.clock.slot(now), 0 | 10) {
            return wait;
        }
        self.clock.next_slot_us(now) + guard
    }

    fn send_multicast(&mut self, now: Time, sent: &mut usize, out: &mut Vec<Action>) {
        while *sent < BURST && !self.multicast.is_empty() && self.multicast_wait(now) == 0 {
            let q = self.multicast.pop_front().expect("not empty");
            let seq = self.next_seq();
            let awdl_seq = self.awdl_seq;
            self.awdl_seq = self.awdl_seq.wrapping_add(1);
            let bytes =
                frame::data_frame(self.cfg.addr, q.packet.dst, seq, awdl_seq, &q.packet.data);
            self.stats.tx_multicast += 1;
            *sent += 1;
            out.push(Action::Transmit {
                at: now,
                frame: Frame {
                    bytes,
                    to: q.packet.dst,
                    rate: self.cfg.rate.for_peer(None),
                    no_ack: false,
                },
            });
        }
    }

    fn send_unicast(&mut self, now: Time, sent: &mut usize, out: &mut Vec<Action>) {
        if self.unicast.is_empty() {
            return;
        }
        let mut waiting: VecDeque<Queued> = VecDeque::new();
        let mut items: VecDeque<Queued> = core::mem::take(&mut self.unicast);
        let mut blocked: Vec<MacAddr> = Vec::new();
        while let Some(q) = items.pop_front() {
            let dst = q.packet.dst;
            let open = *sent < BURST
                && !blocked.contains(&dst)
                && self
                    .peers
                    .get(&dst)
                    .is_some_and(|p| self.unicast_wait(p, now) == 0);
            if !open {
                if !blocked.contains(&dst) {
                    blocked.push(dst);
                }
                waiting.push_back(q);
                continue;
            }
            let peer = &self.peers[&dst];
            let rate = self.cfg.rate.for_peer(peer.ht.as_ref());
            let mut batch = Vec::from([q]);
            if self.cfg.amsdu && peer.ht.is_some() {
                let limit = peer
                    .ht
                    .map_or(AMSDU_DEFAULT_MAX, |h| h.max_amsdu())
                    .min(self.cfg.max_frame.saturating_sub(frame::HEADER_LEN + 2));
                let mut len = frame::amsdu_subframe_len(batch[0].packet.data.len());
                let mut rest = VecDeque::new();
                while let Some(next) = items.pop_front() {
                    let add = frame::amsdu_subframe_len(next.packet.data.len()) + 3;
                    if next.packet.dst == dst && batch.len() < AMSDU_PACKETS && len + add <= limit {
                        len += add;
                        batch.push(next);
                    } else {
                        rest.push_back(next);
                    }
                }
                items = rest;
            }
            let seq = self.next_seq();
            let awdl_seq = self.awdl_seq;
            self.awdl_seq = self.awdl_seq.wrapping_add(batch.len() as u16);
            let bytes = if batch.len() == 1 {
                frame::data_frame(self.cfg.addr, dst, seq, awdl_seq, &batch[0].packet.data)
            } else {
                let packets: Vec<&[u8]> = batch.iter().map(|q| q.packet.data.as_slice()).collect();
                self.stats.tx_amsdu += 1;
                frame::amsdu_frame(self.cfg.addr, dst, seq, awdl_seq, &packets)
            };
            self.stats.tx_unicast += batch.len() as u64;
            *sent += 1;
            out.push(Action::Transmit {
                at: now,
                frame: Frame {
                    bytes,
                    to: dst,
                    rate,
                    no_ack: self.cfg.no_ack,
                },
            });
        }
        self.unicast = waiting;
    }

    /// When to be called back.
    fn deadline(&self, now: Time) -> Time {
        let mut t = self.next_tick.min(self.next_psf).min(self.next_mif);
        if self.cfg.neighbour_echo {
            t = t.min(self.next_echo);
        }
        if let Some(r) = self.resume {
            t = t.min(r);
        }
        if !self.multicast.is_empty() {
            t = t.min(now.plus(self.multicast_wait(now).max(1)));
        }
        let mut seen: Vec<MacAddr> = Vec::new();
        for q in &self.unicast {
            if seen.contains(&q.packet.dst) {
                continue;
            }
            seen.push(q.packet.dst);
            if let Some(p) = self.peers.get(&q.packet.dst) {
                t = t.min(now.plus(self.unicast_wait(p, now).max(1)));
            }
        }
        t.max(now)
    }
}
