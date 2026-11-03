//! `Node` against frames crafted as an iPhone sends them: what it takes a
//! peer for, what it advertises (AWDL-12), when it sends (AWDL-16), and
//! what it hands the IP stack.

use owly_awdl::channel::{Encoding, SLOTS};
use owly_awdl::election::Election;
use owly_awdl::frame::{self, subtype};
use owly_awdl::sync::{SLOT_US, UNICAST_GUARD_US};
use owly_awdl::tlv::{self, HtCapabilities, Own};
use owly_awdl::{
    Action, Channel, Config, Input, Ipv6Packet, MacAddr, Node, Presence, RadioConstraints,
    Sequence, TU, Time,
};

const US: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
const PHONE: MacAddr = MacAddr([0x86, 0x08, 0x04, 0x8a, 0x2b, 0xf4]);
const START: Time = Time(10_000_000);

fn node(channel: u8, presence: Presence) -> Node {
    let radio = RadioConstraints {
        channel: Channel(channel),
        presence,
    };
    Node::new(Config::new(US, "owly", radio), START)
}

fn seq(channels: [u8; SLOTS]) -> Sequence {
    let mut s = Sequence::empty(Encoding::OpClass);
    for (slot, c) in s.slots.iter_mut().zip(channels) {
        if c != 0 {
            *slot = Channel(c).slot();
        }
    }
    s
}

/// An iPhone's action frame: master of its own tree with metric 600, at the
/// start of its AW `aw_counter`'s slot.
fn phone_frame(kind: u8, sequence: &Sequence, aw_counter: u16, next_tu: u16) -> Vec<u8> {
    frame_from(PHONE, kind, sequence, aw_counter, next_tu)
}

/// The same frame from any address.
fn frame_from(
    mac: MacAddr,
    kind: u8,
    sequence: &Sequence,
    aw_counter: u16,
    next_tu: u16,
) -> Vec<u8> {
    let mut e = Election::own(mac);
    e.self_metric = 600;
    e.master_metric = 600;
    let own = Own {
        addr: mac,
        name: "iPhone",
        devclass: tlv::devclass::IOS,
        channel: sequence.channel(0),
        master_channel: Channel(149),
        next_tu,
        aw_counter,
        psf_interval_tu: 110,
        sequence,
        election: &e,
        ht: Some(HtCapabilities::ONE_STREAM),
        tuned: false,
    };
    frame::action_frame(mac, 1, kind, 0, |out| {
        tlv::put_all(out, &own, kind == subtype::MIF)
    })
}

fn feed(n: &mut Node, at: Time, bytes: &[u8]) -> Vec<Action> {
    n.handle(Input::Frame {
        rx_time: at,
        rssi: Some(-40),
        bytes,
    })
    .collect()
}

fn tick(n: &mut Node, at: Time) -> Vec<Action> {
    n.handle(Input::Timer(at)).collect()
}

/// Has the phone become our master: a MIF, then the election's tick.
fn meet(n: &mut Node, sequence: &Sequence) -> Time {
    let t = START.plus(100_000);
    let a = feed(n, t, &phone_frame(subtype::MIF, sequence, 400, 64));
    assert!(
        a.iter()
            .any(|a| matches!(a, Action::PeerUp(p) if p.mac == PHONE))
    );
    let t = START.plus(1_000_000);
    // Heard again just before the tick, so its phase is current.
    feed(n, t, &phone_frame(subtype::PSF, sequence, 400 + 4 * 14, 64));
    tick(n, t);
    assert_eq!(n.election().sync, PHONE);
    t
}

fn tcp_syn() -> Ipv6Packet {
    let mut seg = vec![0u8; 20];
    seg[12] = 5 << 4;
    seg[13] = 0x02;
    let mut data = vec![0x60, 0, 0, 0, 0, 20, 6, 64];
    data.extend(PHONE.link_local().octets());
    data.extend(US.link_local().octets());
    data.extend(seg);
    Ipv6Packet {
        dst: US,
        src: PHONE,
        data,
    }
}

fn data_from_phone(p: &Ipv6Packet) -> Vec<u8> {
    frame::data_frame(PHONE, p.dst, 9, 9, &p.data)
}

fn transmits(actions: &[Action]) -> Vec<&frame::Frame> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Transmit { frame, .. } => Some(frame),
            _ => None,
        })
        .collect()
}

const PHONE_SEQ: [u8; SLOTS] = [149, 149, 149, 0, 0, 0, 0, 0, 6, 149, 149, 0, 0, 0, 0, 0];

// spec: AWDL-12
#[test]
fn a_fixed_radio_advertises_its_channel_in_every_slot() {
    let mut n = node(6, Presence::Fixed);
    meet(&mut n, &seq(PHONE_SEQ));
    assert_eq!(n.sequence().channels(), [6; SLOTS]);
}

// spec: AWDL-12
#[test]
fn a_shared_radio_advertises_only_the_masters_slots_on_its_channel() {
    let mut n = node(6, Presence::Share);
    meet(&mut n, &seq(PHONE_SEQ));
    let mut want = [0; SLOTS];
    want[8] = 6;
    assert_eq!(n.sequence().channels(), want);
    assert_eq!(n.no_overlap(), None);
    // A master with no slot on our channel: what we had stands, and the
    // host hears which channel the master is on instead.
    let mut n = node(44, Presence::Share);
    meet(&mut n, &seq(PHONE_SEQ));
    assert_eq!(n.sequence().channels(), [44; SLOTS]);
    assert!(n.stats().no_overlap > 0);
    assert_eq!(n.no_overlap(), Some((PHONE, 149)));
}

// spec: AWDL-17
#[test]
fn a_peer_is_valid_once_it_has_sent_a_mif_with_its_version() {
    let mut n = node(6, Presence::Fixed);
    let s = seq(PHONE_SEQ);
    let a = feed(&mut n, START, &phone_frame(subtype::PSF, &s, 400, 64));
    assert!(!a.iter().any(|a| matches!(a, Action::PeerUp(_))));
    assert!(!n.peer(PHONE).unwrap().valid);
    let a = feed(
        &mut n,
        START.plus(1000),
        &phone_frame(subtype::MIF, &s, 400, 63),
    );
    let up: Vec<_> = a
        .iter()
        .filter(|a| matches!(a, Action::PeerUp(_)))
        .collect();
    assert_eq!(up.len(), 1);
    let Action::PeerUp(info) = up[0] else {
        unreachable!()
    };
    assert_eq!(
        (info.mac, info.name.as_str(), info.devclass, info.rssi),
        (PHONE, "iPhone", 2, Some(-40))
    );
    // Only once.
    let a = feed(
        &mut n,
        START.plus(2000),
        &phone_frame(subtype::MIF, &s, 400, 62),
    );
    assert!(!a.iter().any(|a| matches!(a, Action::PeerUp(_))));
}

// spec: SEC-11
#[test]
fn spoofed_peers_cannot_fill_the_table() {
    let mut n = node(6, Presence::Fixed);
    let s = seq(PHONE_SEQ);
    let fake = |i: usize| MacAddr([0x02, 0xff, 0, 0, (i >> 8) as u8, i as u8]);
    for i in 0..owly_awdl::MAX_PEERS {
        let at = START.plus(i as u64 * 1000);
        feed(&mut n, at, &frame_from(fake(i), subtype::MIF, &s, 400, 64));
    }
    // The phone takes the place of the fake heard from longest ago.
    let at = START.plus(owly_awdl::MAX_PEERS as u64 * 1000);
    let a = feed(&mut n, at, &phone_frame(subtype::MIF, &s, 400, 64));
    assert!(
        a.iter()
            .any(|a| matches!(a, Action::PeerDown(m) if *m == fake(0)))
    );
    assert!(
        a.iter()
            .any(|a| matches!(a, Action::PeerUp(p) if p.mac == PHONE))
    );
    assert!(n.peer(fake(0)).is_none());
    assert!(n.peer(fake(1)).is_some());
    assert_eq!(n.stats().peers_evicted, 1);
}

// spec: AWDL-18
#[test]
fn a_syn_before_the_mif_is_held_until_the_peer_is_valid() {
    let mut n = node(6, Presence::Fixed);
    let s = seq(PHONE_SEQ);
    feed(&mut n, START, &phone_frame(subtype::PSF, &s, 400, 64));
    let syn = tcp_syn();
    let a = feed(&mut n, START.plus(10), &data_from_phone(&syn));
    assert!(!a.iter().any(|a| matches!(a, Action::Deliver(_))), "{a:?}");
    // Even from a peer we've never heard.
    let a = feed(&mut n, START.plus(20), &data_from_phone(&syn));
    assert!(!a.iter().any(|a| matches!(a, Action::Deliver(_))));
    let a = feed(
        &mut n,
        START.plus(30),
        &phone_frame(subtype::MIF, &s, 400, 63),
    );
    let up = a
        .iter()
        .position(|a| matches!(a, Action::PeerUp(_)))
        .expect("up");
    let delivered: Vec<usize> = a
        .iter()
        .enumerate()
        .filter(|(_, a)| matches!(a, Action::Deliver(p) if *p == syn))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(delivered.len(), 1, "the duplicate is held once");
    assert!(up < delivered[0], "the neighbour entry comes first");
}

// spec: AWDL-18
#[test]
fn held_syns_expire() {
    let mut n = node(6, Presence::Fixed);
    feed(&mut n, START, &data_from_phone(&tcp_syn()));
    tick(&mut n, START.plus(3_000_000));
    let a = feed(
        &mut n,
        START.plus(3_100_000),
        &phone_frame(subtype::MIF, &seq(PHONE_SEQ), 400, 63),
    );
    assert!(!a.iter().any(|a| matches!(a, Action::Deliver(_))));
}

// spec: AWDL-17, NET-3
#[test]
fn data_reaches_the_stack_only_from_peers_and_only_for_us() {
    let mut n = node(6, Presence::Fixed);
    let mut packet = Ipv6Packet::echo_request(PHONE, US, 1, 1, b"hi");
    // From a stranger: dropped.
    assert!(
        !feed(&mut n, START, &data_from_phone(&packet))
            .iter()
            .any(|a| matches!(a, Action::Deliver(_)))
    );
    meet(&mut n, &seq(PHONE_SEQ));
    let t = START.plus(1_100_000);
    let a = feed(&mut n, t, &data_from_phone(&packet));
    assert!(a.contains(&Action::Deliver(packet.clone())));
    // To someone else, which a monitor overhears.
    packet.dst = MacAddr([0x02, 9, 9, 9, 9, 9]);
    assert!(
        !feed(&mut n, t, &data_from_phone(&packet))
            .iter()
            .any(|a| matches!(a, Action::Deliver(_)))
    );
    // To a multicast group.
    packet.dst = MacAddr([0x33, 0x33, 0, 0, 0, 0xfb]);
    assert!(feed(&mut n, t, &data_from_phone(&packet)).contains(&Action::Deliver(packet.clone())));
    // Data keeps the peer alive without action frames (patch owl-07).
    let late = t.plus(4_500_000);
    feed(&mut n, late, &data_from_phone(&packet));
    assert!(
        !tick(&mut n, late.plus(1_000_000))
            .iter()
            .any(|a| matches!(a, Action::PeerDown(_)))
    );
    assert!(tick(&mut n, late.plus(5_100_000)).contains(&Action::PeerDown(PHONE)));
}

#[test]
fn what_the_stack_sends_to_nobody_is_dropped_and_to_us_comes_back() {
    let mut n = node(6, Presence::Fixed);
    let p = Ipv6Packet::echo_request(US, PHONE, 1, 1, b"x");
    let a: Vec<Action> = n
        .handle(Input::Outbound {
            now: START,
            packet: p,
        })
        .collect();
    assert!(transmits(&a).iter().all(|f| f.to != PHONE));
    assert_eq!(n.stats().dropped_no_peer, 1);
    let to_self = Ipv6Packet::echo_request(US, US, 1, 1, b"x");
    let a: Vec<Action> = n
        .handle(Input::Outbound {
            now: START,
            packet: to_self.clone(),
        })
        .collect();
    assert!(a.contains(&Action::Deliver(to_self)));
}

// spec: AWDL-16
#[test]
fn unicast_goes_only_in_shared_slots_clear_of_their_edges() {
    let mut n = node(6, Presence::Share);
    let phone = seq(PHONE_SEQ);
    let mut t = meet(&mut n, &phone);
    let p = Ipv6Packet::echo_request(US, PHONE, 1, 1, b"payload");
    let mut sent_at = None;
    n.handle(Input::Outbound { now: t, packet: p })
        .for_each(drop);
    for _ in 0..(32 * SLOT_US / 256) {
        t = t.plus(256);
        let a = tick(&mut n, t);
        if transmits(&a)
            .iter()
            .any(|f| f.to == PHONE && f.bytes.ends_with(b"payload"))
        {
            sent_at = Some(t);
            break;
        }
    }
    let t = sent_at.expect("never sent");
    let c = n.clock();
    assert_eq!(c.slot(t), 8, "slot 8 is the one both are on 6");
    let into = SLOT_US - c.next_slot_us(t);
    assert!(into >= UNICAST_GUARD_US, "{into} µs into the slot");
}

// spec: AWDL-12, AWDL-16
#[test]
fn a_fixed_radio_sends_unicast_in_every_slot_its_peer_is_on_its_channel_without_acks() {
    let mut phone = PHONE_SEQ;
    phone[3] = 6;
    let mut n = node(6, Presence::Fixed);
    let mut t = meet(&mut n, &seq(phone));
    let mut slots = std::collections::BTreeSet::new();
    for i in 0..6 {
        let p = Ipv6Packet::echo_request(US, PHONE, 1, i, b"payload");
        n.handle(Input::Outbound { now: t, packet: p })
            .for_each(drop);
        let mut sent = false;
        for _ in 0..(32 * SLOT_US / 256) {
            t = t.plus(256);
            let a = tick(&mut n, t);
            let ours = transmits(&a)
                .into_iter()
                .find(|f| f.to == PHONE && f.bytes.ends_with(b"payload"))
                .cloned();
            if let Some(f) = ours {
                assert!(f.no_ack, "patch owl-05: sent once, without an ACK");
                slots.insert(n.clock().slot(t));
                sent = true;
                break;
            }
        }
        assert!(sent, "packet {i} never sent");
        // Into the next slot, so the next packet finds the other one.
        t = t.plus(SLOT_US);
    }
    assert_eq!(slots.into_iter().collect::<Vec<_>>(), [3, 8]);
    // A shared radio waits for ACKs.
    let radio = n.config().radio.clone();
    let shared = RadioConstraints {
        presence: Presence::Share,
        ..radio
    };
    assert!(!Config::new(US, "owly", shared).no_ack);
}

#[test]
fn packets_for_a_peer_that_went_are_dropped_with_it() {
    // On 44, where the phone never is, so nothing goes.
    let mut n = node(44, Presence::Share);
    let t = meet(&mut n, &seq(PHONE_SEQ));
    let queued = t.plus(4_500_000);
    for i in 0..3 {
        let p = Ipv6Packet::echo_request(US, PHONE, 1, i, b"payload");
        n.handle(Input::Outbound {
            now: queued,
            packet: p,
        })
        .for_each(drop);
    }
    // Ours, and the node's own neighbour echoes.
    let queued = n.backlog();
    assert!(queued >= 3, "{queued}");
    // The phone times out with them still young: they go with it, rather
    // than holding up the host until they expire.
    assert!(tick(&mut n, t.plus(5_100_000)).contains(&Action::PeerDown(PHONE)));
    assert_eq!(n.backlog(), 0);
    assert_eq!(n.stats().dropped_no_peer, queued as u64);
    assert_eq!(n.stats().dropped_expired, 0);
    assert_eq!(n.no_overlap(), None, "no master, no overlap to miss");
}

// spec: AWDL-16
#[test]
fn multicast_goes_in_slots_0_and_10_or_any_slot_on_a_fixed_radio() {
    for (presence, slots) in [(Presence::Share, &[0usize, 10][..]), (Presence::Fixed, &[])] {
        let mut n = node(6, presence);
        let mut t = START;
        let group = MacAddr([0x33, 0x33, 0, 0, 0, 0xfb]);
        let mut sent = Vec::new();
        for i in 0..40u64 {
            let mut p = Ipv6Packet::echo_request(US, PHONE, 1, i as u16, b"m");
            p.dst = group;
            n.handle(Input::Outbound { now: t, packet: p })
                .for_each(drop);
            let end = t.plus(SLOT_US);
            while t < end {
                for f in transmits(&tick(&mut n, t)) {
                    if f.to == group {
                        sent.push(n.clock().slot(t));
                    }
                }
                t = t.plus(512);
            }
        }
        assert!(!sent.is_empty());
        if !slots.is_empty() {
            assert!(
                sent.iter().all(|s| slots.contains(s)),
                "{presence:?}: {sent:?}"
            );
        } else {
            let distinct: std::collections::BTreeSet<_> = sent.iter().collect();
            assert!(distinct.len() > 2, "{presence:?}: {sent:?}");
        }
    }
}

#[test]
fn psfs_every_110_tu_and_a_mif_every_slot() {
    let mut n = node(6, Presence::Fixed);
    let mut t = START;
    let (mut psf, mut mif) = (Vec::new(), Vec::new());
    while t < START.plus(1_000_000) {
        let a: Vec<Action> = n.handle(Input::Timer(t)).collect();
        for f in transmits(&a) {
            if let Ok(frame::Received::Action { subtype, .. }) = frame::parse(&f.bytes) {
                if subtype == subtype::PSF {
                    psf.push(t)
                } else {
                    mif.push(t)
                }
            }
        }
        let Some(Action::ArmTimer(next)) = a.last() else {
            panic!("no timer")
        };
        assert!(*next > t);
        t = *next;
    }
    assert_eq!(psf.first(), Some(&START.plus(110 * TU)));
    assert!(psf.windows(2).all(|w| w[1].since(w[0]) == 110 * TU));
    assert!((14..=16).contains(&mif.len()), "{} MIFs", mif.len());
    // The first goes at once, as legacy's did, and the rest mid-slot.
    assert!(
        mif[1..]
            .windows(2)
            .all(|w| w[1].since(w[0]).abs_diff(SLOT_US) < 2 * TU)
    );
}

#[test]
fn weak_frames_are_ignored_and_known_peers_kept_a_little_longer() {
    let mut n = node(6, Presence::Fixed);
    let f = phone_frame(subtype::MIF, &seq(PHONE_SEQ), 400, 64);
    n.handle(Input::Frame {
        rx_time: START,
        rssi: Some(-66),
        bytes: &f,
    })
    .for_each(drop);
    assert!(n.peer(PHONE).is_none());
    n.handle(Input::Frame {
        rx_time: START,
        rssi: Some(-60),
        bytes: &f,
    })
    .for_each(drop);
    n.handle(Input::Frame {
        rx_time: START.plus(1),
        rssi: Some(-69),
        bytes: &f,
    })
    .for_each(drop);
    assert_eq!(n.peer(PHONE).unwrap().rssi, Some(-69));
    n.handle(Input::Frame {
        rx_time: START.plus(2),
        rssi: Some(-71),
        bytes: &f,
    })
    .for_each(drop);
    assert_eq!(n.peer(PHONE).unwrap().rssi, Some(-69));
}

#[test]
fn a_malformed_frame_changes_nothing() {
    let mut n = node(6, Presence::Fixed);
    let mut f = phone_frame(subtype::MIF, &seq(PHONE_SEQ), 400, 64);
    f.push(21); // half a TLV header
    f.push(2);
    feed(&mut n, START, &f);
    assert!(n.peer(PHONE).is_none());
    assert_eq!(n.stats().rx_malformed, 1);
}

// spec: AWDL-15
#[test]
fn block_ack_sessions_are_accepted_only_when_asked_to() {
    let mut req = Vec::new();
    frame::put_header(&mut req, frame::fc::ACTION, US, PHONE, 3);
    req.extend_from_slice(&[3, 0, 9, 0x02, 0x10, 0, 0, 0, 0]);
    for accept in [false, true] {
        let mut n = node(6, Presence::Fixed);
        let mut cfg = n.config().clone();
        cfg.accept_addba = accept;
        n = Node::new(cfg, START);
        meet(&mut n, &seq(PHONE_SEQ));
        let a = feed(&mut n, START.plus(1_200_000), &req);
        let answered = transmits(&a)
            .iter()
            .any(|f| f.to == PHONE && f.bytes[24] == 3 && f.bytes[25] == 1);
        assert_eq!(answered, accept);
    }
}

#[test]
fn tuned_node_advertises_custom_metric_and_two_stream() {
    let radio = RadioConstraints {
        channel: Channel(6),
        presence: Presence::Fixed,
    };
    let mut cfg = Config::new(US, "owly", radio);
    cfg.election_metric = Some(550);
    let mut n = Node::new(cfg, START);
    let actions = tick(&mut n, START);
    let frame = transmits(&actions)[0];
    let tlvs = match frame::parse(&frame.bytes).unwrap() {
        frame::Received::Action { tlvs, .. } => tlvs,
        other => panic!("expected action frame, got {other:?}"),
    };
    let advert = tlv::Advert::parse(tlvs).unwrap();
    let election = advert.election.unwrap();
    assert_eq!(election.master_metric, 550);
    assert_eq!(election.self_metric, 550);
    let expected_counter = (START.micros() / 3_140_000) as u32;
    assert_eq!(election.master_counter, expected_counter);
    assert_eq!(election.self_counter, expected_counter);
    let ht = advert.ht.unwrap();
    assert_eq!(ht.capabilities, 0x11ee);
    assert!(ht.sgi20());
}
