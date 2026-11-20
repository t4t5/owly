//! Simulation tests: `Node`s on an in-memory medium with simulated clocks
//! and loss, converging on one master and passing IPv6 between them within
//! a bounded time.

mod sim;

use owly_awdl::sync::SLOT_US;
use owly_awdl::{Channel, Config, Presence, RadioConstraints};
use sim::{Sim, mac};

fn radio(channel: u8, presence: Presence) -> RadioConstraints {
    RadioConstraints {
        channel: Channel(channel),
        presence,
    }
}

fn config(n: u8, channel: u8, presence: Presence) -> Config {
    Config::new(mac(n), &format!("node{n}"), radio(channel, presence))
}

/// Within this, nodes that hear each other agree on a master and pass
/// IPv6: valid peers within a few slots, the election within its 1 s
/// tick, then a slot or two for the packet.
const CONVERGE_US: u64 = 3_000_000;

fn converge_and_ping(sim: &mut Sim) {
    let n = sim.nodes.len();
    let end = sim.now.plus(CONVERGE_US);
    let converged = sim.run_until(end, |s| {
        s.one_master().is_some() && (0..n).all(|i| (0..n).all(|j| i == j || s.valid(i, j)))
    });
    assert!(converged, "no single master after {CONVERGE_US} µs");
    let master = sim.one_master().unwrap();
    assert_eq!(
        master,
        mac(n as u8),
        "the highest address wins a tie of metrics"
    );
    // Everyone else's clock follows the master's.
    let m = (0..n)
        .find(|&i| sim.nodes[i].node.config().addr == master)
        .unwrap();
    sim.run_for(500_000);
    let now = sim.now;
    let master_slot = sim.nodes[m].node.clock().current_eaw(now);
    for (i, s) in sim.nodes.iter().enumerate() {
        let slot = s.node.clock().current_eaw(now);
        assert_eq!(slot, master_slot, "node {i} isn't in the master's slot");
        let off = s.node.clock().next_slot_us(now) as i64
            - sim.nodes[m].node.clock().next_slot_us(now) as i64;
        assert!(off.abs() < 2_000, "node {i} is {off} µs off the master");
    }
    // Packets both ways, within a period of the channel sequence.
    for (from, to) in [(0, n - 1), (n - 1, 0)] {
        let payload = format!("from {from} to {to}");
        sim.send(from, to, payload.as_bytes());
        let end = sim.now.plus(16 * SLOT_US);
        assert!(
            sim.run_until(end, |s| s.got(to, payload.as_bytes())),
            "{payload}: not delivered"
        );
    }
}

// spec: AWDL-7, AWDL-8
#[test]
fn two_fixed_radios_sync_and_pass_ipv6() {
    let mut sim = Sim::new(
        vec![config(1, 6, Presence::Fixed), config(2, 6, Presence::Fixed)],
        0,
        1,
    );
    converge_and_ping(&mut sim);
}

#[test]
fn three_nodes_with_loss() {
    let mut sim = Sim::new(
        vec![
            config(1, 44, Presence::Fixed),
            config(2, 44, Presence::Share),
            config(3, 44, Presence::Fixed),
        ],
        200,
        7,
    );
    converge_and_ping(&mut sim);
}

#[test]
fn nodes_on_different_channels_never_meet() {
    let mut sim = Sim::new(
        vec![
            config(1, 6, Presence::Fixed),
            config(2, 149, Presence::Fixed),
        ],
        0,
        5,
    );
    sim.run_for(3_000_000);
    assert!(!sim.valid(0, 1) && !sim.valid(1, 0));
    assert!(sim.nodes.iter().all(|n| n.node.election().is_master()));
}

// spec: AWDL-17
#[test]
fn a_silent_peer_is_dropped() {
    let mut sim = Sim::new(
        vec![config(1, 6, Presence::Fixed), config(2, 6, Presence::Fixed)],
        0,
        9,
    );
    let end = sim.now.plus(CONVERGE_US);
    assert!(sim.run_until(end, |s| s.valid(0, 1)));
    // Node 2 leaves for another channel and is never heard again.
    sim.nodes[1].channel = Channel(149);
    let end = sim.now.plus(7_000_000);
    assert!(sim.run_until(end, |s| !s.nodes[0].down.is_empty()));
    assert_eq!(sim.nodes[0].down[0].1, mac(2));
    assert!(sim.nodes[0].node.election().is_master());
}

// spec: OWLY-2
#[test]
fn neighbours_are_echoed_and_the_replies_kept_from_the_stack() {
    let mut sim = Sim::new(
        vec![config(1, 6, Presence::Fixed), config(2, 6, Presence::Fixed)],
        0,
        11,
    );
    sim.run_for(8_000_000);
    // Each node's echoes reach the other's IP stack, which would answer.
    for (i, node) in sim.nodes.iter().enumerate() {
        let echoes = node
            .delivered
            .iter()
            .filter(|(_, p)| p.data.len() > 40 && p.data[40] == 128 && p.data.ends_with(b"owly"))
            .count();
        assert!(echoes >= 1, "node {i} got no echo request");
    }
}
