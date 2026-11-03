//! Sync master election (docs/SPEC.md §3.3, AWDL-7–9), as legacy ran it.
//!
//! Each node advertises the master it follows, its distance (height) to it,
//! and that master's metric and counter. A node follows whichever valid
//! peer offers the best master, by metric and counter, then by the shorter
//! path, then by the higher address, and never a peer that follows it.

use crate::MacAddr;

/// AWDL-8: the metric a node starts with.
pub const METRIC_INIT: u32 = 60;
/// AWDL-8: the counter a node starts with.
pub const COUNTER_INIT: u32 = 0;
/// The longest path to a master that's followed. Legacy's arbitrary limit.
pub const MAX_HEIGHT: u32 = 10;

/// What decides between two masters first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ranking {
    /// Counter, then metric, as legacy ranked in shared mode.
    CounterFirst,
    /// Metric, then counter, as Apple devices rank (legacy patch `owl-04`): in
    /// a capture of a dozen of them, a master with metric 510 and counter
    /// 3214 gave way to one with 522 and 393 (AWDL-9).
    MetricFirst,
}

/// A node's election state: its own, or what a peer advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Election {
    /// The node itself.
    pub own: MacAddr,
    /// The top master it follows.
    pub master: MacAddr,
    /// The node it syncs to, one hop towards the master.
    pub sync: MacAddr,
    /// Hops to the master.
    pub height: u32,
    pub master_metric: u32,
    pub master_counter: u32,
    pub self_metric: u32,
    pub self_counter: u32,
    /// Whether a custom sync master metric was configured.
    pub custom_metric: bool,
}

impl Election {
    /// A node that follows nobody but itself, with AWDL-8's metric and
    /// counter.
    pub const fn own(addr: MacAddr) -> Election {
        Election {
            own: addr,
            master: addr,
            sync: addr,
            height: 0,
            master_metric: METRIC_INIT,
            master_counter: COUNTER_INIT,
            self_metric: METRIC_INIT,
            self_counter: COUNTER_INIT,
            custom_metric: false,
        }
    }

    /// Sets a custom election metric for the node.
    pub fn set_metric(&mut self, metric: u32) {
        self.self_metric = metric;
        self.master_metric = metric;
        self.custom_metric = true;
    }

    /// Whether the node is its own sync master.
    pub fn is_master(&self) -> bool {
        self.sync == self.own
    }

    fn reset_self(&mut self) {
        self.height = 0;
        self.master = self.own;
        self.sync = self.own;
        self.master_metric = self.self_metric;
        self.master_counter = self.self_counter;
    }

    fn rank(&self, ranking: Ranking) -> (u32, u32) {
        match ranking {
            Ranking::CounterFirst => (self.master_counter, self.master_metric),
            Ranking::MetricFirst => (self.master_metric, self.master_counter),
        }
    }

    /// Runs the election over the valid peers' states. Returns whether the
    /// master or the node synced to changed.
    pub fn run<'a>(
        &mut self,
        peers: impl IntoIterator<Item = &'a Election>,
        ranking: Ranking,
    ) -> bool {
        let (old_master, old_sync) = (self.master, self.sync);
        self.reset_self();
        let mut best: Election = *self;
        for p in peers {
            // The peer's height is whatever it sent, so no arithmetic on
            // it: following it would put us at `height + 1`.
            if p.height >= MAX_HEIGHT {
                continue;
            }
            // No cycles: never follow a peer that follows us.
            if p.sync == self.own {
                continue;
            }
            match p.rank(ranking).cmp(&best.rank(ranking)) {
                core::cmp::Ordering::Less => continue,
                core::cmp::Ordering::Equal => {
                    if p.height > best.height || (p.height == best.height && p.own <= best.own) {
                        continue;
                    }
                }
                core::cmp::Ordering::Greater => {}
            }
            best = *p;
        }
        if best.own != self.own {
            self.master = best.master;
            self.sync = best.own;
            self.master_metric = best.master_metric;
            self.master_counter = best.master_counter;
            self.height = best.height + 1;
        }
        self.master != old_master || self.sync != old_sync
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr([2, 0, 0, 0, 0, n])
    }

    fn peer(n: u8, metric: u32, counter: u32) -> Election {
        let mut e = Election::own(mac(n));
        e.self_metric = metric;
        e.self_counter = counter;
        e.master_metric = metric;
        e.master_counter = counter;
        e
    }

    // spec: AWDL-8
    #[test]
    fn a_node_starts_as_its_own_master_at_metric_60() {
        let e = Election::own(mac(1));
        assert!(e.is_master());
        assert_eq!((e.self_metric, e.self_counter), (60, 0));
    }

    // spec: AWDL-7
    #[test]
    fn the_higher_address_wins_a_tie() {
        let mut low = Election::own(mac(1));
        let high = Election::own(mac(2));
        assert!(low.run([&high], Ranking::CounterFirst));
        assert_eq!((low.master, low.sync, low.height), (mac(2), mac(2), 1));
        let mut high = high;
        assert!(!high.run([&low], Ranking::CounterFirst), "low follows high");
        assert!(high.is_master());
    }

    // spec: AWDL-9
    #[test]
    fn apple_ranks_by_metric_first() {
        let old = peer(3, 510, 3214);
        let new = peer(4, 522, 393);
        let mut us = Election::own(mac(1));
        us.run([&old, &new], Ranking::MetricFirst);
        assert_eq!(us.master, mac(4));
        us.run([&old, &new], Ranking::CounterFirst);
        assert_eq!(us.master, mac(3));
    }

    #[test]
    fn followers_shorter_paths_and_cycles() {
        let master = peer(9, 600, 10);
        // A peer that follows the master, one hop away.
        let mut relay = Election::own(mac(5));
        relay.run([&master], Ranking::MetricFirst);
        // Directly heard, the master wins over the relay.
        let mut us = Election::own(mac(1));
        us.run([&relay, &master], Ranking::MetricFirst);
        assert_eq!((us.sync, us.height), (mac(9), 1));
        // Through the relay only, two hops.
        us.run([&relay], Ranking::MetricFirst);
        assert_eq!((us.master, us.sync, us.height), (mac(9), mac(5), 2));
        // A peer that syncs to us is never followed.
        let mut follower = peer(7, 900, 0);
        follower.sync = mac(1);
        us.run([&follower], Ranking::MetricFirst);
        assert!(us.is_master());
        // Nor one whose tree is already as tall as allowed.
        let mut far = peer(8, 900, 0);
        far.height = MAX_HEIGHT;
        us.run([&far], Ranking::MetricFirst);
        assert!(us.is_master());
        // However tall it claims to be.
        far.height = u32::MAX;
        us.run([&far], Ranking::MetricFirst);
        assert!(us.is_master());
    }
}
