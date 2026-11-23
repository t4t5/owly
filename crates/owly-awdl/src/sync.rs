//! Availability windows (docs/SPEC.md §3.3).
//!
//! An availability window (AW) lasts 16 TU, and four make an extended one
//! (EAW), one slot of the channel sequence: 64 TU. A node counts AWs, and a
//! node that isn't the sync master aligns its count and phase to the
//! master's Synchronization Parameters TLV (AWDL-7). [`Clock`] keeps that
//! alignment.

use crate::{TU, Time};

/// TU per availability window.
pub const AW_PERIOD_TU: u16 = 16;
/// Availability windows per slot (the presence mode, §3.2).
pub const PRESENCE_MODE: u8 = 4;
/// TU per slot (one extended availability window).
pub const SLOT_TU: u64 = AW_PERIOD_TU as u64 * PRESENCE_MODE as u64;
/// Microseconds per slot.
pub const SLOT_US: u64 = SLOT_TU * TU;
/// Slots in a full channel sequence period.
pub const PERIOD_US: u64 = SLOT_US * crate::channel::SLOTS as u64;

/// AWDL-16: how far from a slot's edges unicast keeps.
pub const UNICAST_GUARD_US: u64 = 3 * TU;
/// AWDL-16: how far from a slot's edges multicast keeps.
pub const MULTICAST_GUARD_US: u64 = 16 * TU;

/// Where this node is in the AW schedule: the AW count at a slot boundary,
/// and when that boundary was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// The start of the slot holding `aw_counter`, clamped to the local epoch.
    last: Time,
    /// Portion of that slot before the local epoch, in microseconds.
    before_epoch_us: u64,
    aw_counter: u16,
}

impl Clock {
    /// A schedule of our own, starting a slot at `now`.
    pub const fn new(now: Time) -> Clock {
        Clock {
            last: now,
            before_epoch_us: 0,
            aw_counter: 0,
        }
    }

    fn since(&self, now: Time) -> u64 {
        // Only the low bits select an AW or slot, including at the u64 wrap.
        now.since(self.last).wrapping_add(self.before_epoch_us)
    }

    /// Microseconds to the next slot boundary, in `1..=SLOT_US`.
    pub fn next_slot_us(&self, now: Time) -> u64 {
        SLOT_US - self.since(now) % SLOT_US
    }

    /// TU to the next slot boundary, as the Synchronization Parameters TLV
    /// announces it (its TX down-counter).
    pub fn next_slot_tu(&self, now: Time) -> u16 {
        (SLOT_TU - (self.since(now) / TU) % SLOT_TU) as u16
    }

    /// The AW count now, as announced in the TLV's next AW sequence number.
    pub fn current_aw(&self, now: Time) -> u16 {
        let tu = self.since(now) / TU;
        let aw = self.aw_counter as u64
            + (tu % SLOT_TU) / AW_PERIOD_TU as u64
            + PRESENCE_MODE as u64 * (tu / SLOT_TU);
        aw as u16
    }

    /// The slot count now: one per four AWs.
    pub fn current_eaw(&self, now: Time) -> u16 {
        self.current_aw(now) / PRESENCE_MODE as u16
    }

    /// The slot of the channel sequence now.
    pub fn slot(&self, now: Time) -> usize {
        self.current_eaw(now) as usize % crate::channel::SLOTS
    }

    /// How far, in TU, a schedule announced at `now` as `next_tu` TU to the
    /// next boundary and AW count `aw_counter` is ahead of ours (negative:
    /// behind). Slot counts are compared modulo their wrap, which legacy's
    /// weren't.
    pub fn error_tu(&self, now: Time, next_tu: u16, aw_counter: u16) -> i64 {
        const EAW_WRAP: i32 = 1 << 14; // u16 AWs, four a slot
        let theirs = (aw_counter / PRESENCE_MODE as u16) as i32;
        let ours = self.current_eaw(now) as i32;
        let slots = (theirs - ours + EAW_WRAP / 2).rem_euclid(EAW_WRAP) - EAW_WRAP / 2;
        slots as i64 * SLOT_TU as i64 - (next_tu as i64 - self.next_slot_tu(now) as i64)
    }

    /// Adopts a schedule announced at `now` (AWDL-7): the next boundary is
    /// `next_tu` TU away, and the slot holds AW `aw_counter`.
    pub fn update(&mut self, now: Time, next_tu: u16, aw_counter: u16) {
        let next = (next_tu as u64).min(SLOT_TU);
        let phase_us = (SLOT_TU - next) * TU;
        self.last = now.minus(phase_us);
        self.before_epoch_us = phase_us.saturating_sub(now.micros());
        self.aw_counter = aw_counter & !(PRESENCE_MODE as u16 - 1);
    }

    /// Whether `now` is within `guard` of the end of a slot.
    pub fn in_end_guard(&self, now: Time, guard: u64) -> bool {
        self.next_slot_us(now) < guard
    }

    /// Whether `now` is within `guard` of the start of a slot.
    pub fn in_start_guard(&self, now: Time, guard: u64) -> bool {
        SLOT_US - self.next_slot_us(now) < guard
    }

    /// How long to wait until `now` is clear of `guard` at both edges of
    /// its slot: 0 when it already is.
    pub fn edge_wait(&self, now: Time, guard: u64) -> u64 {
        let next = self.next_slot_us(now);
        if next < guard {
            next + guard
        } else {
            // Into the slot by SLOT_US - next.
            guard.saturating_sub(SLOT_US - next)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_clock_counts_slots_from_its_start() {
        let c = Clock::new(Time(1_000_000));
        let t = Time(1_000_000);
        assert_eq!(c.next_slot_us(t), SLOT_US);
        assert_eq!(c.next_slot_tu(t), 64);
        assert_eq!(c.slot(t), 0);
        assert_eq!(c.current_aw(t.plus(16 * TU)), 1);
        assert_eq!(c.slot(t.plus(SLOT_US)), 1);
        assert_eq!(c.slot(t.plus(17 * SLOT_US)), 1);
        assert_eq!(c.next_slot_us(t.plus(SLOT_US - 1)), 1);
    }

    // spec: AWDL-7
    #[test]
    fn following_a_master_takes_its_phase_and_count() {
        let mut c = Clock::new(Time(0));
        let now = Time(10_000_000);
        // The master's next boundary is 20 TU off, in its AW 401 (slot 100).
        assert_ne!(c.error_tu(now, 20, 401), 0);
        c.update(now, 20, 401);
        assert_eq!(c.error_tu(now, 20, 401), 0);
        assert_eq!(c.next_slot_tu(now), 20);
        assert_eq!(c.current_eaw(now), 100);
        assert_eq!(c.slot(now), 100 % 16);
        assert_eq!(c.slot(now.plus(20 * TU)), 101 % 16);
        // A peer 3 TU ahead and one a slot behind.
        assert_eq!(c.error_tu(now, 17, 401), 3);
        assert_eq!(c.error_tu(now, 20, 397), -64);
    }

    // spec: AWDL-7
    #[test]
    fn adopts_a_slot_that_started_before_the_local_epoch() {
        let mut c = Clock::new(Time(0));
        let rx = Time(500);
        // The master is in its last AW before the counter wraps, with 7 TU
        // left in the slot. The follower has been running for only 500 us.
        c.update(rx, 7, u16::MAX);
        assert_eq!(c.current_aw(rx), u16::MAX);
        assert_eq!(c.error_tu(rx, 7, u16::MAX), 0);
        assert_eq!(c.next_slot_us(rx), 7 * TU);
        assert_eq!(c.slot(rx.plus(7 * TU - 1)), 15);
        assert_eq!(c.current_aw(rx.plus(7 * TU)), 0);
        assert_eq!(c.slot(rx.plus(7 * TU)), 0);

        // A later sample pins a slot entirely on our local clock.
        let later = rx.plus(2 * SLOT_US);
        c.update(later, 60, 4);
        assert_eq!(c.error_tu(later, 60, 4), 0);
        assert_eq!(c.next_slot_us(later), 60 * TU);
    }

    #[test]
    fn slot_counts_compare_across_their_wrap() {
        let mut c = Clock::new(Time(0));
        c.update(Time(0), 64, 65532);
        assert_eq!(c.current_eaw(Time(0)), 16383);
        assert_eq!(c.error_tu(Time(0), 64, 0), 64);
        assert_eq!(c.current_eaw(Time(SLOT_US)), 0, "wraps");
        assert_eq!(c.slot(Time(SLOT_US)), 0, "and stays in step");
    }

    // spec: AWDL-16
    #[test]
    fn guards_keep_clear_of_slot_edges() {
        let c = Clock::new(Time(0));
        let g = UNICAST_GUARD_US;
        assert_eq!(c.edge_wait(Time(0), g), g);
        assert_eq!(c.edge_wait(Time(g), g), 0);
        assert_eq!(c.edge_wait(Time(SLOT_US / 2), g), 0);
        assert_eq!(c.edge_wait(Time(SLOT_US - g), g), 0);
        assert_eq!(c.edge_wait(Time(SLOT_US - 1000), g), 1000 + g);
        assert!(c.in_end_guard(Time(SLOT_US - 1000), g));
        assert!(c.in_start_guard(Time(SLOT_US + 1000), g));
        let m = MULTICAST_GUARD_US;
        assert_eq!(c.edge_wait(Time(SLOT_US / 2), m), 0);
        assert_eq!(c.edge_wait(Time(1000), m), m - 1000);
    }
}
