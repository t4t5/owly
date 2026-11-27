//! Sans-IO AWDL: frames and TLVs, sync and election, channel sequence, data path and peer table.
//!
//! [`Node`] is the state machine. It does no I/O and reads no clock: the
//! host feeds it what the radio received, the packets the IP stack wants
//! sent and timer expiries, each with the time, and carries out the
//! [`Action`]s it returns (transmit a frame, arm the timer, add or remove a
//! neighbour, hand a packet to the IP stack). That makes it testable from
//! vectors, captures and simulation, and portable to any host, runtime or
//! firmware.
//!
//! The layers, each in its own module, follow docs/SPEC.md §3: [`frame`]
//! (802.11 headers, the AWDL action header and data framing, AWDL-3,
//! AWDL-13–15), [`tlv`] (TLV encoding and the TLVs themselves, AWDL-4–6),
//! [`sync`] (availability windows, AWDL-7, AWDL-16), [`election`] (AWDL-7–9),
//! [`channel`] (channel sequences, AWDL-10–12), [`peer`] (the peer table),
//! [`ip`] (the IPv6 packets the data path carries) and [`rate`] (transmit
//! rates).
//!
//! The `driver` feature adds [`driver`], which runs a node on std and tokio
//! for any radio that can inject and capture 802.11 frames. The core stays
//! `no_std` without it.
//!
//! "Legacy" in this crate's comments is the patched AWDL daemon that
//! `omdrop-owl` 0.3.0 and older ran, with its patches at the repository's
//! `v0.3.0` tag. It's the reference for behaviour the spec leaves open;
//! where this crate differs from it, the item says why.

#![no_std]

extern crate alloc;
#[cfg(feature = "driver")]
extern crate std;

pub mod channel;
#[cfg(feature = "driver")]
pub mod driver;
pub mod election;
pub mod frame;
pub mod ip;
mod node;
pub mod peer;
pub mod rate;
pub mod service;
pub mod sync;
pub mod tlv;
mod wire;

use core::fmt;
use core::net::Ipv6Addr;

pub use channel::{Channel, Sequence};
pub use frame::Frame;
pub use ip::Ipv6Packet;
pub use node::{
    Action, Config, Input, MAX_PEERS, Node, Presence, RadioConstraints, Stats, UNICAST_QUEUE,
};
pub use peer::PeerInfo;
pub use rate::TxRate;

/// A monotonic count of microseconds from an epoch the caller picks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time(pub u64);

impl Time {
    pub const fn micros(self) -> u64 {
        self.0
    }

    /// `us` microseconds later.
    pub const fn plus(self, us: u64) -> Time {
        Time(self.0.saturating_add(us))
    }

    /// `us` microseconds earlier, or the epoch.
    pub const fn minus(self, us: u64) -> Time {
        Time(self.0.saturating_sub(us))
    }

    /// Microseconds since `earlier`, or 0 if it's later.
    pub const fn since(self, earlier: Time) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// One time unit, 1024 µs: what 802.11 and AWDL count in.
pub const TU: u64 = 1024;

/// An 802.11 MAC address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    /// Broadcast or multicast: the group bit is set.
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 1 == 1
    }

    /// A locally administered address of our own beside `self`, for a
    /// monitor interface that mustn't carry the station's.
    pub const fn local(self) -> MacAddr {
        let mut b = self.0;
        b[0] = 0x02;
        MacAddr(b)
    }

    /// NET-1: the modified EUI-64 link-local address for this MAC, which is
    /// how AWDL peers address each other (NET-2).
    pub const fn link_local(self) -> Ipv6Addr {
        let m = self.0;
        Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            u16::from_be_bytes([m[0] ^ 0x02, m[1]]),
            u16::from_be_bytes([m[2], 0xff]),
            u16::from_be_bytes([0xfe, m[3]]),
            u16::from_be_bytes([m[4], m[5]]),
        )
    }

    /// The MAC a modified EUI-64 link-local address was made from, if it
    /// was made from one.
    pub fn from_link_local(addr: Ipv6Addr) -> Option<MacAddr> {
        let o = addr.octets();
        if o[..8] != [0xfe, 0x80, 0, 0, 0, 0, 0, 0] || o[11] != 0xff || o[12] != 0xfe {
            return None;
        }
        Some(MacAddr([o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]]))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl core::str::FromStr for MacAddr {
    type Err = Error;

    /// Colon-separated hex octets, in either case. Also takes
    /// `ether_ntoa`'s unpadded ones (`86:8:4:8a:2b:f4`).
    fn from_str(s: &str) -> Result<Self, Error> {
        const BAD: Error = Error::Malformed("not a MAC address");
        let mut out = [0; 6];
        let mut octets = s.split(':');
        for b in &mut out {
            let o = octets.next().ok_or(BAD)?;
            if o.is_empty() || o.len() > 2 {
                return Err(BAD);
            }
            *b = u8::from_str_radix(o, 16).map_err(|_| BAD)?;
        }
        if octets.next().is_some() {
            return Err(BAD);
        }
        Ok(MacAddr(out))
    }
}

/// AWDL-1: the BSSID every AWDL frame carries.
pub const BSSID: MacAddr = MacAddr([0x00, 0x25, 0x00, 0xff, 0x94, 0x73]);

/// Apple's OUI, in action frames and in data frames' SNAP header.
pub const OUI: [u8; 3] = [0x00, 0x17, 0xf2];

/// Why bytes off the air were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Shorter than its headers or lengths say.
    Truncated,
    /// A field holds a value this implementation doesn't accept.
    Malformed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => f.write_str("truncated"),
            Error::Malformed(what) => write!(f, "malformed: {what}"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_parse_unpadded_octets() {
        use alloc::string::ToString;
        let mac: MacAddr = "86:8:4:8a:2b:f4".parse().unwrap();
        assert_eq!(mac.to_string(), "86:08:04:8a:2b:f4");
        assert_eq!(
            "AA:BB:CC:DD:EE:FF".parse::<MacAddr>().unwrap().to_string(),
            "aa:bb:cc:dd:ee:ff"
        );
        for bad in [
            "",
            "1:2:3:4:5",
            "1:2:3:4:5:6:7",
            "123:0:0:0:0:0",
            "g:0:0:0:0:0",
            "1::3:4:5:6",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad}");
        }
    }

    // spec: AWDL-1
    #[test]
    fn frames_carry_awdls_bssid() {
        use alloc::string::ToString;
        assert_eq!(BSSID.to_string(), "00:25:00:ff:94:73");
    }

    // spec: NET-1
    #[test]
    fn link_local_is_modified_eui64_and_back() {
        let mac = MacAddr([0x86, 0x08, 0x04, 0x8a, 0x2b, 0xf4]);
        let addr = mac.link_local();
        assert_eq!(
            addr,
            "fe80::8408:4ff:fe8a:2bf4".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(MacAddr::from_link_local(addr), Some(mac));
        assert_eq!(MacAddr::from_link_local("fe80::1".parse().unwrap()), None);
    }
}
