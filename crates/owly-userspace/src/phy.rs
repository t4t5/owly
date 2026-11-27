//! `smoltcp::phy::Device` bridging [`owly_awdl::Ipv6Packet`] on `Medium::Ip`.

use std::collections::VecDeque;

use owly_awdl::Ipv6Packet;
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// AWDL `awdl0` MTU used by `owly`.
pub const MTU: usize = 1450;

/// Userspace `Medium::Ip` device translating IPv6 packets to/from [`owly_awdl::Ipv6Packet`].
///
/// Using `Medium::Ip` relies directly on AWDL's modified EUI-64 link-local MAC derivation
/// (`NET-2` / `Ipv6Packet::from_ip`), so `smoltcp` needs no Neighbor Discovery (NDP).
#[derive(Debug, Default)]
pub struct AwdlIpDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Ipv6Packet>,
    rx_packets: u64,
    tx_packets: u64,
}

impl AwdlIpDevice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues an IPv6 packet delivered by [`owly_awdl::Action::Deliver`] for `smoltcp` ingress.
    pub fn push_rx(&mut self, packet: Ipv6Packet) {
        self.rx.push_back(packet.data);
        self.rx_packets = self.rx_packets.saturating_add(1);
    }

    /// Pops the next outbound IPv6 packet produced by `smoltcp` for [`owly_awdl::Input::Outbound`].
    pub fn pop_tx(&mut self) -> Option<Ipv6Packet> {
        self.tx.pop_front()
    }

    pub fn rx_pending(&self) -> usize {
        self.rx.len()
    }

    pub fn tx_pending(&self) -> usize {
        self.tx.len()
    }

    pub fn rx_packets(&self) -> u64 {
        self.rx_packets
    }

    pub fn tx_packets(&self) -> u64 {
        self.tx_packets
    }
}

impl Device for AwdlIpDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.rx.pop_front()?;
        let rx = RxToken { buffer };
        let tx = TxToken {
            tx: &mut self.tx,
            tx_packets: &mut self.tx_packets,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            tx: &mut self.tx,
            tx_packets: &mut self.tx_packets,
        })
    }
}

/// Ingress buffer handed to `smoltcp`.
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// Egress buffer wrapping IPv6 packets into [`owly_awdl::Ipv6Packet`].
pub struct TxToken<'a> {
    tx: &'a mut VecDeque<Ipv6Packet>,
    tx_packets: &'a mut u64,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        // Non-link-local or unspecified-source DAD packets legitimately return None.
        if let Some(packet) = Ipv6Packet::from_ip(buffer) {
            self.tx.push_back(packet);
            *self.tx_packets = self.tx_packets.saturating_add(1);
        }
        result
    }
}
