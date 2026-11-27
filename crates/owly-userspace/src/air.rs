//! Pluggable 802.11 RF transport backends: simulated bus (+ PCAP tap), UDP bridge, and `nusb` dongle probe.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use owly_awdl::Frame;
use owly_awdl::channel::Channel;

use crate::pcap::PcapWriter;

/// Diagnostic counters recorded by [`SimAirHub`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AirStats {
    pub transmitted: u64,
    pub delivered: u64,
    pub dropped_loss: u64,
    pub dropped_channel: u64,
}

struct RadioPort {
    channel: Channel,
    rx_queue: VecDeque<(Option<i8>, Vec<u8>)>,
}

type SharedPcap = Arc<Mutex<PcapWriter<Box<dyn Write + Send>>>>;

/// Deterministic multi-node simulated 802.11 wireless medium.
///
/// Models channel isolation, configurable pseudo-random packet loss (`loss_permille`),
/// RSSI attenuation, and optional `DLT_IEEE802_11_RADIO` PCAP capture.
pub struct SimAirHub {
    radios: BTreeMap<usize, RadioPort>,
    next_id: usize,
    loss_permille: u16,
    rssi_dbm: Option<i8>,
    rng_state: u64,
    pcap: Option<SharedPcap>,
    pcap_error: Option<io::Error>,
    stats: AirStats,
}

impl SimAirHub {
    /// Creates an ideal lossless simulated air (`rssi = -40 dBm`).
    pub fn new() -> Self {
        Self {
            radios: BTreeMap::new(),
            next_id: 1,
            loss_permille: 0,
            rssi_dbm: Some(-40),
            rng_state: 0x9E37_79B9_7F4A_7C15,
            pcap: None,
            pcap_error: None,
            stats: AirStats::default(),
        }
    }

    /// Configures deterministic packet loss in parts per thousand (`0..=1000`).
    pub fn with_loss_permille(mut self, permille: u16) -> Self {
        self.loss_permille = permille.min(1000);
        self
    }

    /// Sets the simulated RSSI delivered to peer receivers.
    pub fn with_rssi(mut self, rssi_dbm: Option<i8>) -> Self {
        self.rssi_dbm = rssi_dbm;
        self
    }

    /// Attaches a live `DLT_IEEE802_11_RADIO` PCAP writer recording every transmitted frame.
    pub fn with_pcap<W: Write + Send + 'static>(mut self, writer: W) -> std::io::Result<Self> {
        let boxed: Box<dyn Write + Send> = Box::new(writer);
        let pcap = PcapWriter::new(boxed)?;
        self.pcap = Some(Arc::new(Mutex::new(pcap)));
        Ok(self)
    }

    /// Registers a radio tuned to `channel`, returning its hub handle ID.
    pub fn register(&mut self, channel: Channel) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.radios.insert(
            id,
            RadioPort {
                channel,
                rx_queue: VecDeque::new(),
            },
        );
        id
    }

    /// Tunes radio `id` to a different 802.11 channel.
    pub fn set_channel(&mut self, id: usize, channel: Channel) {
        if let Some(port) = self.radios.get_mut(&id) {
            port.channel = channel;
        }
    }

    /// Broadcasts or unicasts a transmitted 802.11 frame from `sender_id` to peers on the medium.
    pub fn transmit(&mut self, sender_id: usize, now_us: u64, frame: &Frame) {
        let Some(src_chan) = self.radios.get(&sender_id).map(|p| p.channel) else {
            return;
        };
        self.stats.transmitted = self.stats.transmitted.saturating_add(1);
        if let Some(pcap) = self.pcap.clone() {
            let write_result = pcap
                .lock()
                .map_err(|_| io::Error::other("pcap writer mutex poisoned"))
                .and_then(|mut guard| guard.write_80211_frame(now_us, self.rssi_dbm, &frame.bytes));
            if let Err(err) = write_result
                && self.pcap_error.is_none()
            {
                self.pcap_error = Some(err);
            }
        }

        let peer_ids: Vec<usize> = self
            .radios
            .keys()
            .copied()
            .filter(|&id| id != sender_id)
            .collect();
        for peer_id in peer_ids {
            let same_chan = self
                .radios
                .get(&peer_id)
                .is_some_and(|p| p.channel == src_chan);
            if !same_chan {
                self.stats.dropped_channel = self.stats.dropped_channel.saturating_add(1);
                continue;
            }
            if self.loss_permille > 0 && self.next_u16() % 1000 < self.loss_permille {
                self.stats.dropped_loss = self.stats.dropped_loss.saturating_add(1);
                continue;
            }
            if let Some(peer) = self.radios.get_mut(&peer_id) {
                peer.rx_queue
                    .push_back((self.rssi_dbm, frame.bytes.clone()));
                self.stats.delivered = self.stats.delivered.saturating_add(1);
            }
        }
    }

    /// Drains all queued incoming frames waiting for radio `id`.
    pub fn drain_rx(&mut self, id: usize) -> Vec<(Option<i8>, Vec<u8>)> {
        let Some(port) = self.radios.get_mut(&id) else {
            return Vec::new();
        };
        port.rx_queue.drain(..).collect()
    }

    pub fn stats(&self) -> AirStats {
        self.stats
    }

    pub fn flush_pcap(&mut self) -> std::io::Result<()> {
        let flush_result = if let Some(pcap) = &self.pcap {
            pcap.lock()
                .map_err(|_| io::Error::other("pcap writer mutex poisoned"))?
                .flush()
        } else {
            Ok(())
        };
        if let Some(err) = self.pcap_error.take() {
            return Err(err);
        }
        flush_result
    }

    fn next_u16(&mut self) -> u16 {
        // SplitMix64 step for reproducible loss simulation.
        self.rng_state = self.rng_state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 16) as u16
    }
}

impl Default for SimAirHub {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "udp")]
pub mod udp {
    //! Radiotap-over-UDP bridge carrying 802.11 AWDL frames between processes or hosts.

    use std::io;
    use std::net::SocketAddr;

    use owly_awdl::Frame;
    use tokio::net::UdpSocket;

    use crate::pcap::{parse_radiotap, tx_radiotap};

    /// Non-blocking UDP socket sending and receiving Radiotap-wrapped 802.11 frames.
    pub struct UdpRadiotapAir {
        socket: UdpSocket,
        peer: SocketAddr,
        buf: Vec<u8>,
    }

    impl UdpRadiotapAir {
        pub async fn bind(local: SocketAddr, peer: SocketAddr) -> io::Result<Self> {
            let socket = UdpSocket::bind(local).await?;
            Ok(Self {
                socket,
                peer,
                buf: vec![0u8; 16 * 1024],
            })
        }

        pub fn local_addr(&self) -> io::Result<SocketAddr> {
            self.socket.local_addr()
        }

        /// Encapsulates `frame` in Radiotap and transmits without blocking.
        pub fn try_send(&self, frame: &Frame, rssi_dbm: Option<i8>) -> io::Result<usize> {
            let mut datagram = tx_radiotap(rssi_dbm);
            datagram.extend_from_slice(&frame.bytes);
            self.socket.try_send_to(&datagram, self.peer)
        }

        /// Drains all immediately available Radiotap frames from the UDP socket.
        pub fn try_drain_rx(&mut self) -> Vec<(Option<i8>, Vec<u8>)> {
            let mut out = Vec::new();
            while let Ok((n, src)) = self.socket.try_recv_from(&mut self.buf) {
                if src != self.peer {
                    continue;
                }
                if let Some((frame, rssi)) = parse_radiotap(&self.buf[..n]) {
                    out.push((rssi.or(Some(-40)), frame.to_vec()));
                }
            }
            out
        }
    }
}

#[cfg(feature = "usb")]
pub mod usb {
    //! Safe-Rust userspace USB Wi-Fi dongle discovery via `nusb` (no kernel Wi-Fi driver).

    use std::io;

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_arch = "wasm32"
    ))]
    use nusb::MaybeFuture;

    /// Supported USB Wi-Fi chipsets targeted for userspace active-monitor AWDL transport.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SupportedDongle {
        /// Qualcomm Atheros AR9271 (`ath9k_htc`, open firmware, 2.4 GHz channel 6).
        Ar9271,
        /// MediaTek MT7612U (`mt76x2u`, dual-band 5 GHz channels 44/149 + hardware A-MPDU BA).
        Mt7612u,
    }

    impl SupportedDongle {
        pub const fn usb_ids(self) -> (u16, u16) {
            match self {
                Self::Ar9271 => (0x0cf3, 0x9271),
                Self::Mt7612u => (0x0e8d, 0x7612),
            }
        }

        pub const fn name(self) -> &'static str {
            match self {
                Self::Ar9271 => "Qualcomm Atheros AR9271 (ath9k_htc)",
                Self::Mt7612u => "MediaTek MT7612U (mt76x2u)",
            }
        }
    }

    /// USB device descriptor summary for a detected AWDL-capable dongle.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DetectedDongle {
        pub kind: SupportedDongle,
        pub vendor_id: u16,
        pub product_id: u16,
        pub bus_id: String,
        pub device_address: u8,
        pub product: Option<String>,
    }

    /// Enumerates attached AR9271 / MT7612U USB Wi-Fi dongles without root or kernel netdevs.
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_arch = "wasm32"
    ))]
    pub fn discover_dongles() -> io::Result<Vec<DetectedDongle>> {
        let mut found = Vec::new();
        for dev in nusb::list_devices().wait().map_err(io::Error::other)? {
            let id = (dev.vendor_id(), dev.product_id());
            let kind = if id == crate::usb_radio::Ar9271Codec::USB_ID {
                Some(SupportedDongle::Ar9271)
            } else if crate::usb_radio::Mt7612uCodec::SUPPORTED_USB_IDS.contains(&id) {
                Some(SupportedDongle::Mt7612u)
            } else {
                None
            };
            if let Some(kind) = kind {
                found.push(DetectedDongle {
                    kind,
                    vendor_id: dev.vendor_id(),
                    product_id: dev.product_id(),
                    bus_id: dev.bus_id().to_string(),
                    device_address: dev.device_address(),
                    product: dev.product_string().map(str::to_string),
                });
            }
        }
        Ok(found)
    }

    /// Reports that `nusb` enumeration is unavailable on this target.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_arch = "wasm32"
    )))]
    pub fn discover_dongles() -> io::Result<Vec<DetectedDongle>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nusb device enumeration is unavailable on this target",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use owly_awdl::{MacAddr, TxRate};

    #[derive(Default)]
    struct FailAfterHeader {
        written: usize,
    }

    impl Write for FailAfterHeader {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.written >= 24 {
                return Err(io::Error::other("capture sink failed"));
            }
            self.written += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn capture_errors_are_reported_on_flush() {
        let mut hub = SimAirHub::new()
            .with_pcap(FailAfterHeader::default())
            .unwrap();
        let sender = hub.register(Channel(149));
        hub.transmit(
            sender,
            0,
            &Frame {
                bytes: vec![0xd0; 24],
                to: MacAddr([0xff; 6]),
                rate: TxRate::BASIC,
                no_ack: true,
            },
        );
        assert_eq!(
            hub.flush_pcap().unwrap_err().to_string(),
            "capture sink failed"
        );
    }
}
