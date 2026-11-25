#![forbid(unsafe_code)]
//! Safe-Rust, zero-kernel-Wi-Fi-driver, zero-TAP, zero-root 7-layer AWDL + IPv6 (`smoltcp`) + AirDrop stack.
//!
//! This crate composes:
//! - Layers 1–2: [`owly_awdl::Node`] (sans-IO AWDL sync, election, channel schedule, and data framing)
//! - Layers 3–4: [`smoltcp`] over [`phy::AwdlIpDevice`] (`Medium::Ip`, IPv6 link-local `fe80::/64` + `ff02::fb`)
//! - Layer 4.5: [`owly_airdrop::proto::mdns`] responder & browser over a `smoltcp` UDP socket (`:5353`)
//! - Layer 5: [`tls::UserspaceTls`] driving `rustls` cleanly inside `smoltcp` TCP sockets
//! - Layers 6–7: [`owly_airdrop::proto::receiver`] & [`owly_airdrop::proto::sender`] + in-memory CPIO/Gzip/DVZip
//! - Pluggable radios ([`air`]): deterministic [`air::SimAirHub`] with Radiotap PCAP capture,
//!   [`air::udp::UdpRadiotapAir`] (`udp` feature), and [`air::usb`] dongle discovery via `nusb` (`usb` feature).

#[cfg(feature = "ring")]
use std::sync::Once;

pub mod air;
pub mod archive;
#[cfg(all(
    feature = "usb",
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    )
))]
pub mod mt7612u_hw;
pub mod node;
pub mod pcap;
pub mod phy;
pub mod tls;
pub mod usb_radio;

pub use air::{AirStats, SimAirHub};
pub use node::{
    DEFAULT_IN_MEMORY_UPLOAD_LIMIT, DEFAULT_RECEIVER_PORT, StepClusterStats, UserspaceNode,
    UserspaceReceiveEvent, compressor_for_receiver_flags, default_awdl_config, step_cluster,
};
pub use owly_airdrop;
pub use owly_awdl;
pub use pcap::{PcapWriter, parse_radiotap, read_pcap, tx_radiotap};
pub use phy::{AwdlIpDevice, MTU as AWDL_MTU};

#[cfg(feature = "ring")]
static CRYPTO_INIT: Once = Once::new();

/// Installs the process-wide `ring` crypto provider for `rustls` when the `ring` feature is enabled (idempotent).
///
/// With `default-features = false`, the application installs its own `rustls` crypto provider,
/// matching [`owly_airdrop::driver::tls`].
pub fn ensure_crypto_provider() {
    #[cfg(feature = "ring")]
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
