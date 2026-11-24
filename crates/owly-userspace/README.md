# owly-userspace

A safe-Rust (`#![forbid(unsafe_code)]`), zero-kernel-Wi-Fi-driver, zero-TAP, zero-root **7-layer AWDL + IPv6 (`smoltcp`) + AirDrop** protocol stack built directly on the sans-IO cores of [`owly-awdl`](../owly-awdl) and [`owly-airdrop`](../owly-airdrop). Dependencies such as the default `ring` crypto provider may contain native code.

## Why `owly-userspace`?

The other crates in this workspace target a real host network stack on Linux:

| Crate | What it provides | Host / OS requirements |
|---|---|---|
| `owly-awdl` | Sans-IO AWDL L1–L2 state machine + `driver` (`Air` ↔ `Netif`) | `driver` expects an OS network interface (Linux TAP `awdl0`, Windows Wintun) |
| `owly-airdrop` | Sans-IO AirDrop L4.5–L7 core + `tokio`/`mdns` driver | `driver` uses OS TCP/UDP sockets and a filesystem staging directory |
| `owly-radio` + `owlyd` | Linux `nl80211` monitor/ad-hoc radio backend, `awdl0` TAP, D-Bus daemon | Linux-only, root/privileged, kernel Wi-Fi driver (or `mac80211_hwsim` for tests) |
| **`owly-userspace`** | **All 7 layers in one rootless Rust process (`smoltcp` + `rustls` + in-memory CPIO) with pluggable RF transports** | **None for the simulator — runs identically on Linux, macOS, and Windows with no root, no TAP, no Wi-Fi hardware, and no disk staging** |

### Stack layers

| Layer | Implementation | Notes |
|---|---|---|
| **1–2 (AWDL)** | `owly_awdl::Node` | PSF/MIF sync, election, channel schedule, data framing, held-SYN buffering |
| **3–4 (IPv6 / TCP / UDP)** | `smoltcp` (`Medium::Ip`, MTU `1450`) | Uses `Ipv6Packet::from_ip` (EUI-64 link-local MAC derivation, no NDP) |
| **4.5 (mDNS)** | `owly_airdrop::proto::mdns` | Responds & browses `_airdrop._tcp` over `smoltcp` UDP `:5353` (`ff02::fb`) |
| **5 (TLS 1.2 / 1.3)** | `rustls` (`ring`) + `owly_airdrop::driver::tls` | Sans-IO TLS pump inside `smoltcp` TCP sockets |
| **6–7 (HTTP / bplist / CPIO)** | `owly_airdrop::proto::{receiver,sender}` | `/Discover`, interactive `/Ask` (`accept_ask`/`decline_ask`), URL shares, in-memory Gzip & DVZip uploads |
| **Transports & Framing** | `air::SimAirHub`, `air::udp::UdpRadiotapAir`, `usb_radio` | Deterministic multi-node RF sim with channel isolation, packet loss & Radiotap PCAP capture; cross-host UDP radiotap bridge; clean-room `MT7612U`/`AR9271` USB bulk/control framing + optional `nusb` transport |

## Demonstrative example

Run the full showcase — zero root, zero TAP, zero Wi-Fi hardware — to see what `owly-userspace` does that the other crates cannot do on their own (4-node AWDL mesh with channel isolation & 5% RF loss, userspace IPv6/mDNS/TLS, interactive `/Ask` decline, in-memory DVZip & Gzip file transfers, URL sharing, simulated MT7612U USB bulk URB framing, and Wireshark-ready Radiotap PCAP verification):

```sh
cargo run -p owly-userspace --example showcase
# Optionally save the live 802.11 Radiotap PCAP to inspect in Wireshark:
cargo run -p owly-userspace --example showcase -- --pcap /tmp/owly-showcase.pcap --loss 50
```

## Other examples & tests

```sh
# Run the full test suite (7-layer sim, OWL vectors & fuzzing, UDP bridge, USB framing)
cargo test -p owly-userspace --all-features

# Minimal 2-node virtual AirDrop transfer
cargo run -p owly-userspace --example virtual_airdrop -- --pcap /tmp/awdl.pcap

# Cross-host 802.11 Radiotap-over-UDP bridge (requires default `udp` feature)
cargo run -p owly-userspace --example udp_bridge -- --role rx --bind 0.0.0.0:17777 --peer 192.168.1.242:17777

# Userspace USB Wi-Fi dongle discovery & MT7612U firmware parser check (requires `usb` feature)
cargo run -p owly-userspace --features usb --example usb_probe
cargo run -p owly-userspace --features usb --example usb_probe -- --fw-check <mt7662u_rom_patch.bin> <mt7662u.bin>
```

The default `ring` feature installs rustls's process-wide `ring` provider. With
`default-features = false`, install a rustls crypto provider before creating TLS
connections. The default receiver limits compressed and extracted in-memory
uploads to 256 MiB; use `enable_receiver_with_config` to choose a different
application-appropriate limit.

## MT7612U (`0e8d:7612`) userspace USB notes

- `usb_radio` implements clean-room IEEE 802.11 bulk URB TXWI/RXWI framing (`Mt7612uCodec`, `Ar9271Codec`), chipset-aware endpoint selection (`select_endpoints` skipping MT7612U's `0x08` inband command pipe to select `0x04`/`0x84` data + `0x08`/`0x85` MCU pipes), `Mt7612uRomPatch`/`Mt7612uFirmware` image parsers, MCU command & FCE DMA upload builders, and `nusb_transport::load_mt7612u_firmware`.
- `load_mt7612u_firmware` performs the firmware image transfer only; full hardware bring-up still needs chipset reset, patch-enable, firmware-start, EEPROM, calibration, and MCU channel sequences.
- `nusb` enumeration and transport are available on Linux, macOS, and Windows. On Android, `discover_dongles` returns `Unsupported` because `nusb` does not enumerate `/dev/bus/usb`, while `usb_radio::nusb_transport::UsbRadioHandle::open_from_fd` accepts an already-authorized file descriptor (for example from Android `UsbDeviceConnection.getFileDescriptor()` over USB OTG).
- On Linux xHCI USB 3.0 hosts where `mt76x2u` stalls with `MAC RX failed to stop`, prefer a USB 2.0 High-Speed port or set `options mt76_usb disable_usb_sg=1`.

## Status

On 0.x until Owly 1.0: the API can change between minor versions.

## License

MIT
