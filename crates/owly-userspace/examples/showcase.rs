//! End-to-end showcase of `owly-userspace`: what it does that `owly-awdl`,
//! `owly-airdrop`, `owly-radio`, and `owlyd` cannot do on their own.
//!
//! Runs completely rootless, with zero kernel Wi-Fi drivers, zero `awdl0` TAP
//! interfaces, zero OS sockets, zero Wi-Fi hardware, and zero disk staging:
//!
//! 1. 4-node deterministic AWDL RF mesh on `SimAirHub` with configurable RF
//!    packet loss and channel isolation (Ch 149 vs Ch 44).
//! 2. Userspace IPv6 (`smoltcp` `Medium::Ip`, EUI-64 link-local) + mDNS
//!    `_airdrop._tcp` discovery over `ff02::fb:5353` (no Avahi/Bonjour).
//! 3. `rustls` TLS inside `smoltcp` TCP sockets: `/Discover` and interactive
//!    `/Ask` policy decline.
//! 4. In-memory multi-file DVZip & Gzip AirDrop transfers surviving simulated
//!    RF packet loss without writing temp files or staging directories.
//! 5. AirDrop URL share delivered directly to application memory.
//! 6. Clean-room MediaTek MT7612U USB bulk URB framing (`Mt7612uCodec`)
//!    carrying a full 7-layer AirDrop transfer without any kernel Wi-Fi driver.
//! 7. Live `DLT_IEEE802_11_RADIO` Radiotap PCAP capture verified with
//!    `read_pcap` + `parse_radiotap` + `owly_awdl::frame::parse` (optionally
//!    written to `--pcap <path>` for Wireshark).
//!
//! Run with:
//!   cargo run -p owly-userspace --example showcase
//!   cargo run -p owly-userspace --example showcase -- --pcap /tmp/owly-showcase.pcap --loss 50

use std::io::{self, Cursor, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use owly_userspace::air::SimAirHub;
use owly_userspace::owly_airdrop::proto::archive::compress::Compressor;
use owly_userspace::owly_airdrop::proto::mdns::{RECEIVER_FLAGS, SUPPORTS_DVZIP};
use owly_userspace::owly_airdrop::proto::sender::Outcome;
use owly_userspace::owly_awdl::MacAddr;
use owly_userspace::owly_awdl::channel::Channel;
use owly_userspace::owly_awdl::frame::{self, Received, subtype};
use owly_userspace::usb_radio::{Mt7612uCodec, RadioWire, UsbChipset, select_endpoints};
use owly_userspace::{
    DEFAULT_RECEIVER_PORT, UserspaceNode, UserspaceReceiveEvent, compressor_for_receiver_flags,
    default_awdl_config, parse_radiotap, read_pcap,
};

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("pcap buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn step_mesh(
    hub: &mut SimAirHub,
    now_us: &mut u64,
    dt_us: u64,
    nodes: &mut [(usize, &mut UserspaceNode)],
) {
    for (id, node) in nodes.iter_mut() {
        let rx = hub.drain_rx(*id);
        for frame in node.step(*now_us, &rx) {
            hub.transmit(*id, *now_us, &frame);
        }
    }
    *now_us += dt_us;
}

fn deterministic_blob(len: usize) -> Vec<u8> {
    let mut state = 0x517c_c1b7_2722_0a95u64;
    let mut out = vec![0u8; len];
    for byte in &mut out {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *byte = (z ^ (z >> 31)) as u8;
    }
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pcap_out: Option<PathBuf> = None;
    let mut loss_permille: u16 = 50; // 5% RF packet loss by default

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pcap" => {
                pcap_out = Some(PathBuf::from(
                    args.next().ok_or("missing value for --pcap")?,
                ));
            }
            "--loss" => {
                loss_permille = args
                    .next()
                    .ok_or("missing value for --loss")?
                    .parse::<u16>()?
                    .min(1000);
            }
            "--help" | "-h" => {
                println!(
                    "Usage: showcase [--pcap <output.pcap>] [--loss <permille 0..=1000, default 50>]"
                );
                return Ok(());
            }
            other => return Err(format!("unknown flag {other} (try --help)").into()),
        }
    }

    println!("========================================================================");
    println!("  owly-userspace 7-Layer Showcase (zero root, zero TAP, zero hardware)");
    println!("========================================================================");
    println!(
        "  Unlike owly-radio/owlyd (Linux root + nl80211 + awdl0 TAP + D-Bus) or\n  \
         owly-airdrop::driver (OS sockets + disk staging), every layer below\n  \
         runs inside this single Rust process on Linux, macOS, or Windows:\n  \
           L1-L2 : owly_awdl::Node (PSF/MIF sync, election, channel schedule)\n  \
           L3-L4 : smoltcp Medium::Ip (EUI-64 fe80::/64, TCP/UDP, no NDP)\n  \
           L4.5  : owly_airdrop::proto::mdns on smoltcp UDP ff02::fb:5353\n  \
           L5    : rustls TLS 1.2/1.3 pumped through smoltcp TCP sockets\n  \
           L6-L7 : owly_airdrop HTTP/bplist/CPIO completely in memory\n"
    );

    // -------------------------------------------------------------------------
    // Stage 1: 4-node RF mesh with channel isolation + packet loss + PCAP tap
    // -------------------------------------------------------------------------
    let ch_main = Channel(149);
    let ch_other = Channel(44);
    let pcap_buf = SharedBuf::default();
    let mut hub = SimAirHub::new()
        .with_loss_permille(loss_permille)
        .with_rssi(Some(-42))
        .with_pcap(pcap_buf.clone())?;

    let id_alice = hub.register(ch_main);
    let id_bob = hub.register(ch_main);
    let id_carol = hub.register(ch_main);
    let id_dave = hub.register(ch_other);

    let mut alice = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0x4f, 0x77, 0x00, 0x00, 0x01]),
            "alice",
            ch_main,
        ),
        0,
    );
    let mut bob = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0x4f, 0x77, 0x00, 0x00, 0x02]),
            "bob",
            ch_main,
        ),
        0,
    );
    let mut carol = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0x4f, 0x77, 0x00, 0x00, 0x03]),
            "carol",
            ch_main,
        ),
        0,
    );
    let mut dave = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0x4f, 0x77, 0x00, 0x00, 0x04]),
            "dave",
            ch_other,
        ),
        0,
    );

    bob.enable_receiver(
        "Bob (DVZip)",
        "024f77000002",
        "bob",
        DEFAULT_RECEIVER_PORT,
        RECEIVER_FLAGS | SUPPORTS_DVZIP,
        0,
    )?;
    carol.enable_receiver(
        "Carol (Gzip-only)",
        "024f77000003",
        "carol",
        DEFAULT_RECEIVER_PORT,
        RECEIVER_FLAGS,
        0,
    )?;
    dave.enable_receiver(
        "Dave (Ch 44)",
        "024f77000004",
        "dave",
        DEFAULT_RECEIVER_PORT,
        RECEIVER_FLAGS | SUPPORTS_DVZIP,
        0,
    )?;
    alice.enable_browser(0);

    println!(
        "[Stage 1] Booting 4 userspace nodes (RF loss = {:.1}%):",
        f64::from(loss_permille) / 10.0
    );
    println!("  alice (sender)   ch=149  ipv6={}", alice.link_local());
    println!(
        "  bob   (DVZip rx) ch=149  ipv6={}  flags={:#x}",
        bob.link_local(),
        RECEIVER_FLAGS | SUPPORTS_DVZIP
    );
    println!(
        "  carol (Gzip rx)  ch=149  ipv6={}  flags={:#x}",
        carol.link_local(),
        RECEIVER_FLAGS
    );
    println!(
        "  dave  (isolated) ch=44   ipv6={}  (different RF channel)",
        dave.link_local()
    );

    let dt_us = 2_000;
    let mut now_us = 0u64;
    let mut bob_svc = None;
    let mut carol_svc = None;

    for _ in 0..5000 {
        step_mesh(
            &mut hub,
            &mut now_us,
            dt_us,
            &mut [
                (id_alice, &mut alice),
                (id_bob, &mut bob),
                (id_carol, &mut carol),
                (id_dave, &mut dave),
            ],
        );
        for svc in alice.discovered_services() {
            if svc.instance == "024f77000002" {
                bob_svc = Some(svc);
            } else if svc.instance == "024f77000003" {
                carol_svc = Some(svc);
            }
        }
        if alice.valid_peers().len() == 2 && bob_svc.is_some() && carol_svc.is_some() {
            break;
        }
    }

    let bob_svc = bob_svc.ok_or("Alice failed to discover Bob over userspace mDNS")?;
    let carol_svc = carol_svc.ok_or("Alice failed to discover Carol over userspace mDNS")?;
    assert!(
        dave.valid_peers().is_empty(),
        "Dave on Ch 44 should remain isolated from Ch 149"
    );
    assert!(
        !alice
            .discovered_services()
            .iter()
            .any(|s| s.instance == "024f77000004"),
        "Alice on Ch 149 should not discover Dave on Ch 44"
    );

    println!(
        "  -> AWDL converged on Ch 149: {} valid peers, master={}, channel-isolated drops={}",
        alice.valid_peers().len(),
        alice.awdl().election().master,
        hub.stats().dropped_channel,
    );
    println!(
        "  -> mDNS discovered: Bob ([{}]:{}, DVZip={}) & Carol ([{}]:{}, DVZip={}); Dave invisible on Ch 44\n",
        bob_svc.addr,
        bob_svc.port,
        bob_svc.flags & SUPPORTS_DVZIP != 0,
        carol_svc.addr,
        carol_svc.port,
        carol_svc.flags & SUPPORTS_DVZIP != 0,
    );

    // -------------------------------------------------------------------------
    // Stage 2: TLS /Discover + Interactive /Ask Decline (Alice -> Carol)
    // -------------------------------------------------------------------------
    println!("[Stage 2] TLS /Discover + interactive /Ask policy decline (Alice -> Carol):");
    alice.start_discover(carol_svc.addr, carol_svc.port, now_us)?;
    let mut carol_peer = None;
    for _ in 0..3000 {
        step_mesh(
            &mut hub,
            &mut now_us,
            dt_us,
            &mut [
                (id_alice, &mut alice),
                (id_bob, &mut bob),
                (id_carol, &mut carol),
                (id_dave, &mut dave),
            ],
        );
        if let Some(res) = alice.take_discover_result() {
            carol_peer = res?;
            break;
        }
    }
    let carol_peer = carol_peer.ok_or("Carol /Discover returned empty response")?;
    println!(
        "  -> /Discover over rustls-in-smoltcp succeeded: computer_name={:?}, model={:?}",
        carol_peer.computer_name, carol_peer.model_name
    );

    let declined_offer = vec![("unwanted.txt".to_string(), b"never uploaded".to_vec())];
    alice.start_send_files(
        carol_svc.addr,
        carol_svc.port,
        carol_svc.flags,
        "Alice",
        &declined_offer,
    )?;
    let mut decline_outcome = None;
    for _ in 0..3000 {
        step_mesh(
            &mut hub,
            &mut now_us,
            dt_us,
            &mut [
                (id_alice, &mut alice),
                (id_bob, &mut bob),
                (id_carol, &mut carol),
                (id_dave, &mut dave),
            ],
        );
        while let Some(ev) = carol.poll_receiver_event() {
            if let UserspaceReceiveEvent::Ask { id, request } = ev {
                println!(
                    "  -> Carol prompted by {:?} for {:?}; calling decline_ask({id})",
                    request.sender_computer_name, request.offer
                );
                assert!(carol.decline_ask(id));
            }
        }
        if let Some(out) = alice.take_transfer_outcome() {
            decline_outcome = Some(out);
            break;
        }
    }
    assert_eq!(decline_outcome, Some(Outcome::Declined));
    println!("  -> Alice observed Outcome::Declined (zero payload bytes uploaded)\n");

    // -------------------------------------------------------------------------
    // Stage 3: Multi-file DVZip upload under simulated RF loss (Alice -> Bob)
    // -------------------------------------------------------------------------
    println!(
        "[Stage 3] In-memory multi-file DVZip upload under {:.1}% RF loss (Alice -> Bob):",
        f64::from(loss_permille) / 10.0
    );
    let dvzip_payload = vec![
        (
            "notes.txt".to_string(),
            b"Zero TAP, zero root, zero disk staging: Rust userspace 7-layer AirDrop!\n".to_vec(),
        ),
        ("sensor-dump.bin".to_string(), deterministic_blob(32 * 1024)),
    ];
    assert_eq!(
        compressor_for_receiver_flags(bob_svc.flags),
        Compressor::DvZip
    );
    alice.start_send_files(
        bob_svc.addr,
        bob_svc.port,
        bob_svc.flags,
        "Alice",
        &dvzip_payload,
    )?;

    let mut bob_received = Vec::new();
    let mut dvzip_outcome = None;
    for _ in 0..8000 {
        step_mesh(
            &mut hub,
            &mut now_us,
            dt_us,
            &mut [
                (id_alice, &mut alice),
                (id_bob, &mut bob),
                (id_carol, &mut carol),
                (id_dave, &mut dave),
            ],
        );
        while let Some(ev) = bob.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, request } => {
                    println!(
                        "  -> Bob prompted by {:?} (transfer {:?}); calling accept_ask({id})",
                        request.sender_computer_name, request.transfer_id
                    );
                    assert!(bob.accept_ask(id));
                }
                UserspaceReceiveEvent::ReceivedFiles { files, .. } => {
                    bob_received = files;
                }
                UserspaceReceiveEvent::Failed { reason, .. } => {
                    return Err(format!("Bob receiver failed: {reason}").into());
                }
                _ => {}
            }
        }
        if dvzip_outcome.is_none() {
            dvzip_outcome = alice.take_transfer_outcome();
        }
        if dvzip_outcome.is_some() && !bob_received.is_empty() {
            break;
        }
    }
    assert_eq!(dvzip_outcome, Some(Outcome::Delivered));
    assert_eq!(bob_received, dvzip_payload);
    println!(
        "  -> Delivered {} files ({} bytes total) byte-for-byte into memory (RF loss drops so far: {})\n",
        bob_received.len(),
        bob_received.iter().map(|(_, b)| b.len()).sum::<usize>(),
        hub.stats().dropped_loss,
    );

    // -------------------------------------------------------------------------
    // Stage 4: Legacy Gzip negotiation + URL share (Alice -> Carol)
    // -------------------------------------------------------------------------
    println!("[Stage 4] Legacy Gzip negotiation + AirDrop URL share (Alice -> Carol):");
    let gzip_payload = vec![(
        "legacy.txt".to_string(),
        b"Carol omitted SUPPORTS_DVZIP, so owly-userspace automatically negotiated Gzip.\n"
            .to_vec(),
    )];
    assert_eq!(
        compressor_for_receiver_flags(carol_svc.flags),
        Compressor::Gzip
    );
    alice.start_send_files(
        carol_svc.addr,
        carol_svc.port,
        carol_svc.flags,
        "Alice",
        &gzip_payload,
    )?;
    let mut carol_files = Vec::new();
    let mut gzip_outcome = None;
    for _ in 0..6000 {
        step_mesh(
            &mut hub,
            &mut now_us,
            dt_us,
            &mut [
                (id_alice, &mut alice),
                (id_bob, &mut bob),
                (id_carol, &mut carol),
                (id_dave, &mut dave),
            ],
        );
        while let Some(ev) = carol.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, .. } => {
                    assert!(carol.accept_ask(id));
                }
                UserspaceReceiveEvent::ReceivedFiles { files, .. } => {
                    carol_files = files;
                }
                UserspaceReceiveEvent::Failed { reason, .. } => {
                    return Err(format!("Carol Gzip receive failed: {reason}").into());
                }
                _ => {}
            }
        }
        if gzip_outcome.is_none() {
            gzip_outcome = alice.take_transfer_outcome();
        }
        if gzip_outcome.is_some() && !carol_files.is_empty() {
            break;
        }
    }
    assert_eq!(gzip_outcome, Some(Outcome::Delivered));
    assert_eq!(carol_files, gzip_payload);
    println!(
        "  -> Gzip file transfer delivered to Carol ({} bytes)",
        carol_files[0].1.len()
    );

    let shared_urls = vec!["https://github.com/t4t5/owly".to_string()];
    alice.start_send_urls(carol_svc.addr, carol_svc.port, "Alice", shared_urls.clone())?;
    let mut carol_urls = None;
    let mut url_outcome = None;
    for _ in 0..4000 {
        step_mesh(
            &mut hub,
            &mut now_us,
            dt_us,
            &mut [
                (id_alice, &mut alice),
                (id_bob, &mut bob),
                (id_carol, &mut carol),
                (id_dave, &mut dave),
            ],
        );
        while let Some(ev) = carol.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, .. } => {
                    assert!(carol.accept_ask(id));
                }
                UserspaceReceiveEvent::Urls { urls, .. } => {
                    carol_urls = Some(urls);
                }
                _ => {}
            }
        }
        if url_outcome.is_none() {
            url_outcome = alice.take_transfer_outcome();
        }
        if url_outcome.is_some() && carol_urls.is_some() {
            break;
        }
    }
    assert_eq!(url_outcome, Some(Outcome::Delivered));
    assert_eq!(carol_urls, Some(shared_urls.clone()));
    println!("  -> URL share accepted & delivered: {:?}\n", shared_urls);

    // -------------------------------------------------------------------------
    // Stage 5: Driverless USB Wi-Fi bulk URB framing (MT7612U codec)
    // -------------------------------------------------------------------------
    println!("[Stage 5] Clean-room MT7612U USB bulk URB framing (simulated radio path):");
    // Physical PAU0D (0e8d:7612) exposes EP 0x08 (inband MCU) before EP 0x04 (TX data).
    let pau0d_eps = [
        (0x84u8, 512usize),
        (0x85, 512),
        (0x08, 512),
        (0x04, 512),
        (0x05, 512),
    ];
    let selected = select_endpoints(UsbChipset::Mt7612u, &pau0d_eps)
        .ok_or("MT7612U endpoint selection failed")?;
    let init_ctrls =
        Mt7612uCodec::active_monitor_init_transfers([0x02, 0x76, 0x12, 0x00, 0x00, 0x01], ch_main)?;
    let fmt_ep = |ep: Option<u8>| ep.map_or_else(|| "none".into(), |e| format!("0x{e:02x}"));
    println!(
        "  -> Endpoint selection: data tx=0x{:02x} rx=0x{:02x}, mcu cmd_out={} cmd_in={}",
        selected.bulk_out_ep,
        selected.bulk_in_ep,
        fmt_ep(selected.cmd_out_ep),
        fmt_ep(selected.cmd_in_ep),
    );
    println!(
        "  -> Built {} vendor-control register writes for MT7612U active-monitor init on Ch 149",
        init_ctrls.len()
    );

    let codec = Mt7612uCodec;
    let mut usb_rx = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0x76, 0x12, 0x00, 0x00, 0x01]),
            "usb-rx",
            ch_main,
        ),
        0,
    );
    let mut usb_tx = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0x76, 0x12, 0x00, 0x00, 0x02]),
            "usb-tx",
            ch_main,
        ),
        0,
    );
    usb_rx.enable_receiver(
        "MT7612U Userspace Rx",
        "027612000001",
        "usb-rx",
        DEFAULT_RECEIVER_PORT,
        RECEIVER_FLAGS | SUPPORTS_DVZIP,
        0,
    )?;
    usb_tx.enable_browser(0);

    let usb_payload = vec![(
        "over-usb-urb.txt".to_string(),
        b"Every 802.11 MPDU of this AirDrop transfer passed through MT7612U TXWI/RXWI USB bulk URBs.\n"
            .to_vec(),
    )];
    let mut q_to_rx = Vec::new();
    let mut q_to_tx = Vec::new();
    let mut usb_now = 0u64;
    let mut usb_sent = false;
    let mut usb_got = Vec::new();
    let mut usb_outcome = None;
    let mut usb_frames = 0u64;

    for _ in 0..4000 {
        let rx_in: Vec<_> = q_to_rx
            .drain(..)
            .filter_map(|urb: Vec<u8>| codec.decapsulate_rx(&urb))
            .collect();
        for f in usb_rx.step(usb_now, &rx_in) {
            let tx_urb = codec.encapsulate_tx(&f);
            assert_eq!(tx_urb.len() % 4, 0);
            let mpdu = codec
                .decapsulate_tx(&tx_urb)
                .ok_or("MT7612U codec rejected its own TX URB")?;
            usb_frames += 1;
            q_to_tx.push(Mt7612uCodec::encode_rx_packet(&mpdu, -41));
        }

        let tx_in: Vec<_> = q_to_tx
            .drain(..)
            .filter_map(|urb: Vec<u8>| codec.decapsulate_rx(&urb))
            .collect();
        for f in usb_tx.step(usb_now, &tx_in) {
            let tx_urb = codec.encapsulate_tx(&f);
            assert_eq!(tx_urb.len() % 4, 0);
            let mpdu = codec
                .decapsulate_tx(&tx_urb)
                .ok_or("MT7612U codec rejected its own TX URB")?;
            usb_frames += 1;
            q_to_rx.push(Mt7612uCodec::encode_rx_packet(&mpdu, -41));
        }

        while let Some(ev) = usb_rx.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, .. } => {
                    assert!(usb_rx.accept_ask(id));
                }
                UserspaceReceiveEvent::ReceivedFiles { files, .. } => usb_got = files,
                UserspaceReceiveEvent::Failed { reason, .. } => {
                    return Err(format!("USB-framed receive failed: {reason}").into());
                }
                _ => {}
            }
        }
        if !usb_sent && let Some(svc) = usb_tx.discovered_services().first() {
            usb_tx.start_send_files(svc.addr, svc.port, svc.flags, "USB Tx", &usb_payload)?;
            usb_sent = true;
        }
        if usb_sent && usb_outcome.is_none() {
            usb_outcome = usb_tx.take_transfer_outcome();
        }
        if usb_outcome.is_some() && !usb_got.is_empty() {
            break;
        }
        usb_now += dt_us;
    }
    assert_eq!(usb_outcome, Some(Outcome::Delivered));
    assert_eq!(usb_got, usb_payload);
    println!(
        "  -> Completed full 7-layer AirDrop through {usb_frames} {} TX URBs and {usb_frames} synthetic RX URBs\n",
        codec.name()
    );

    // -------------------------------------------------------------------------
    // Stage 6: Radiotap PCAP inspection & 7-layer telemetry summary
    // -------------------------------------------------------------------------
    // Advance beyond a complete 110-TU PSF interval even when the lossless transfer finishes
    // unusually quickly, so the capture demonstrates both AWDL action-frame types.
    for _ in 0..60 {
        step_mesh(
            &mut hub,
            &mut now_us,
            dt_us,
            &mut [
                (id_alice, &mut alice),
                (id_bob, &mut bob),
                (id_carol, &mut carol),
                (id_dave, &mut dave),
            ],
        );
    }
    hub.flush_pcap()?;
    let pcap_bytes = pcap_buf.0.lock().expect("pcap buffer lock").clone();
    if let Some(path) = &pcap_out {
        std::fs::write(path, &pcap_bytes)?;
    }

    let captured = read_pcap(Cursor::new(&pcap_bytes))?;
    let mut psf_count = 0u64;
    let mut mif_count = 0u64;
    let mut data_count = 0u64;
    for (_ts, datagram) in &captured {
        if let Some((mpdu, _rssi)) = parse_radiotap(datagram)
            && let Ok(parsed) = frame::parse(mpdu)
        {
            match parsed {
                Received::Action {
                    subtype: subtype::PSF,
                    ..
                } => psf_count += 1,
                Received::Action {
                    subtype: subtype::MIF,
                    ..
                } => mif_count += 1,
                Received::Data { .. } => data_count += 1,
                _ => {}
            }
        }
    }
    assert!(psf_count > 0, "capture should contain an AWDL PSF");
    assert!(mif_count > 0, "capture should contain an AWDL MIF");
    assert!(data_count > 0, "capture should contain AWDL data frames");

    let stats = hub.stats();
    let (a_rx, a_tx) = alice.device_stats();
    let (b_rx, b_tx) = bob.device_stats();
    let (c_rx, c_tx) = carol.device_stats();

    println!("[Stage 6] Captured Radiotap PCAP & 7-layer telemetry:");
    println!(
        "  Simulated time : {:.1} ms across 4 stages on 4 nodes",
        now_us as f64 / 1000.0
    );
    println!(
        "  SimAirHub RF   : tx={} delivered={} dropped_loss={} dropped_channel={}",
        stats.transmitted, stats.delivered, stats.dropped_loss, stats.dropped_channel
    );
    println!(
        "  Radiotap PCAP  : {} records ({} bytes) -> PSF={} MIF={} AWDL-Data={}",
        captured.len(),
        pcap_bytes.len(),
        psf_count,
        mif_count,
        data_count
    );
    println!(
        "  smoltcp IPv6   : alice(rx={a_rx}, tx={a_tx})  bob(rx={b_rx}, tx={b_tx})  carol(rx={c_rx}, tx={c_tx})"
    );
    if let Some(path) = &pcap_out {
        println!(
            "  Wrote PCAP     : {} (open directly in Wireshark)",
            path.display()
        );
    } else {
        println!(
            "  Tip            : pass `-- --pcap /tmp/owly-showcase.pcap` to save for Wireshark"
        );
    }
    println!("\nAll 6 stages passed with zero root, zero TAP interfaces, and zero Wi-Fi hardware.");

    Ok(())
}
