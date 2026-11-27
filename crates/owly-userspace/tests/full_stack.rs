use owly_userspace::air::SimAirHub;
use owly_userspace::archive::build_in_memory_upload;
use owly_userspace::owly_airdrop::proto::archive::compress::Compressor;
use owly_userspace::owly_airdrop::proto::mdns::{BrowseEvent, RECEIVER_FLAGS, SUPPORTS_DVZIP};
use owly_userspace::owly_airdrop::proto::receiver::Config as ReceiverConfig;
use owly_userspace::owly_airdrop::proto::sender::Outcome;
use owly_userspace::owly_awdl::MacAddr;
use owly_userspace::owly_awdl::channel::Channel;
use owly_userspace::{
    DEFAULT_IN_MEMORY_UPLOAD_LIMIT, DEFAULT_RECEIVER_PORT, UserspaceNode, UserspaceReceiveEvent,
    compressor_for_receiver_flags, default_awdl_config, read_pcap,
};

type SimTransferResult = (Outcome, Vec<(String, Vec<u8>)>, Option<String>);

fn install_test_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn run_transfer_over_sim(
    receiver_flags: u32,
    pcap_path: Option<&std::path::Path>,
    accept_transfer: bool,
    payload: Vec<(String, Vec<u8>)>,
) -> SimTransferResult {
    install_test_crypto_provider();
    let ch = Channel(149);
    let mac_rx = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x01]);
    let mac_tx = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x02]);

    let mut hub = if let Some(path) = pcap_path {
        let f = std::fs::File::create(path).unwrap();
        SimAirHub::new().with_pcap(f).unwrap()
    } else {
        SimAirHub::new()
    };
    let id_rx = hub.register(ch);
    let id_tx = hub.register(ch);

    let mut rx_node = UserspaceNode::new(default_awdl_config(mac_rx, "rx-node", ch), 0);
    let mut tx_node = UserspaceNode::new(default_awdl_config(mac_tx, "tx-node", ch), 0);

    rx_node
        .enable_receiver(
            "Userspace Rx",
            "001122334401",
            "userspace-rx",
            DEFAULT_RECEIVER_PORT,
            receiver_flags,
            0,
        )
        .unwrap();
    tx_node.enable_browser(0);

    let dt_us = 2_000;
    let mut now_us = 0u64;
    let mut found_svc = None;
    let mut discovered_name = None;
    let mut discover_started = false;
    let mut transfer_started = false;
    let mut received_files = Vec::new();
    let mut final_outcome = None;

    for _ in 0..5000 {
        for (id, node) in [(id_rx, &mut rx_node), (id_tx, &mut tx_node)] {
            let rx = hub.drain_rx(id);
            for frame in node.step(now_us, &rx) {
                hub.transmit(id, now_us, &frame);
            }
        }

        while let Some(ev) = rx_node.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, .. } => {
                    if accept_transfer {
                        assert!(rx_node.accept_ask(id));
                    } else {
                        assert!(rx_node.decline_ask(id));
                    }
                }
                UserspaceReceiveEvent::ReceivedFiles { files, .. } => {
                    received_files = files;
                }
                UserspaceReceiveEvent::Failed { reason, .. } => {
                    panic!("receiver failed unexpectedly: {reason}");
                }
                _ => {}
            }
        }

        if found_svc.is_none() {
            while let Some(ev) = tx_node.poll_browse_event() {
                if let BrowseEvent::Found(svc) = ev {
                    found_svc = Some(svc);
                }
            }
        }

        if let Some(svc) = &found_svc
            && !discover_started
        {
            tx_node.start_discover(svc.addr, svc.port, now_us).unwrap();
            discover_started = true;
        }

        if let Some(res) = tx_node.take_discover_result() {
            let peer = res.expect("discover error").expect("missing discover body");
            discovered_name = Some(peer.computer_name.clone());
            let svc = found_svc.as_ref().unwrap();
            tx_node
                .start_send_files(svc.addr, svc.port, svc.flags, "Userspace Tx", &payload)
                .unwrap();
            transfer_started = true;
        }

        if transfer_started && final_outcome.is_none() {
            final_outcome = tx_node.take_transfer_outcome();
        }

        if final_outcome.is_some() && (!accept_transfer || !received_files.is_empty()) {
            break;
        }
        now_us += dt_us;
    }

    hub.flush_pcap().unwrap();
    let outcome = final_outcome.expect("transfer never completed");
    (outcome, received_files, discovered_name)
}

#[test]
fn full_7_layer_file_transfer_gzip_and_dvzip() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("awdl_7layer.pcap");

    let payload = vec![
        (
            "hello.txt".to_string(),
            b"Pure Rust 7-layer AirDrop!\n".to_vec(),
        ),
        ("binary.bin".to_string(), vec![0xA5; 24 * 1024]),
    ];

    // 1. Gzip mode (RECEIVER_FLAGS omits SUPPORTS_DVZIP)
    let (outcome_gz, rx_gz, disc_gz) =
        run_transfer_over_sim(RECEIVER_FLAGS, Some(&pcap_path), true, payload.clone());
    assert_eq!(disc_gz.as_deref(), Some("Userspace Rx"));
    assert_eq!(outcome_gz, Outcome::Delivered);
    assert_eq!(rx_gz, payload);

    // 2. Verify generated Wireshark-compatible Radiotap PCAP
    let pcap_frames = read_pcap(std::fs::File::open(&pcap_path).unwrap()).unwrap();
    assert!(
        pcap_frames.len() >= 10,
        "expected >=10 captured 802.11 frames, got {}",
        pcap_frames.len()
    );

    // 3. DVZip mode (advertises SUPPORTS_DVZIP)
    let (outcome_dvz, rx_dvz, disc_dvz) =
        run_transfer_over_sim(RECEIVER_FLAGS | SUPPORTS_DVZIP, None, true, payload.clone());
    assert_eq!(disc_dvz.as_deref(), Some("Userspace Rx"));
    assert_eq!(outcome_dvz, Outcome::Delivered);
    assert_eq!(rx_dvz, payload);
}

#[test]
fn large_incompressible_upload_drains_tls_deframer() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut data = vec![0u8; 128 * 1024];
    for b in &mut data {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *b = (z ^ (z >> 31)) as u8;
    }
    let payload = vec![("random_128k.bin".to_string(), data)];
    let (outcome, received, _) =
        run_transfer_over_sim(RECEIVER_FLAGS | SUPPORTS_DVZIP, None, true, payload.clone());
    assert_eq!(outcome, Outcome::Delivered);
    assert_eq!(received, payload);
}

#[test]
fn interactive_decline_and_url_share() {
    let payload = vec![("secret.txt".to_string(), b"do not save".to_vec())];
    let (outcome_declined, rx_files, _) =
        run_transfer_over_sim(RECEIVER_FLAGS, None, false, payload);
    assert_eq!(outcome_declined, Outcome::Declined);
    assert!(rx_files.is_empty());

    // URL share over simulated AWDL + smoltcp + rustls
    let ch = Channel(44);
    let mac_rx = MacAddr([0x02, 0x44, 0x55, 0x66, 0x77, 0x01]);
    let mac_tx = MacAddr([0x02, 0x44, 0x55, 0x66, 0x77, 0x02]);
    let mut hub = SimAirHub::new();
    let id_rx = hub.register(ch);
    let id_tx = hub.register(ch);

    let mut rx_node = UserspaceNode::new(default_awdl_config(mac_rx, "rx-url", ch), 0);
    let mut tx_node = UserspaceNode::new(default_awdl_config(mac_tx, "tx-url", ch), 0);
    rx_node
        .enable_receiver(
            "URL Rx",
            "abcdef123456",
            "url-rx",
            DEFAULT_RECEIVER_PORT,
            RECEIVER_FLAGS,
            0,
        )
        .unwrap();
    tx_node.enable_browser(0);

    let urls = vec!["https://git.manymath.com/sneurlax/owly-userspace".to_string()];
    let mut now_us = 0u64;
    let mut sent = false;
    let mut got_urls = None;
    let mut outcome = None;

    for _ in 0..4000 {
        for (id, node) in [(id_rx, &mut rx_node), (id_tx, &mut tx_node)] {
            let rx = hub.drain_rx(id);
            for frame in node.step(now_us, &rx) {
                hub.transmit(id, now_us, &frame);
            }
        }
        while let Some(ev) = rx_node.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, .. } => {
                    rx_node.accept_ask(id);
                }
                UserspaceReceiveEvent::Urls { urls: u, .. } => {
                    got_urls = Some(u);
                }
                _ => {}
            }
        }
        if !sent && let Some(svc) = tx_node.discovered_services().first() {
            tx_node
                .start_send_urls(svc.addr, svc.port, "URL Tx", urls.clone())
                .unwrap();
            sent = true;
        }
        if sent && outcome.is_none() {
            outcome = tx_node.take_transfer_outcome();
        }
        if outcome.is_some() && got_urls.is_some() {
            break;
        }
        now_us += 2_000;
    }

    assert_eq!(outcome, Some(Outcome::Delivered));
    assert_eq!(got_urls, Some(urls));
}

#[test]
fn three_node_mesh_under_packet_loss() {
    install_test_crypto_provider();
    let ch = Channel(6);
    let mut hub = SimAirHub::new().with_loss_permille(50); // 5% RF packet loss
    let macs = [
        MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0x00, 0x01]),
        MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0x00, 0x02]),
        MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0x00, 0x03]),
    ];
    let id1 = hub.register(ch);
    let id2 = hub.register(ch);
    let id3 = hub.register(ch);

    let mut n1 = UserspaceNode::new(default_awdl_config(macs[0], "node1", ch), 0);
    let mut n2 = UserspaceNode::new(default_awdl_config(macs[1], "node2", ch), 0);
    let mut n3 = UserspaceNode::new(default_awdl_config(macs[2], "node3", ch), 0);
    n3.enable_receiver(
        "Node Three",
        "333333333333",
        "node3",
        DEFAULT_RECEIVER_PORT,
        RECEIVER_FLAGS,
        0,
    )
    .unwrap();
    n1.enable_browser(0);

    let want = vec![("mesh.txt".to_string(), b"survived 5% packet loss!".to_vec())];
    let mut now_us = 0u64;
    let mut sent = false;
    let mut rx_files = Vec::new();
    let mut outcome = None;

    for _ in 0..8000 {
        for (id, node) in [(id1, &mut n1), (id2, &mut n2), (id3, &mut n3)] {
            let rx = hub.drain_rx(id);
            for frame in node.step(now_us, &rx) {
                hub.transmit(id, now_us, &frame);
            }
        }
        while let Some(ev) = n3.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, .. } => {
                    n3.accept_ask(id);
                }
                UserspaceReceiveEvent::ReceivedFiles { files, .. } => rx_files = files,
                _ => {}
            }
        }
        if !sent && let Some(svc) = n1.discovered_services().first() {
            n1.start_send_files(svc.addr, svc.port, svc.flags, "Node One", &want)
                .unwrap();
            sent = true;
        }
        if sent && outcome.is_none() {
            outcome = n1.take_transfer_outcome();
        }
        if outcome.is_some() && !rx_files.is_empty() {
            break;
        }
        now_us += 2_000;
    }

    assert!(
        n1.valid_peers().len() >= 2,
        "n1 peers: {:?}",
        n1.valid_peers()
    );
    assert!(
        n2.valid_peers().len() >= 2,
        "n2 peers: {:?}",
        n2.valid_peers()
    );
    assert!(
        n3.valid_peers().len() >= 2,
        "n3 peers: {:?}",
        n3.valid_peers()
    );
    assert!(hub.stats().dropped_loss > 0, "expected nonzero loss drops");
    assert_eq!(outcome, Some(Outcome::Delivered));
    assert_eq!(rx_files, want);
}

#[cfg(feature = "udp")]
#[tokio::test]
async fn udp_radiotap_bridge_transfer() {
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::time::Duration;

    use owly_userspace::air::udp::UdpRadiotapAir;
    use owly_userspace::owly_awdl::{Frame, TxRate};
    use owly_userspace::tx_radiotap;

    install_test_crypto_provider();

    let ch = Channel(149);
    let mac_rx = MacAddr([0x02, 0xde, 0xad, 0xbe, 0xef, 0x01]);
    let mac_tx = MacAddr([0x02, 0xde, 0xad, 0xbe, 0xef, 0x02]);

    // Reserve two loopback UDP ports cleanly before cross-connecting them.
    let probe_rx =
        std::net::UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)).unwrap();
    let probe_tx =
        std::net::UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)).unwrap();
    let addr_rx = probe_rx.local_addr().unwrap();
    let addr_tx = probe_tx.local_addr().unwrap();
    drop(probe_rx);
    drop(probe_tx);

    let mut air_rx = UdpRadiotapAir::bind(addr_rx, addr_tx).await.unwrap();
    let mut air_tx = UdpRadiotapAir::bind(addr_tx, addr_rx).await.unwrap();

    let intruder = tokio::net::UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
        .await
        .unwrap();
    let mut injected = tx_radiotap(Some(-10));
    injected.extend_from_slice(&[0xd0; 24]);
    intruder.send_to(&injected, addr_rx).await.unwrap();
    let trusted = Frame {
        bytes: vec![0xd0; 24],
        to: MacAddr([0xff; 6]),
        rate: TxRate::BASIC,
        no_ack: true,
    };
    air_tx.try_send(&trusted, Some(-20)).unwrap();
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(
        air_rx.try_drain_rx(),
        vec![(Some(-20), trusted.bytes)],
        "UDP bridge should accept only its configured peer"
    );

    let mut rx_node = UserspaceNode::new(default_awdl_config(mac_rx, "udp-rx", ch), 0);
    let mut tx_node = UserspaceNode::new(default_awdl_config(mac_tx, "udp-tx", ch), 0);
    rx_node
        .enable_receiver(
            "UDP Receiver",
            "feedface0001",
            "udp-rx",
            DEFAULT_RECEIVER_PORT,
            RECEIVER_FLAGS,
            0,
        )
        .unwrap();
    tx_node.enable_browser(0);

    let payload = vec![(
        "udp.txt".to_string(),
        b"across UDP radiotap bridge".to_vec(),
    )];
    let mut now_us = 0u64;
    let mut sent = false;
    let mut rx_files = Vec::new();
    let mut outcome = None;

    for _ in 0..4000 {
        let in_rx = air_rx.try_drain_rx();
        for f in rx_node.step(now_us, &in_rx) {
            let _ = air_rx.try_send(&f, Some(-38));
        }

        let in_tx = air_tx.try_drain_rx();
        for f in tx_node.step(now_us, &in_tx) {
            let _ = air_tx.try_send(&f, Some(-38));
        }

        while let Some(ev) = rx_node.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, .. } => {
                    rx_node.accept_ask(id);
                }
                UserspaceReceiveEvent::ReceivedFiles { files, .. } => rx_files = files,
                _ => {}
            }
        }
        if !sent && let Some(svc) = tx_node.discovered_services().first() {
            tx_node
                .start_send_files(svc.addr, svc.port, svc.flags, "UDP Sender", &payload)
                .unwrap();
            sent = true;
        }
        if sent && outcome.is_none() {
            outcome = tx_node.take_transfer_outcome();
        }
        if outcome.is_some() && !rx_files.is_empty() {
            break;
        }
        now_us += 2_000;
        if now_us.is_multiple_of(10_000) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    assert_eq!(outcome, Some(Outcome::Delivered));
    assert_eq!(rx_files, payload);
}

#[test]
fn in_memory_upload_rejects_unsafe_and_duplicate_names() {
    for name in ["dir/file.txt", r"dir\file.txt", "bad\0name", ".", ".."] {
        assert!(
            build_in_memory_upload(&[(name.into(), vec![1])], Compressor::DvZip).is_err(),
            "accepted {name:?}"
        );
    }
    assert!(
        build_in_memory_upload(
            &[("same.txt".into(), vec![1]), ("same.txt".into(), vec![2])],
            Compressor::Gzip,
        )
        .is_err()
    );
}

#[test]
fn receiver_setup_validates_lifecycle_and_default_limits() {
    assert_eq!(DEFAULT_IN_MEMORY_UPLOAD_LIMIT, 256 * 1024 * 1024);

    let ch = Channel(149);
    let mut invalid = UserspaceNode::new(
        default_awdl_config(MacAddr([0x02, 1, 2, 3, 4, 5]), "invalid", ch),
        0,
    );
    assert!(
        invalid
            .enable_receiver("Invalid", "invalid", "invalid", 0, RECEIVER_FLAGS, 0)
            .is_err()
    );

    let mut duplicate = UserspaceNode::new(
        default_awdl_config(MacAddr([0x02, 1, 2, 3, 4, 6]), "duplicate", ch),
        0,
    );
    duplicate
        .enable_receiver(
            "Receiver",
            "receiver",
            "receiver",
            DEFAULT_RECEIVER_PORT,
            RECEIVER_FLAGS,
            0,
        )
        .unwrap();
    assert!(
        duplicate
            .enable_receiver(
                "Receiver Again",
                "receiver-2",
                "receiver-2",
                DEFAULT_RECEIVER_PORT + 1,
                RECEIVER_FLAGS,
                0,
            )
            .is_err()
    );

    let mut custom_config = ReceiverConfig::new("Small Receiver");
    custom_config.limits.max_upload_body = 1024;
    custom_config.limits.extract.max_total = 512;
    let mut custom = UserspaceNode::new(
        default_awdl_config(MacAddr([0x02, 1, 2, 3, 4, 7]), "custom", ch),
        0,
    );
    custom
        .enable_receiver_with_config(
            custom_config,
            "custom",
            "custom",
            DEFAULT_RECEIVER_PORT + 2,
            RECEIVER_FLAGS,
            0,
        )
        .unwrap();
}

#[test]
fn compressor_selection_matches_receiver_flags() {
    assert_eq!(
        compressor_for_receiver_flags(RECEIVER_FLAGS),
        Compressor::Gzip
    );
    assert_eq!(
        compressor_for_receiver_flags(RECEIVER_FLAGS | SUPPORTS_DVZIP),
        Compressor::DvZip
    );
    assert_eq!(compressor_for_receiver_flags(0), Compressor::DvZip);
}
