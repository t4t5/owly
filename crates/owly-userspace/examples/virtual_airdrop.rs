//! Runs a complete 7-layer AirDrop file transfer entirely in userspace (no root, no TAP).

use std::path::PathBuf;

use owly_userspace::air::SimAirHub;
use owly_userspace::owly_airdrop::proto::mdns::{RECEIVER_FLAGS, SUPPORTS_DVZIP};
use owly_userspace::owly_airdrop::proto::sender::Outcome;
use owly_userspace::owly_awdl::MacAddr;
use owly_userspace::owly_awdl::channel::Channel;
use owly_userspace::{
    DEFAULT_RECEIVER_PORT, UserspaceNode, UserspaceReceiveEvent, default_awdl_config,
};

fn main() {
    let mut pcap_out: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--pcap" {
            pcap_out = args.next().map(PathBuf::from);
        }
    }

    let channel = Channel(149);
    let mut hub = if let Some(path) = &pcap_out {
        let f = std::fs::File::create(path).expect("create pcap file");
        SimAirHub::new().with_pcap(f).expect("init pcap writer")
    } else {
        SimAirHub::new()
    };

    let rx_id = hub.register(channel);
    let tx_id = hub.register(channel);

    let mut rx = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            "demo-rx",
            channel,
        ),
        0,
    );
    let mut tx = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            "demo-tx",
            channel,
        ),
        0,
    );

    rx.enable_receiver(
        "Demo Receiver",
        "1234567890ab",
        "demo-rx",
        DEFAULT_RECEIVER_PORT,
        RECEIVER_FLAGS | SUPPORTS_DVZIP,
        0,
    )
    .expect("enable receiver");
    tx.enable_browser(0);

    let payload = vec![(
        "greeting.txt".to_string(),
        b"Transferred over 7-layer Rust userspace AWDL + smoltcp + rustls + AirDrop!\n".to_vec(),
    )];

    let mut now_us = 0u64;
    let mut sent = false;
    let mut received = Vec::new();
    let mut outcome: Option<Outcome> = None;

    for _ in 0..4000 {
        for (id, node) in [(rx_id, &mut rx), (tx_id, &mut tx)] {
            let incoming = hub.drain_rx(id);
            for frame in node.step(now_us, &incoming) {
                hub.transmit(id, now_us, &frame);
            }
        }
        while let Some(ev) = rx.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, request } => {
                    println!(
                        "Receiver prompted by {:?} (transfer {:?}); accepting.",
                        request.sender_computer_name, request.transfer_id
                    );
                    rx.accept_ask(id);
                }
                UserspaceReceiveEvent::ReceivedFiles { files, .. } => {
                    received = files;
                }
                _ => {}
            }
        }
        if !sent && let Some(svc) = tx.discovered_services().first() {
            println!(
                "Discovered AirDrop receiver {} ({}) at [{}]:{} flags={:#x}",
                svc.instance, svc.host, svc.addr, svc.port, svc.flags
            );
            tx.start_send_files(svc.addr, svc.port, svc.flags, "Demo Sender", &payload)
                .expect("start file send");
            sent = true;
        }
        if sent && outcome.is_none() {
            outcome = tx.take_transfer_outcome();
        }
        if outcome.is_some() && !received.is_empty() {
            break;
        }
        now_us += 2_000;
    }

    hub.flush_pcap().expect("flush pcap");
    let stats = hub.stats();
    println!(
        "Transfer outcome={outcome:?}, received {} file(s), simulated RF frames tx={} delivered={}",
        received.len(),
        stats.transmitted,
        stats.delivered
    );
    if let Some(path) = pcap_out {
        println!("Wrote Radiotap PCAP to {}", path.display());
    }
    assert_eq!(outcome, Some(Outcome::Delivered));
    assert_eq!(received, payload);
}
