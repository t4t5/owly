//! Drives live 7-layer AirDrop over a real MediaTek MT7612U (`mt76x2u`) USB dongle
//! via `nusb` + `owly-userspace` (`Mt7612uRadio` + `UserspaceNode`).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use owly_userspace::air::usb::{SupportedDongle, discover_dongles};
use owly_userspace::mt7612u_hw::Mt7612uRadio;
use owly_userspace::owly_airdrop::proto::mdns::{BrowseEvent, RECEIVER_FLAGS, SUPPORTS_DVZIP};
use owly_userspace::owly_airdrop::proto::sender::Outcome;
use owly_userspace::owly_awdl::MacAddr;
use owly_userspace::owly_awdl::channel::Channel;
use owly_userspace::usb_radio::{Mt7612uFirmware, Mt7612uRomPatch};
use owly_userspace::{
    DEFAULT_RECEIVER_PORT, UserspaceNode, UserspaceReceiveEvent, default_awdl_config,
    ensure_crypto_provider,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Observe,
    Receive,
    Send,
}

struct Args {
    fw_dir: PathBuf,
    channel: u8,
    mode: Mode,
    peer_name: Option<String>,
    files: Vec<PathBuf>,
    urls: Vec<String>,
    save_dir: Option<PathBuf>,
    duration_secs: u64,
    name: String,
    mac_override: Option<[u8; 6]>,
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let mac: MacAddr = s.parse().map_err(|e| format!("invalid MAC {s:?}: {e}"))?;
    Ok(mac.0)
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        fw_dir: PathBuf::from("."),
        channel: 149,
        mode: Mode::Observe,
        peer_name: None,
        files: Vec::new(),
        urls: Vec::new(),
        save_dir: None,
        duration_secs: 20,
        name: "Owly USB".to_string(),
        mac_override: None,
    };

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let next = |it: &mut std::iter::Skip<std::env::Args>, f: &str| {
            it.next().ok_or_else(|| format!("missing value for {f}"))
        };
        match flag.as_str() {
            "--fw-dir" => args.fw_dir = PathBuf::from(next(&mut it, "--fw-dir")?),
            "--channel" => {
                args.channel = next(&mut it, "--channel")?
                    .parse()
                    .map_err(|e| format!("invalid channel: {e}"))?;
            }
            "--mode" => {
                args.mode = match next(&mut it, "--mode")?.as_str() {
                    "observe" => Mode::Observe,
                    "receive" => Mode::Receive,
                    "send" => Mode::Send,
                    other => return Err(format!("invalid --mode {other:?}")),
                };
            }
            "--peer-name" => args.peer_name = Some(next(&mut it, "--peer-name")?),
            "--file" => args.files.push(PathBuf::from(next(&mut it, "--file")?)),
            "--url" => args.urls.push(next(&mut it, "--url")?),
            "--save-dir" => args.save_dir = Some(PathBuf::from(next(&mut it, "--save-dir")?)),
            "--duration-secs" => {
                args.duration_secs = next(&mut it, "--duration-secs")?
                    .parse()
                    .map_err(|e| format!("invalid duration: {e}"))?;
            }
            "--name" => args.name = next(&mut it, "--name")?,
            "--mac" => args.mac_override = Some(parse_mac(&next(&mut it, "--mac")?)?),
            "--help" | "-h" => {
                return Err(
                    "usage: live_usb_airdrop [--fw-dir DIR] [--channel 149] [--mode observe|receive|send] [--peer-name SUBSTR] [--file PATH] [--url URL] [--save-dir DIR] [--duration-secs 20] [--name NAME] [--mac AA:BB:CC:DD:EE:FF]"
                        .to_string(),
                );
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }

    if args.mode == Mode::Send && args.files.is_empty() && args.urls.is_empty() {
        return Err("--mode send requires --file or --url".to_string());
    }
    Ok(args)
}

fn sanitize_host_label(name: &str) -> String {
    let label: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if label.is_empty() {
        "owlyusb".to_string()
    } else {
        label
    }
}

fn write_received_files(save_dir: &Path, files: &[(String, Vec<u8>)]) -> std::io::Result<()> {
    fs::create_dir_all(save_dir)?;
    for (rel, data) in files {
        let leaf = Path::new(rel)
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty() && *s != "." && *s != "..")
            .unwrap_or("received.bin");
        let target = save_dir.join(leaf);
        fs::write(&target, data)?;
        println!("SAVED_FILE path={} bytes={}", target.display(), data.len());
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    let args = parse_args().map_err(std::io::Error::other)?;

    let patch_bytes = fs::read(args.fw_dir.join("mt7662_rom_patch.bin"))?;
    let fw_bytes = fs::read(args.fw_dir.join("mt7662.bin"))?;
    let patch = Mt7612uRomPatch::parse(&patch_bytes).map_err(std::io::Error::other)?;
    let fw = Mt7612uFirmware::parse(&fw_bytes).map_err(std::io::Error::other)?;

    let dongles = discover_dongles()?;
    let dongle = dongles
        .iter()
        .find(|d| d.kind == SupportedDongle::Mt7612u)
        .ok_or("no MT7612U USB dongle found via nusb")?;

    let mut radio = Mt7612uRadio::open_and_init(
        dongle,
        &patch,
        &fw,
        args.mac_override,
        Channel(args.channel),
    )?;
    let mac = MacAddr(radio.mac());
    let mut node = UserspaceNode::new(
        default_awdl_config(mac, &args.name, Channel(args.channel)),
        0,
    );

    println!(
        "RADIO_READY mac={} link_local={} channel={} asic=0x{:08x} mode={:?}",
        mac,
        node.link_local(),
        args.channel,
        radio.asic_version(),
        args.mode
    );

    match args.mode {
        Mode::Observe => node.enable_browser(0),
        Mode::Send => node.enable_browser(0),
        Mode::Receive => {
            let record_id = format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]
            );
            let host = sanitize_host_label(&args.name);
            node.enable_receiver(
                &args.name,
                &record_id,
                &host,
                DEFAULT_RECEIVER_PORT,
                RECEIVER_FLAGS | SUPPORTS_DVZIP,
                0,
            )
            .map_err(std::io::Error::other)?;
            node.enable_browser(0);
        }
    }

    let send_files: Vec<(String, Vec<u8>)> = args
        .files
        .iter()
        .map(|p| {
            let name = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("payload.bin")
                .to_string();
            let bytes = fs::read(p)?;
            Ok::<_, std::io::Error>((name, bytes))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let start = Instant::now();
    let deadline = Duration::from_secs(args.duration_secs);
    let mut last_drain = Instant::now();
    let mut rx_count = 0u64;
    let mut known_peers: BTreeSet<MacAddr> = BTreeSet::new();
    let mut send_started = false;
    let mut done_at: Option<(Instant, bool)> = None;

    while start.elapsed() < deadline {
        if let Some((finished, success)) = done_at
            && finished.elapsed() >= Duration::from_millis(400)
        {
            if !success {
                return Err("AirDrop transfer did not succeed".into());
            }
            return Ok(());
        }

        let mut rx_batch = Vec::new();
        while let Some((rssi, mpdu)) = radio.try_recv_mpdu() {
            rx_count += 1;
            if rx_count <= 10 || rx_count.is_multiple_of(50) {
                let fc = if mpdu.len() >= 2 {
                    u16::from_le_bytes([mpdu[0], mpdu[1]])
                } else {
                    0
                };
                println!(
                    "AWDL_RX count={rx_count} rssi={rssi:?} len={} fc=0x{fc:04x}",
                    mpdu.len()
                );
            }
            rx_batch.push((rssi, mpdu));
        }

        let now_us = start.elapsed().as_micros() as u64;
        for tx_frame in node.step(now_us, &rx_batch) {
            if let Err(e) = radio.send_frame(&tx_frame) {
                eprintln!("WARN: USB TX failed: {e}");
            }
        }

        for peer in node.valid_peers() {
            if known_peers.insert(peer) {
                println!("PEER_UP mac={} link_local={}", peer, peer.link_local());
            }
        }

        while let Some(ev) = node.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, request } => {
                    println!("ASK id={id} request={request:?}");
                    let _ = node.accept_ask(id);
                }
                UserspaceReceiveEvent::ReceivedFiles { id, files } => {
                    println!("RECEIVED_FILES id={id} count={}", files.len());
                    for (name, data) in &files {
                        println!("RECV_ITEM name={name:?} bytes={}", data.len());
                    }
                    if let Some(dir) = args.save_dir.as_deref() {
                        write_received_files(dir, &files)?;
                    }
                    println!("TRANSFER_DONE outcome=Delivered");
                    if args.mode == Mode::Receive && done_at.is_none() {
                        done_at = Some((Instant::now(), true));
                    }
                }
                UserspaceReceiveEvent::Urls { id, urls } => {
                    println!("RECEIVED_URLS id={id} urls={urls:?}");
                    println!("TRANSFER_DONE outcome=Delivered");
                    if args.mode == Mode::Receive && done_at.is_none() {
                        done_at = Some((Instant::now(), true));
                    }
                }
                UserspaceReceiveEvent::Failed { id, reason } => {
                    println!("RECEIVER_FAILED id={id} reason={reason}");
                }
                _ => {}
            }
        }

        while let Some(ev) = node.poll_browse_event() {
            match ev {
                BrowseEvent::Found(svc) => {
                    println!(
                        "BROWSE_FOUND instance={} host={} addr={} port={} flags=0x{:x}",
                        svc.instance, svc.host, svc.addr, svc.port, svc.flags
                    );
                    let matches_peer = args.peer_name.as_ref().is_none_or(|needle| {
                        let q = needle.to_ascii_lowercase();
                        svc.host.to_ascii_lowercase().contains(&q)
                            || svc.instance.to_ascii_lowercase().contains(&q)
                    });
                    if args.mode == Mode::Send && !send_started && matches_peer {
                        if !send_files.is_empty() {
                            node.start_send_files(
                                svc.addr,
                                svc.port,
                                svc.flags,
                                &args.name,
                                &send_files,
                            )
                            .map_err(std::io::Error::other)?;
                        } else {
                            node.start_send_urls(svc.addr, svc.port, &args.name, args.urls.clone())
                                .map_err(std::io::Error::other)?;
                        }
                        send_started = true;
                        println!("SEND_STARTED target={}", svc.addr);
                    }
                }
                BrowseEvent::Lost(id) => {
                    println!("BROWSE_LOST instance={id}");
                }
            }
        }

        if send_started
            && done_at.is_none()
            && let Some(outcome) = node.take_transfer_outcome()
        {
            println!("TRANSFER_DONE outcome={outcome:?}");
            done_at = Some((Instant::now(), outcome == Outcome::Delivered));
        }

        if last_drain.elapsed() >= Duration::from_millis(100) {
            radio.drain_tx_status();
            last_drain = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(1));
    }

    println!(
        "STOPPED rx_count={rx_count} valid_peers={}",
        known_peers.len()
    );
    if args.mode != Mode::Observe && done_at.is_none() {
        return Err(format!(
            "timed out after {}s without completed transfer",
            args.duration_secs
        )
        .into());
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("live_usb_airdrop error: {e}");
        std::process::exit(1);
    }
}
