//! Cross-host 7-layer AWDL + smoltcp + AirDrop file transfer over UDP Radiotap.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use owly_userspace::air::udp::UdpRadiotapAir;
use owly_userspace::owly_airdrop::proto::mdns::{BrowseEvent, RECEIVER_FLAGS, SUPPORTS_DVZIP};
use owly_userspace::owly_airdrop::proto::sender::Outcome;
use owly_userspace::owly_awdl::MacAddr;
use owly_userspace::owly_awdl::channel::Channel;
use owly_userspace::{
    DEFAULT_RECEIVER_PORT, PcapWriter, UserspaceNode, UserspaceReceiveEvent, default_awdl_config,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut role = String::new();
    let mut bind_addr = String::new();
    let mut peer_addr = String::new();
    let mut channel_num: u8 = 149;
    let mut file_path: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut pcap_path: Option<PathBuf> = None;
    let mut timeout_secs: u64 = 20;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--role" => role = args.next().ok_or("missing --role")?,
            "--bind" => bind_addr = args.next().ok_or("missing --bind")?,
            "--peer" => peer_addr = args.next().ok_or("missing --peer")?,
            "--channel" => channel_num = args.next().ok_or("missing --channel")?.parse()?,
            "--file" => file_path = Some(PathBuf::from(args.next().ok_or("missing --file")?)),
            "--out-dir" => out_dir = Some(PathBuf::from(args.next().ok_or("missing --out-dir")?)),
            "--pcap" => pcap_path = Some(PathBuf::from(args.next().ok_or("missing --pcap")?)),
            "--timeout-secs" => {
                timeout_secs = args.next().ok_or("missing --timeout-secs")?.parse()?
            }
            other => return Err(format!("unknown flag {other}").into()),
        }
    }

    let bind: SocketAddr = bind_addr.parse()?;
    let peer: SocketAddr = peer_addr.parse()?;
    let channel = Channel(channel_num);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main(
        role,
        bind,
        peer,
        channel,
        file_path,
        out_dir,
        pcap_path,
        timeout_secs,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn async_main(
    role: String,
    bind: SocketAddr,
    peer: SocketAddr,
    channel: Channel,
    file_path: Option<PathBuf>,
    mut out_dir: Option<PathBuf>,
    pcap_path: Option<PathBuf>,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let channel_num = channel.0;
    let mut air = UdpRadiotapAir::bind(bind, peer).await?;

    let mut pcap = match pcap_path {
        Some(ref p) => Some(PcapWriter::new(std::fs::File::create(p)?)?),
        None => None,
    };

    let mac = if role == "rx" {
        MacAddr([0x02, 0x00, 0x00, 0x10, 0x00, 0x01])
    } else {
        MacAddr([0x02, 0x00, 0x00, 0x10, 0x00, 0x02])
    };
    let name = if role == "rx" { "udp-rx" } else { "udp-tx" };
    let mut node = UserspaceNode::new(default_awdl_config(mac, name, channel), 0);

    let payload: Vec<(String, Vec<u8>)> = if role == "tx" {
        let p = file_path.ok_or("--file is required for --role tx")?;
        let fname = p
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("invalid file name")?
            .to_string();
        let bytes = std::fs::read(&p)?;
        vec![(fname, bytes)]
    } else {
        Vec::new()
    };

    if role == "rx" {
        let dest = out_dir.unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dest)?;
        out_dir = Some(dest);
        node.enable_receiver(
            "UDP Bridge Rx",
            "020000100001",
            "udp-rx",
            DEFAULT_RECEIVER_PORT,
            RECEIVER_FLAGS | SUPPORTS_DVZIP,
            0,
        )?;
        println!(
            "UDP_BRIDGE_RX_READY bind={} peer={peer} ch={channel_num}",
            air.local_addr()?
        );
    } else if role == "tx" {
        node.enable_browser(0);
        println!(
            "UDP_BRIDGE_TX_READY bind={} peer={peer} ch={channel_num}",
            air.local_addr()?
        );
    } else {
        return Err("--role must be rx or tx".into());
    }

    let start = Instant::now();
    let deadline = start + Duration::from_secs(timeout_secs);
    let mut sent = false;
    let mut tx_done = false;
    let mut rx_saved = false;
    let mut tx_frames = 0u64;
    let mut rx_frames = 0u64;

    while Instant::now() < deadline {
        let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let incoming = air.try_drain_rx();
        rx_frames += incoming.len() as u64;
        if let Some(pw) = pcap.as_mut() {
            for (rssi, frame_bytes) in &incoming {
                let _ = pw.write_80211_frame(now_us, *rssi, frame_bytes);
            }
        }

        for frame in node.step(now_us, &incoming) {
            if let Some(pw) = pcap.as_mut() {
                let _ = pw.write_80211_frame(now_us, Some(-40), &frame.bytes);
            }
            if air.try_send(&frame, Some(-40)).is_ok() {
                tx_frames += 1;
            }
        }

        if role == "rx" {
            while let Some(ev) = node.poll_receiver_event() {
                match ev {
                    UserspaceReceiveEvent::Ask { id, .. } => {
                        let _ = node.accept_ask(id);
                    }
                    UserspaceReceiveEvent::ReceivedFiles { files, .. } => {
                        let dest = out_dir.as_ref().expect("out_dir");
                        for (fname, data) in files {
                            let safe = std::path::Path::new(&fname)
                                .file_name()
                                .ok_or("unsafe filename")?;
                            let target = dest.join(safe);
                            std::fs::write(&target, &data)?;
                            println!(
                                "RECEIVED_FILE path={} bytes={}",
                                target.display(),
                                data.len()
                            );
                        }
                        rx_saved = true;
                    }
                    UserspaceReceiveEvent::Failed { reason, .. } => {
                        return Err(format!("receiver failed: {reason}").into());
                    }
                    _ => {}
                }
            }
            if rx_saved {
                break;
            }
        } else {
            if !sent {
                while let Some(ev) = node.poll_browse_event() {
                    if let BrowseEvent::Found(svc) = ev {
                        println!("DISCOVERED {} at [{}]:{}", svc.instance, svc.addr, svc.port);
                        node.start_send_files(
                            svc.addr,
                            svc.port,
                            svc.flags,
                            "UDP Sender",
                            &payload,
                        )?;
                        sent = true;
                        break;
                    }
                }
            }
            if sent && let Some(out) = node.take_transfer_outcome() {
                println!("TX_OUTCOME {out:?} tx_frames={tx_frames} rx_frames={rx_frames}");
                if out != Outcome::Delivered {
                    return Err(format!("transfer failed: {out:?}").into());
                }
                tx_done = true;
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    if let Some(mut pw) = pcap {
        pw.flush()?;
    }

    if role == "rx" && !rx_saved {
        return Err("receiver timed out before file arrived".into());
    }
    if role == "tx" && !tx_done {
        return Err("sender timed out before transfer completed".into());
    }
    println!("DONE role={role} tx_frames={tx_frames} rx_frames={rx_frames}");
    Ok(())
}
