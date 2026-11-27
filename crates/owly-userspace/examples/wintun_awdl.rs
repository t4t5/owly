//! Bridges a Windows Wintun virtual IPv6 interface (`awdl0`) directly to a
//! userspace MT7612U (`mt76x2u`) USB dongle running `owly_awdl::Node` (`active-monitor`).

#[cfg(windows)]
mod win_bridge {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use owly_userspace::air::usb::{SupportedDongle, discover_dongles};
    use owly_userspace::mt7612u_hw::Mt7612uRadio;
    use owly_userspace::owly_awdl::channel::Channel;
    use owly_userspace::owly_awdl::{Action, Input, Ipv6Packet, MacAddr, Node, Time};
    use owly_userspace::usb_radio::{Mt7612uFirmware, Mt7612uRomPatch};
    use owly_userspace::{AWDL_MTU, default_awdl_config};

    struct Args {
        wintun_dll: PathBuf,
        fw_dir: PathBuf,
        channel: u8,
        name: String,
        iface: String,
        mac_override: Option<[u8; 6]>,
        duration_secs: Option<u64>,
        stop_file: Option<PathBuf>,
    }

    fn parse_mac(s: &str) -> Result<[u8; 6], String> {
        let mac: MacAddr = s.parse().map_err(|e| format!("invalid MAC {s:?}: {e}"))?;
        Ok(mac.0)
    }

    fn parse_args() -> Result<Args, String> {
        let mut args = Args {
            wintun_dll: PathBuf::from("wintun.dll"),
            fw_dir: PathBuf::from("."),
            channel: 149,
            name: "owly-win".to_string(),
            iface: "awdl0".to_string(),
            mac_override: None,
            duration_secs: None,
            stop_file: None,
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let next = |it: &mut std::iter::Skip<std::env::Args>, f: &str| {
                it.next().ok_or_else(|| format!("missing value for {f}"))
            };
            match flag.as_str() {
                "--wintun-dll" => args.wintun_dll = PathBuf::from(next(&mut it, "--wintun-dll")?),
                "--fw-dir" => args.fw_dir = PathBuf::from(next(&mut it, "--fw-dir")?),
                "--channel" => {
                    args.channel = next(&mut it, "--channel")?
                        .parse()
                        .map_err(|e| format!("invalid channel: {e}"))?;
                }
                "--name" => args.name = next(&mut it, "--name")?,
                "--iface" => args.iface = next(&mut it, "--iface")?,
                "--mac" => args.mac_override = Some(parse_mac(&next(&mut it, "--mac")?)?),
                "--duration-secs" => {
                    args.duration_secs = Some(
                        next(&mut it, "--duration-secs")?
                            .parse()
                            .map_err(|e| format!("invalid duration: {e}"))?,
                    );
                }
                "--stop-file" => {
                    args.stop_file = Some(PathBuf::from(next(&mut it, "--stop-file")?))
                }
                "--help" | "-h" => {
                    return Err(
                        "usage: wintun_awdl [--wintun-dll PATH] [--fw-dir DIR] [--channel 149] [--iface awdl0] [--name HOST] [--mac AA:BB:CC:DD:EE:FF] [--duration-secs N] [--stop-file PATH]"
                            .to_string(),
                    );
                }
                other => return Err(format!("unknown flag: {other}")),
            }
        }
        Ok(args)
    }

    fn configure_ipv6_interface(iface_idx: u32, link_local: std::net::Ipv6Addr, mtu: usize) {
        let idx = iface_idx.to_string();
        let addr_str = link_local.to_string();
        let mtu_arg = format!("mtu={mtu}");

        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "set",
                "interface",
                &idx,
                &mtu_arg,
                "routerdiscovery=disabled",
                "dadtransmits=0",
            ])
            .output();

        // Add the deterministic EUI-64 link-local address with `/64` prefix (`set`, then `add`,
        // then without `/64` fallback), and ensure an on-link `fe80::/64` route exists.
        let addr_cidr = format!("address={addr_str}/64");
        let addr_plain = format!("address={addr_str}");
        let mut assigned = false;
        for (verb, addr_arg, extra) in [
            ("set", addr_cidr.as_str(), None),
            ("add", addr_cidr.as_str(), Some("skipassource=false")),
            ("set", addr_plain.as_str(), None),
            ("add", addr_plain.as_str(), Some("skipassource=false")),
        ] {
            let mut cmd = Command::new("netsh");
            cmd.args([
                "interface",
                "ipv6",
                verb,
                "address",
                &format!("interface={idx}"),
                addr_arg,
            ]);
            if let Some(ex) = extra {
                cmd.arg(ex);
            }
            if let Ok(out) = cmd.output()
                && out.status.success()
            {
                assigned = true;
                break;
            }
        }
        if !assigned {
            eprintln!("WARN: netsh failed to assign {addr_str} on interface={idx}");
        }

        let _ = Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "add",
                "route",
                "prefix=fe80::/64",
                &format!("interface={idx}"),
            ])
            .output();

        // Remove any Windows-autogenerated RFC 7217 non-EUI-64 `fe80::` addresses so
        // unbound sockets always source from our EUI-64 address (`owly_awdl::Ipv6Packet::from_ip`).
        let ps_prune = format!(
            "$target = [System.Net.IPAddress]::Parse('{addr_str}'); \
             Get-NetIPAddress -InterfaceIndex {idx} -AddressFamily IPv6 -ErrorAction SilentlyContinue | \
             Where-Object {{ \
                 $raw = ($_.IPAddress -split '%')[0]; \
                 $parsed = $null; \
                 [System.Net.IPAddress]::TryParse($raw, [ref]$parsed) -and \
                 $parsed.IsIPv6LinkLocal -and \
                 -not $parsed.Equals($target) \
             }} | \
             Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue"
        );
        if let Ok(out) = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_prune])
            .output()
            && !out.status.success()
        {
            eprintln!(
                "WARN: PowerShell prune of non-EUI-64 link-local failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }

    fn handle_actions(
        actions: impl Iterator<Item = Action>,
        radio: &mut Mt7612uRadio,
        session: &Arc<wintun::Session>,
        next_timer: &mut Time,
        tx_frames: &mut u64,
        delivered_pkts: &mut u64,
    ) {
        for action in actions {
            match action {
                Action::Transmit { frame, .. } => {
                    *tx_frames += 1;
                    if let Err(e) = radio.send_frame(&frame) {
                        eprintln!("WARN: USB TX error: {e}");
                    }
                }
                Action::Deliver(pkt) => {
                    if let Ok(len) = u16::try_from(pkt.data.len())
                        && let Ok(mut wp) = session.allocate_send_packet(len)
                    {
                        wp.bytes_mut().copy_from_slice(&pkt.data);
                        session.send_packet(wp);
                        *delivered_pkts += 1;
                    }
                }
                Action::PeerUp(peer) => {
                    println!(
                        "PEER_UP mac={} link_local={} name={:?}",
                        peer.mac,
                        peer.mac.link_local(),
                        peer.name
                    );
                }
                Action::PeerDown(mac) => {
                    println!("PEER_DOWN mac={mac}");
                }
                Action::ArmTimer(t) => {
                    *next_timer = t;
                }
            }
        }
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
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
        let link_local = mac.link_local();

        // SAFETY: loads `wintun.dll` from an explicit local or `--wintun-dll` path supplied by the operator.
        #[allow(unsafe_code)]
        let wintun = unsafe { wintun::load_from_path(&args.wintun_dll)? };
        let adapter = match wintun::Adapter::open(&wintun, &args.iface) {
            Ok(existing) => existing,
            Err(_) => wintun::Adapter::create(&wintun, &args.iface, "Owly AWDL", None)?,
        };
        let _ = adapter.set_mtu(AWDL_MTU);
        let iface_idx = adapter.get_adapter_index()?;
        configure_ipv6_interface(iface_idx, link_local, AWDL_MTU);
        let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);

        println!(
            "WINTUN_READY iface={} idx={} mac={} link_local={} channel={} asic=0x{:08x}",
            args.iface,
            iface_idx,
            mac,
            link_local,
            args.channel,
            radio.asic_version()
        );

        let running = Arc::new(AtomicBool::new(true));
        let mut node = Node::new(
            default_awdl_config(mac, &args.name, Channel(args.channel)),
            Time(0),
        );
        let start = Instant::now();
        let mut next_timer = Time(0);
        let mut last_drain = Instant::now();
        let mut last_stats = Instant::now();
        let mut rx_frames = 0u64;
        let mut tx_frames = 0u64;
        let mut out_pkts = 0u64;
        let mut delivered_pkts = 0u64;

        while running.load(Ordering::Relaxed) {
            if let Some(secs) = args.duration_secs
                && start.elapsed() >= Duration::from_secs(secs)
            {
                break;
            }
            if let Some(ref stop_file) = args.stop_file
                && stop_file.exists()
            {
                break;
            }

            let mut did_work = false;
            let now = Time(start.elapsed().as_micros() as u64);

            while let Some((rssi, mpdu)) = radio.try_recv_mpdu() {
                did_work = true;
                rx_frames += 1;
                let now_rx = Time(start.elapsed().as_micros() as u64);
                let actions: Vec<Action> = node
                    .handle(Input::Frame {
                        rx_time: now_rx,
                        rssi,
                        bytes: &mpdu,
                    })
                    .collect();
                handle_actions(
                    actions.into_iter(),
                    &mut radio,
                    &session,
                    &mut next_timer,
                    &mut tx_frames,
                    &mut delivered_pkts,
                );
            }

            while let Ok(Some(pkt)) = session.try_receive() {
                did_work = true;
                let bytes = pkt.bytes();
                if bytes.len() >= 40
                    && (bytes[0] >> 4) == 6
                    && let Some(ip_pkt) = Ipv6Packet::from_ip(bytes.to_vec())
                {
                    out_pkts += 1;
                    let now_tx = Time(start.elapsed().as_micros() as u64);
                    let actions: Vec<Action> = node
                        .handle(Input::Outbound {
                            now: now_tx,
                            packet: ip_pkt,
                        })
                        .collect();
                    handle_actions(
                        actions.into_iter(),
                        &mut radio,
                        &session,
                        &mut next_timer,
                        &mut tx_frames,
                        &mut delivered_pkts,
                    );
                }
            }

            if now >= next_timer {
                did_work = true;
                let actions: Vec<Action> = node.handle(Input::Timer(now)).collect();
                handle_actions(
                    actions.into_iter(),
                    &mut radio,
                    &session,
                    &mut next_timer,
                    &mut tx_frames,
                    &mut delivered_pkts,
                );
            }

            if last_drain.elapsed() >= Duration::from_millis(100) {
                radio.drain_tx_status();
                last_drain = Instant::now();
            }

            if last_stats.elapsed() >= Duration::from_secs(5) {
                println!(
                    "STATS rx_frames={} tx_frames={} out_pkts={} delivered_pkts={} valid_peers={}",
                    rx_frames,
                    tx_frames,
                    out_pkts,
                    delivered_pkts,
                    node.peers().count()
                );
                last_stats = Instant::now();
            }

            if !did_work {
                std::thread::sleep(Duration::from_micros(500));
            }
        }

        let _ = session.shutdown();
        println!(
            "WINTUN_STOP rx_frames={} tx_frames={} out_pkts={} delivered_pkts={}",
            rx_frames, tx_frames, out_pkts, delivered_pkts
        );
        Ok(())
    }
}

fn main() {
    #[cfg(windows)]
    {
        if let Err(e) = win_bridge::run() {
            eprintln!("wintun_awdl error: {e}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("wintun_awdl is only supported on Windows (requires wintun.dll)");
        std::process::exit(2);
    }
}
