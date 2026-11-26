//! The native AWDL driver on a real kernel, without root or a radio: the
//! test re-runs itself in a user and network namespace, where a veth pair
//! stands in for the air. The driver runs on one end with its TAP `awdl0`;
//! on the other, a simulated iPhone, an owly-awdl `Node` of its own, speaks
//! radiotap frames to it. Then the kernel's IPv6 stack has to reach the
//! phone through `awdl0`, and answer it.

use std::net::{SocketAddrV6, UdpSocket};
use std::os::fd::OwnedFd;
use std::process::Command;
use std::time::{Duration, Instant};

use owly_awdl::{
    Action, Channel, Config, Input, Ipv6Packet, MacAddr, Node, Presence, RadioConstraints, Time,
};
use owly_radio::native::Native;
use owly_radio::radiotap;
use owly_radio::sys::{Ops, System};
use tokio::sync::watch;

const INNER: &str = "OWLY_NATIVE_INNER";
const MONITOR: &str = "owlymon0";
const AIR: &str = "owlyair0";
const TAP: &str = "awdl0";
const US: MacAddr = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
const PHONE: MacAddr = MacAddr([0x86, 0x08, 0x04, 0x8a, 0x2b, 0xf4]);

fn ip(args: &[&str]) {
    let ok = Command::new("ip").args(args).status().unwrap().success();
    assert!(ok, "ip {args:?}");
}

fn radio() -> RadioConstraints {
    RadioConstraints {
        channel: Channel(6),
        presence: Presence::Fixed,
    }
}

/// The phone's side of the air.
struct Phone {
    node: Node,
    air: OwnedFd,
    epoch: Instant,
    timer: Time,
    up: bool,
    got: Vec<Ipv6Packet>,
}

impl Phone {
    fn now(&self) -> Time {
        Time(self.epoch.elapsed().as_micros() as u64 + 1)
    }

    fn apply(&mut self, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Transmit { frame, .. } => {
                    let mut buf = radiotap::tx_header(frame.rate, frame.no_ack);
                    buf.extend_from_slice(&frame.bytes);
                    let _ = nix::unistd::write(&self.air, &buf);
                }
                Action::ArmTimer(t) => self.timer = t,
                Action::PeerUp(p) if p.mac == US => self.up = true,
                Action::Deliver(p) => self.got.push(p),
                _ => {}
            }
        }
    }

    /// Runs for up to `limit`, or until `done`.
    fn run(&mut self, limit: Duration, mut done: impl FnMut(&Phone) -> bool) -> bool {
        let end = Instant::now() + limit;
        let mut buf = vec![0u8; 16 * 1024];
        while Instant::now() < end {
            if done(self) {
                return true;
            }
            while let Ok(n) = nix::unistd::read(&self.air, &mut buf) {
                let Some(rx) = radiotap::parse(&buf[..n]) else {
                    continue;
                };
                let bytes = rx.frame.to_vec();
                let now = self.now();
                let a = self
                    .node
                    .handle(Input::Frame {
                        rx_time: now,
                        rssi: Some(-40),
                        bytes: &bytes,
                    })
                    .collect();
                self.apply(a);
            }
            let now = self.now();
            if now >= self.timer {
                let a = self.node.handle(Input::Timer(now)).collect();
                self.apply(a);
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        done(self)
    }

    fn send(&mut self, packet: Ipv6Packet) {
        let now = self.now();
        let a = self.node.handle(Input::Outbound { now, packet }).collect();
        self.apply(a);
    }
}

// spec: AWDL-2, NET-1, NET-2
#[test]
fn the_kernel_reaches_a_phone_through_the_native_driver() {
    if std::env::var_os(INNER).is_none() {
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "--mount", "--"])
            .args([
                "sh",
                "-ec",
                "mount -t sysfs sysfs /sys && exec \"$0\" \"$@\"",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "the_kernel_reaches_a_phone_through_the_native_driver",
                "--exact",
                "--nocapture",
            ])
            .env(INNER, "1")
            .status()
            .expect("running unshare (util-linux)");
        assert!(
            status.success(),
            "failed in its namespace; if unshare itself failed, unprivileged user namespaces may be disabled"
        );
        return;
    }

    ip(&["link", "add", MONITOR, "type", "veth", "peer", "name", AIR]);
    ip(&["link", "set", MONITOR, "up"]);
    ip(&["link", "set", AIR, "up"]);
    let ops = System;

    let (peers_tx, mut peers) = watch::channel(Vec::new());
    let mut cfg = Config::new(US, "owly-test", radio());
    cfg.rssi_threshold = None;
    let native = Native::start(MONITOR, TAP, cfg, peers_tx).expect("the driver starts");

    // AWDL-2, NET-1: awdl0 on our address, with its usable link-local one.
    assert_eq!(ops.mac(TAP).map(|m| m.0), Some(US.0));
    assert_eq!(
        owly_radio::sys::link_local(TAP),
        Some((US.link_local(), false))
    );
    let mtu = std::fs::read_to_string(format!("/sys/class/net/{TAP}/mtu")).unwrap();
    assert_eq!(mtu.trim(), "1450");
    let mtu = std::fs::read_to_string(format!("/sys/class/net/{MONITOR}/mtu")).unwrap();
    assert_eq!(mtu.trim(), "8192");

    let air_index = nix::net::if_::if_nametoindex(AIR).unwrap();
    let mut phone = Phone {
        node: Node::new(Config::new(PHONE, "iPhone", radio()), Time(1)),
        air: owly_radio::native::packet_socket(air_index, false).unwrap(),
        epoch: Instant::now(),
        timer: Time(1),
        up: false,
        got: Vec::new(),
    };
    assert!(
        phone.run(Duration::from_secs(5), |p| p.up
            && peers.borrow().len() == 1),
        "the two never met: phone sees us {}, we see {:?}",
        phone.up,
        *peers.borrow_and_update()
    );
    assert_eq!(peers.borrow()[0].mac.0, PHONE.0);
    assert_eq!(peers.borrow()[0].rssi, None, "a veth reports no signal");

    // NET-2: the phone's neighbour entry.
    let out = Command::new("ip")
        .args(["-6", "neigh", "show", "dev", TAP])
        .output()
        .unwrap();
    let neigh = String::from_utf8_lossy(&out.stdout);
    assert!(
        neigh.contains("lladdr 86:08:04:8a:2b:f4 PERMANENT"),
        "{neigh}"
    );

    // The kernel sends to the phone.
    let index = ops.index(TAP).unwrap();
    let sock = UdpSocket::bind(SocketAddrV6::new(US.link_local(), 0, 0, index)).unwrap();
    sock.send_to(
        b"hello phone",
        SocketAddrV6::new(PHONE.link_local(), 8770, 0, index),
    )
    .unwrap();
    assert!(
        phone.run(Duration::from_secs(3), |p| p
            .got
            .iter()
            .any(|g| g.data.ends_with(b"hello phone"))),
        "the phone got nothing"
    );

    // The phone pings the kernel, which answers.
    phone.send(Ipv6Packet::echo_request(PHONE, US, 0x1234, 1, b"ping"));
    assert!(
        phone.run(Duration::from_secs(3), |p| p
            .got
            .iter()
            .any(|g| g.is_echo_reply(0x1234))),
        "no echo reply from the kernel"
    );

    assert_eq!(*native.failed().borrow(), None);

    native.stop();
    assert!(!ops.exists(TAP), "awdl0 goes with the driver");
}

#[test]
fn pae_fixrate_tags_outgoing_packet_protocol_without_changing_frame_bytes() {
    const INNER_PAE: &str = "OWLY_NATIVE_PAE_INNER";
    if std::env::var_os(INNER_PAE).is_none() {
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "--mount", "--"])
            .args([
                "sh",
                "-ec",
                "mount -t sysfs sysfs /sys && exec \"$0\" \"$@\"",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "pae_fixrate_tags_outgoing_packet_protocol_without_changing_frame_bytes",
                "--exact",
                "--nocapture",
            ])
            .env(INNER_PAE, "1")
            .status()
            .expect("running unshare (util-linux)");
        assert!(status.success(), "failed in its namespace");
        return;
    }

    ip(&["link", "add", MONITOR, "type", "veth", "peer", "name", AIR]);
    ip(&["link", "set", MONITOR, "up"]);
    ip(&["link", "set", AIR, "up"]);

    // Capture outgoing frames on MONITOR itself (before veth peer RX rewrites
    // skb->protocol from Ethernet offsets) to verify sll_protocol == ETH_P_PAE.
    let mon_index = nix::net::if_::if_nametoindex(MONITOR).unwrap();
    let tap_sock = owly_radio::native::packet_socket(mon_index, true).unwrap();

    let (peers_tx, _peers) = watch::channel(Vec::new());
    let mut cfg = Config::new(US, "owly-pae-test", radio());
    cfg.rssi_threshold = None;
    let opts = owly_radio::native::Options {
        tx_pae_fixrate: true,
        peer_sta_iface: None,
    };
    let native =
        Native::start_with(MONITOR, TAP, cfg, opts, peers_tx).expect("the driver starts with PAE");

    let mut buf = vec![0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_pae_action = false;
    while Instant::now() < deadline {
        use std::os::fd::AsRawFd;
        let mut from: nix::libc::sockaddr_ll = nix::libc::sockaddr_ll {
            sll_family: 0,
            sll_protocol: 0,
            sll_ifindex: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let mut from_len = std::mem::size_of::<nix::libc::sockaddr_ll>() as nix::libc::socklen_t;
        #[allow(unsafe_code)]
        // SAFETY: `buf`, `from`, and `from_len` are valid for the syscall.
        let n = unsafe {
            nix::libc::recvfrom(
                tap_sock.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&mut from as *mut nix::libc::sockaddr_ll).cast(),
                &mut from_len,
            )
        };
        if n > 0 {
            let n = n as usize;
            if from.sll_pkttype == nix::libc::PACKET_OUTGOING
                && from.sll_protocol == 0x888eu16.to_be()
                && radiotap::parse(&buf[..n]).is_some()
            {
                saw_pae_action = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    native.stop();
    assert!(
        saw_pae_action,
        "expected an outgoing radiotap frame tagged with ETH_P_PAE (0x888e)"
    );
}
