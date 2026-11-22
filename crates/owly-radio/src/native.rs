//! owly-awdl on Linux: its [`driver`] on a
//! monitor interface the injection backend set up.
//!
//! Its [`Air`] is a packet socket on the monitor, which captures and
//! injects radiotap frames. Its [`Netif`] is `awdl0`, which it makes itself:
//! a TAP device carrying Ethernet frames, created down, given the AWDL
//! address as its MAC (AWDL-2) and its EUI-64 link-local address without
//! DAD (NET-1), MTU 1450 with offloads off, then brought up. Each peer that
//! turns valid gets a permanent neighbour entry (NET-2). The monitor asks
//! for MTU 8192 so A-MSDUs fit.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::radio::{MacAddr, PeerInfo};
use owly_awdl::driver::{self, Air, Netif, Received, Running};
use owly_awdl::frame::Frame;
use owly_awdl::{Config, Ipv6Packet};
use tokio::io::AsyncReadExt;
use tokio::io::unix::AsyncFd;
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::radiotap;
use crate::rtnl::Rtnl;

/// `awdl0`'s MTU.
pub const TAP_MTU: u32 = 1450;
/// What the monitor interface asks for, so A-MSDUs fit.
pub const MONITOR_MTU: u32 = 8192;
/// The most a radiotap header of ours takes.
const RADIOTAP_MAX: usize = 16;

/// A running node.
pub struct Native {
    running: Running,
    /// `awdl0`'s index.
    pub index: u32,
}

impl Native {
    /// Makes `tap` and starts a node with `cfg` on `monitor`, publishing
    /// its valid peers on `peers`.
    pub fn start(
        monitor: &str,
        tap: &str,
        cfg: Config,
        peers: watch::Sender<Vec<PeerInfo>>,
    ) -> io::Result<Native> {
        let monitor_index = if_index(monitor)?;
        let mut rtnl = Rtnl::open()?;
        if let Err(e) = rtnl.set_mtu(monitor_index, MONITOR_MTU) {
            tracing::info!("{monitor} keeps its MTU, not {MONITOR_MTU}: {e}");
        }
        let monitor_mtu = std::fs::read_to_string(format!("/sys/class/net/{monitor}/mtu"))
            .ok()
            .and_then(|m| m.trim().parse::<usize>().ok())
            .unwrap_or(2304);
        let mut cfg = cfg;
        cfg.max_frame = monitor_mtu.saturating_sub(RADIOTAP_MAX).max(1500);

        let air = packet_socket(monitor_index, false)?;
        let tap_fd = open_tap(tap)?;
        let index = if_index(tap)?;
        // No address of the kernel's own beside ours.
        let _ = std::fs::write(format!("/proc/sys/net/ipv6/conf/{tap}/addr_gen_mode"), "1");
        let _ = std::fs::write(format!("/proc/sys/net/ipv6/conf/{tap}/accept_dad"), "0");
        let mac = cfg.addr;
        rtnl.set_mac(index, mac)?;
        rtnl.set_mtu(index, TAP_MTU)?;
        rtnl.add_link_local_nodad(index, mac.link_local())?;
        rtnl.set_up(index, true)?;

        let name = tap.to_string();
        let running = driver::spawn(
            cfg,
            move || {
                let monitor = Monitor {
                    fd: register(air)?,
                    buf: vec![0; 16 * 1024],
                };
                let tap = Tap {
                    fd: register(tap_fd)?,
                    name,
                    index,
                    rtnl,
                    buf: vec![0; 16 * 1024],
                };
                Ok((monitor, tap))
            },
            peers,
        )?;
        Ok(Native { running, index })
    }

    /// Connects to a user-space radio daemon (such as `mtkradio`) over a UNIX
    /// stream socket using the `radio_link` framing protocol, creates `tap`,
    /// and starts `owly-awdl` on it.
    pub fn start_socket(
        sock_path: &str,
        tap: &str,
        cfg: Config,
        peers: watch::Sender<Vec<PeerInfo>>,
    ) -> io::Result<Native> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream as StdUnixStream;

        let mut std_stream = StdUnixStream::connect(sock_path)?;
        // Read RADIO_LINK_HELLO (8-byte hdr + 8-byte hello).
        let mut hello = [0u8; 16];
        std_stream.read_exact(&mut hello)?;

        // Send RADIO_LINK_SET_ADDRESS (type=6, len=6) and BSSID filter (type=5, len=6).
        let mut set_addr = [0u8; 14];
        set_addr[0..2].copy_from_slice(&6u16.to_le_bytes());
        set_addr[4..8].copy_from_slice(&6u32.to_le_bytes());
        set_addr[8..14].copy_from_slice(&cfg.addr.0);
        std_stream.write_all(&set_addr)?;

        let mut set_bssid = [0u8; 14];
        set_bssid[0..2].copy_from_slice(&5u16.to_le_bytes());
        set_bssid[4..8].copy_from_slice(&6u32.to_le_bytes());
        set_bssid[8..14].copy_from_slice(&[0x00, 0x25, 0x00, 0xff, 0x94, 0x73]);
        std_stream.write_all(&set_bssid)?;

        std_stream.set_nonblocking(true)?;
        tune_unix_socket_buffers(std_stream.as_raw_fd());

        let mut rtnl = Rtnl::open()?;
        let tap_fd = open_tap(tap)?;
        let index = if_index(tap)?;
        let _ = std::fs::write(format!("/proc/sys/net/ipv6/conf/{tap}/addr_gen_mode"), "1");
        let _ = std::fs::write(format!("/proc/sys/net/ipv6/conf/{tap}/accept_dad"), "0");
        let mac = cfg.addr;
        rtnl.set_mac(index, mac)?;
        rtnl.set_mtu(index, TAP_MTU)?;
        rtnl.add_link_local_nodad(index, mac.link_local())?;
        rtnl.set_up(index, true)?;

        let name = tap.to_string();
        let running = driver::spawn(
            cfg,
            move || {
                let air = SocketAir::new(UnixStream::from_std(std_stream)?);
                let tap = Tap {
                    fd: register(tap_fd)?,
                    name,
                    index,
                    rtnl,
                    buf: vec![0; 16 * 1024],
                };
                Ok((air, tap))
            },
            peers,
        )?;
        Ok(Native { running, index })
    }

    /// Why the node stopped by itself, once it has.
    pub fn failed(&self) -> watch::Receiver<Option<String>> {
        self.running.failed()
    }

    /// Stops the node. `awdl0` goes with its file descriptor, and its
    /// neighbour entries with it.
    pub fn stop(self) {
        self.running.stop();
    }
}

/// The monitor interface's packet socket.
struct Monitor {
    fd: AsyncFd<OwnedFd>,
    buf: Vec<u8>,
}

impl Air for Monitor {
    async fn recv(&mut self) -> io::Result<Received> {
        loop {
            let mut guard = self.fd.readable().await?;
            let read = guard.try_io(|fd| Ok(nix::unistd::read(fd.get_ref(), &mut self.buf)?));
            match read {
                Ok(Ok(n)) => {
                    if let Some(rx) = radiotap::parse(&self.buf[..n]) {
                        return Ok(Received {
                            bytes: rx.frame.to_vec(),
                            rssi: rx.rssi,
                        });
                    }
                }
                Ok(Err(e)) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("the monitor interface failed: {e}"),
                    ));
                }
                Err(_would_block) => {}
            }
        }
    }

    fn send(&mut self, frame: Frame) -> Result<(), Frame> {
        let mut buf = radiotap::tx_header(frame.rate, frame.no_ack);
        buf.extend_from_slice(&frame.bytes);
        match nix::unistd::write(self.fd.get_ref(), &buf) {
            Ok(_) => Ok(()),
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::ENOBUFS) => Err(frame),
            Err(e) => {
                tracing::debug!("couldn't inject a frame: {e}");
                Ok(())
            }
        }
    }
}

/// Size of `SocketAir`'s internal read buffer so one `read()` pulls many frames.
const SOCKET_RX_BUF: usize = 64 * 1024;
/// Maximum `radio_link` payload accepted from `mtkradio`.
const SOCKET_MAX_BODY: usize = 16 * 1024;
/// Socket send/receive buffer size (4 MiB) for high-throughput bursts.
const SOCKET_BUF_BYTES: i32 = 4 << 20;

/// Cancel-safe UNIX socket `Air` implementation for user-space radio daemons (`mtkradio`).
struct SocketAir {
    stream: UnixStream,
    rx_buf: Vec<u8>,
    rx_start: usize,
    rx_end: usize,
    tx_buf: Vec<u8>,
}

impl SocketAir {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            rx_buf: vec![0u8; SOCKET_RX_BUF],
            rx_start: 0,
            rx_end: 0,
            tx_buf: Vec::with_capacity(4128),
        }
    }
}

/// Appends the radiotap TX header for `rate`/`no_ack` into `out` without allocating.
/// Matches [`radiotap::tx_header`] byte-for-byte.
fn write_tx_radiotap(out: &mut Vec<u8>, rate: owly_awdl::TxRate, no_ack: bool) {
    match rate {
        owly_awdl::TxRate::Legacy(r) => {
            if no_ack {
                out.extend_from_slice(&[0, 0, 12, 0, 0x04, 0x80, 0, 0, r, 0, 0x08, 0]);
            } else {
                out.extend_from_slice(&[0, 0, 9, 0, 0x04, 0, 0, 0, r]);
            }
        }
        owly_awdl::TxRate::Ht { mcs, sgi } => {
            let flags = if sgi { 0x04 } else { 0 };
            if no_ack {
                out.extend_from_slice(&[0, 0, 13, 0, 0, 0x80, 0x08, 0, 0x08, 0, 0x07, flags, mcs]);
            } else {
                out.extend_from_slice(&[0, 0, 11, 0, 0, 0, 0x08, 0, 0x07, flags, mcs]);
            }
        }
    }
}

fn tune_unix_socket_buffers(fd: std::os::fd::RawFd) {
    use nix::libc;
    let size = SOCKET_BUF_BYTES;
    for opt in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        #[allow(unsafe_code)]
        // SAFETY: `size` is a valid i32 living through the setsockopt call.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&size as *const i32).cast(),
                size_of::<i32>() as u32,
            );
        }
    }
}

impl Air for SocketAir {
    async fn recv(&mut self) -> io::Result<Received> {
        loop {
            let avail = self.rx_end - self.rx_start;
            if avail >= 8 {
                let hdr = &self.rx_buf[self.rx_start..self.rx_start + 8];
                let msg_type = u16::from_le_bytes([hdr[0], hdr[1]]);
                let body_len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
                if body_len > SOCKET_MAX_BODY {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "oversized radio_link frame",
                    ));
                }
                let frame_len = 8 + body_len;
                if avail >= frame_len {
                    let body_start = self.rx_start + 8;
                    let body_end = self.rx_start + frame_len;
                    self.rx_start = body_end;
                    if self.rx_start == self.rx_end {
                        self.rx_start = 0;
                        self.rx_end = 0;
                    }
                    if msg_type == 2 {
                        if let Some(rx) = radiotap::parse(&self.rx_buf[body_start..body_end]) {
                            return Ok(Received {
                                bytes: rx.frame.to_vec(),
                                rssi: rx.rssi,
                            });
                        }
                    }
                    continue;
                }
            }

            if self.rx_start > 0 && self.rx_buf.len() - self.rx_end < SOCKET_MAX_BODY + 8 {
                self.rx_buf.copy_within(self.rx_start..self.rx_end, 0);
                self.rx_end -= self.rx_start;
                self.rx_start = 0;
            }

            let n = self.stream.read(&mut self.rx_buf[self.rx_end..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mtkradio socket closed",
                ));
            }
            self.rx_end += n;
        }
    }

    fn send(&mut self, frame: Frame) -> Result<(), Frame> {
        use nix::errno::Errno;
        use nix::sys::socket::{MsgFlags, send};

        self.tx_buf.clear();
        self.tx_buf.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0]); // RADIO_LINK_TX
        write_tx_radiotap(&mut self.tx_buf, frame.rate, frame.no_ack);
        self.tx_buf.extend_from_slice(&frame.bytes);
        let payload_len = (self.tx_buf.len() - 8) as u32;
        self.tx_buf[4..8].copy_from_slice(&payload_len.to_le_bytes());

        let fd = self.stream.as_raw_fd();
        let flags = MsgFlags::MSG_NOSIGNAL | MsgFlags::MSG_DONTWAIT;
        let mut written = 0;
        while written < self.tx_buf.len() {
            match send(fd, &self.tx_buf[written..], flags) {
                Ok(0) => return Ok(()),
                Ok(n) => written += n,
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN | Errno::ENOBUFS) => {
                    if written == 0 {
                        return Err(frame);
                    }
                    std::thread::yield_now();
                }
                Err(_) => return Ok(()),
            }
        }
        Ok(())
    }
}

/// `awdl0`.
struct Tap {
    fd: AsyncFd<OwnedFd>,
    name: String,
    index: u32,
    rtnl: Rtnl,
    buf: Vec<u8>,
}

impl Netif for Tap {
    async fn recv(&mut self) -> io::Result<Ipv6Packet> {
        loop {
            let mut guard = self.fd.readable().await?;
            let read = guard.try_io(|fd| Ok(nix::unistd::read(fd.get_ref(), &mut self.buf)?));
            match read {
                Ok(Ok(n)) => {
                    if let Some(packet) = Ipv6Packet::from_ethernet(&self.buf[..n]) {
                        return Ok(packet);
                    }
                }
                Ok(Err(e)) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("{} failed: {e}", self.name),
                    ));
                }
                Err(_would_block) => {}
            }
        }
    }

    fn deliver(&mut self, packet: Ipv6Packet) {
        let frame = packet.to_ethernet();
        if let Err(e) = nix::unistd::write(self.fd.get_ref(), &frame)
            && e != nix::errno::Errno::EAGAIN
        {
            tracing::debug!("{} refused a packet: {e}", self.name);
        }
    }

    fn peer_up(&mut self, mac: MacAddr) {
        if let Err(e) = self.rtnl.add_neighbour(self.index, mac.link_local(), mac) {
            tracing::warn!("no neighbour entry for {mac}: {e}");
        }
    }

    fn peer_down(&mut self, mac: MacAddr) {
        let _ = self.rtnl.del_neighbour(self.index, mac.link_local());
    }
}

/// Registers a descriptor with the current runtime.
fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    #[allow(unsafe_code)]
    // SAFETY: an OwnedFd is open and stays the same descriptor until the
    // AsyncFd, which owns it, is dropped.
    unsafe { AsyncFd::register(fd) }.map_err(|e| io::Error::other(e.to_string()))
}

fn if_index(name: &str) -> io::Result<u32> {
    nix::net::if_::if_nametoindex(name).map_err(|e| io::Error::other(format!("{name}: {e}")))
}

/// A raw packet socket on interface `index`, non-blocking: what a monitor
/// interface captures, radiotap first, and injects. Frames sent through
/// the interface, by anyone, are read back only when `outgoing`.
pub fn packet_socket(index: u32, outgoing: bool) -> io::Result<OwnedFd> {
    use nix::libc;
    let proto = (libc::ETH_P_ALL as u16).to_be();
    #[allow(unsafe_code)]
    // SAFETY: socket(2) takes no pointers; the descriptor it returns is
    // checked and then owned.
    let fd = unsafe {
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            proto as i32,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };
    let mut addr: libc::sockaddr_ll = zeroed_sockaddr_ll();
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = proto;
    addr.sll_ifindex = index as i32;
    #[allow(unsafe_code)]
    // SAFETY: `addr` is a valid sockaddr_ll for the length given, and lives
    // through the call.
    let r = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_ll).cast(),
            size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // Our own frames aren't wanted back (Linux 4.20 and later), and a
    // burst of an iPhone's shouldn't overflow the buffer.
    let ignore: i32 = (!outgoing).into();
    let size: i32 = 4 << 20;
    for (level, name, value) in [
        (libc::SOL_PACKET, libc::PACKET_IGNORE_OUTGOING, &ignore),
        (libc::SOL_SOCKET, libc::SO_RCVBUF, &size),
        (libc::SOL_SOCKET, libc::SO_SNDBUF, &size),
    ] {
        #[allow(unsafe_code)]
        // SAFETY: `value` points to an i32 that lives through the call.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                name,
                (value as *const i32).cast(),
                size_of::<i32>() as u32,
            );
        }
    }
    Ok(fd)
}

fn zeroed_sockaddr_ll() -> nix::libc::sockaddr_ll {
    nix::libc::sockaddr_ll {
        sll_family: 0,
        sll_protocol: 0,
        sll_ifindex: 0,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    }
}

/// A TAP device named `name`, carrying Ethernet frames with no packet
/// information header and no offloads, left down. It lasts as long as the
/// descriptor.
fn open_tap(name: &str) -> io::Result<OwnedFd> {
    use nix::fcntl::{OFlag, open};
    use nix::libc;
    use nix::sys::stat::Mode;
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54d0;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;

    let fd = open(
        "/dev/net/tun",
        OFlag::O_RDWR | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    let cname = CString::new(name).map_err(|_| io::Error::other("a NUL in the name"))?;
    let bytes = cname.as_bytes_with_nul();
    if bytes.len() > libc::IFNAMSIZ {
        return Err(io::Error::other(format!(
            "{name}: too long for an interface"
        )));
    }
    // struct ifreq: the name, then the flags.
    let mut ifreq = [0u8; 40];
    ifreq[..bytes.len()].copy_from_slice(bytes);
    ifreq[16..18].copy_from_slice(&(IFF_TAP | IFF_NO_PI).to_ne_bytes());
    #[allow(unsafe_code)]
    // SAFETY: TUNSETIFF reads and writes a struct ifreq, which `ifreq` is
    // big enough for and outlives the call.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, ifreq.as_mut_ptr()) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(unsafe_code)]
    // SAFETY: TUNSETOFFLOAD takes its argument by value.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETOFFLOAD as _, 0 as libc::c_ulong) };
    if r < 0 {
        tracing::info!("{name} keeps its offloads: {}", io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use owly_awdl::TxRate;
    use tokio::io::AsyncWriteExt;

    fn radio_link_rx(freq: u16, rssi: i8, payload: &[u8]) -> Vec<u8> {
        let mut body = radiotap::rx_header(Some(freq), Some(rssi));
        body.extend_from_slice(payload);
        let mut wire = Vec::with_capacity(8 + body.len());
        wire.extend_from_slice(&2u16.to_le_bytes()); // RADIO_LINK_RX
        wire.extend_from_slice(&0u16.to_le_bytes());
        wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    #[test]
    fn write_tx_radiotap_matches_radiotap_tx_header() {
        for rate in [
            TxRate::Legacy(12),
            TxRate::Legacy(24),
            TxRate::Legacy(108),
            TxRate::Ht { mcs: 0, sgi: false },
            TxRate::Ht { mcs: 7, sgi: true },
            TxRate::Ht { mcs: 15, sgi: true },
        ] {
            for no_ack in [false, true] {
                let mut buf = Vec::new();
                write_tx_radiotap(&mut buf, rate, no_ack);
                assert_eq!(buf, radiotap::tx_header(rate, no_ack));
            }
        }
    }

    #[tokio::test]
    async fn socket_air_recv_batches_and_is_cancel_safe() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let mut air = SocketAir::new(a);

        // Write a non-RX control frame + two RX frames in one burst.
        let mut burst = Vec::new();
        // RADIO_LINK_HELLO (type=1, len=8) should be skipped cleanly.
        burst.extend_from_slice(&1u16.to_le_bytes());
        burst.extend_from_slice(&0u16.to_le_bytes());
        burst.extend_from_slice(&8u32.to_le_bytes());
        burst.extend_from_slice(&[0u8; 8]);
        let f1 = radio_link_rx(5745, -42, b"first-frame-body");
        let f2 = radio_link_rx(5745, -43, b"second-frame-body");
        let f3 = radio_link_rx(5745, -44, b"third-split-frame");
        burst.extend_from_slice(&f1);
        burst.extend_from_slice(&f2);
        // Append only the first 5 bytes of f3 so recv() must wait and can be cancelled.
        burst.extend_from_slice(&f3[..5]);
        b.write_all(&burst).await.unwrap();

        let r1 = air.recv().await.unwrap();
        assert_eq!(r1.bytes, b"first-frame-body");
        assert_eq!(r1.rssi, Some(-42));

        let r2 = air.recv().await.unwrap();
        assert_eq!(r2.bytes, b"second-frame-body");
        assert_eq!(r2.rssi, Some(-43));

        // Start recv() on the incomplete f3 and cancel it mid-await.
        let timed = tokio::time::timeout(std::time::Duration::from_millis(20), air.recv()).await;
        assert!(timed.is_err(), "incomplete frame should remain pending");

        // Now send the rest of f3; cancel-safety guarantees zero lost bytes.
        b.write_all(&f3[5..]).await.unwrap();
        let r3 = air.recv().await.unwrap();
        assert_eq!(r3.bytes, b"third-split-frame");
        assert_eq!(r3.rssi, Some(-44));
    }

    #[tokio::test]
    async fn socket_air_send_frames_correctly() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let mut air = SocketAir::new(a);

        let frame = Frame {
            bytes: b"hello-80211".to_vec(),
            to: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            rate: TxRate::Ht { mcs: 7, sgi: true },
            no_ack: true,
        };
        assert!(air.send(frame.clone()).is_ok());

        let mut hdr = [0u8; 8];
        b.read_exact(&mut hdr).await.unwrap();
        assert_eq!(u16::from_le_bytes([hdr[0], hdr[1]]), 3); // RADIO_LINK_TX
        let len = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        let mut payload = vec![0u8; len];
        b.read_exact(&mut payload).await.unwrap();

        let mut expected = radiotap::tx_header(frame.rate, frame.no_ack);
        expected.extend_from_slice(&frame.bytes);
        assert_eq!(payload, expected);
    }
}
