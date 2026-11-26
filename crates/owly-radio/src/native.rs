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
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

use crate::nl80211::Nl80211;
use crate::radiotap;
use crate::rtnl::Rtnl;

/// `awdl0`'s MTU.
pub const TAP_MTU: u32 = 1450;
/// What the monitor interface asks for, so A-MSDUs fit.
pub const MONITOR_MTU: u32 = 8192;
/// The most a radiotap header of ours takes.
const RADIOTAP_MAX: usize = 16;
/// `ETH_P_PAE` (IEEE 802.1X / EAPOL control-port protocol, `linux/if_ether.h`).
const ETH_P_PAE: u16 = 0x888e;
/// Most concurrent unauthorized peer STA entries on the hidden AP interface.
const MAX_PEER_STAS: usize = 32;

/// Linux-specific injection and AP peer-station options below `owly-awdl`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Tag monitor injections with `ETH_P_PAE` (`0x888e`) via `sendto` so
    /// mac80211's control-port handler sets `IEEE80211_TX_CTL_USE_MINRATE`
    /// (`MT_TXD2_FIX_RATE` on stock `mt7921e`).
    pub tx_pae_fixrate: bool,
    /// When set, register each valid AWDL peer as an unauthorized station
    /// (`AUTHORIZED = 0`) on this hidden AP interface and remove it on peer
    /// expiry and teardown.
    pub peer_sta_iface: Option<String>,
}

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
        Native::start_with(monitor, tap, cfg, Options::default(), peers)
    }

    /// Starts a node with Linux-specific radio [`Options`].
    pub fn start_with(
        monitor: &str,
        tap: &str,
        cfg: Config,
        opts: Options,
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
        let tx_pae = opts.tx_pae_fixrate.then(|| pae_dest(monitor_index));
        let peer_stas = opts.peer_sta_iface.as_deref().and_then(open_peer_stations);
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
                    tx_pae,
                    buf: vec![0; 16 * 1024],
                };
                let tap = Tap {
                    fd: register(tap_fd)?,
                    name,
                    index,
                    rtnl,
                    peer_stas,
                    buf: vec![0; 16 * 1024],
                };
                Ok((monitor, tap))
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
    /// When set, inject via `sendto` with `sll_protocol = htons(ETH_P_PAE)`.
    tx_pae: Option<nix::libc::sockaddr_ll>,
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
        let sent = match &self.tx_pae {
            Some(dest) => send_raw(self.fd.get_ref(), &buf, dest),
            None => nix::unistd::write(self.fd.get_ref(), &buf)
                .map(|_| ())
                .map_err(io::Error::from),
        };
        match sent {
            Ok(()) => Ok(()),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(nix::libc::EAGAIN | nix::libc::ENOBUFS)
                ) =>
            {
                Err(frame)
            }
            Err(e) => {
                tracing::debug!("couldn't inject a frame: {e}");
                Ok(())
            }
        }
    }
}

/// `awdl0`.
struct Tap {
    fd: AsyncFd<OwnedFd>,
    name: String,
    index: u32,
    rtnl: Rtnl,
    peer_stas: Option<PeerStations>,
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
        if let Some(stas) = &mut self.peer_stas {
            stas.add(mac);
        }
    }

    fn peer_down(&mut self, mac: MacAddr) {
        let _ = self.rtnl.del_neighbour(self.index, mac.link_local());
        if let Some(stas) = &mut self.peer_stas {
            stas.remove(mac);
        }
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

fn pae_dest(ifindex: u32) -> nix::libc::sockaddr_ll {
    let mut addr = zeroed_sockaddr_ll();
    addr.sll_family = nix::libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_PAE.to_be();
    addr.sll_ifindex = ifindex as i32;
    addr
}

fn send_raw(fd: &OwnedFd, buf: &[u8], dest: &nix::libc::sockaddr_ll) -> io::Result<()> {
    #[allow(unsafe_code)]
    // SAFETY: `buf` is valid for `buf.len()` bytes and `dest` is a valid
    // `sockaddr_ll` for the duration of the syscall.
    let r = unsafe {
        nix::libc::sendto(
            fd.as_raw_fd(),
            buf.as_ptr().cast(),
            buf.len(),
            0,
            (dest as *const nix::libc::sockaddr_ll).cast(),
            size_of::<nix::libc::sockaddr_ll>() as nix::libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    if r as usize != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short raw inject ({r}/{})", buf.len()),
        ));
    }
    Ok(())
}

trait StationOps {
    fn add(&mut self, ifindex: u32, mac: MacAddr, aid: u16) -> io::Result<()>;
    fn del(&mut self, ifindex: u32, mac: MacAddr) -> io::Result<()>;
}

impl StationOps for Nl80211 {
    fn add(&mut self, ifindex: u32, mac: MacAddr, aid: u16) -> io::Result<()> {
        self.add_peer_station(ifindex, mac, aid)
    }

    fn del(&mut self, ifindex: u32, mac: MacAddr) -> io::Result<()> {
        self.del_peer_station(ifindex, mac)
    }
}

/// Bounded table of unauthorized peer stations registered on a hidden AP
/// interface, with deterministic cleanup on drop.
struct PeerStations<S: StationOps = Nl80211> {
    ops: S,
    ifindex: u32,
    slots: [Option<MacAddr>; MAX_PEER_STAS],
}

fn open_peer_stations(iface: &str) -> Option<PeerStations> {
    let ifindex = match if_index(iface) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!("peer STA registration disabled on {iface}: {e}");
            return None;
        }
    };
    match Nl80211::open() {
        Ok(nl) => Some(PeerStations::new(nl, ifindex)),
        Err(e) => {
            tracing::warn!("peer STA registration disabled on {iface}: {e}");
            None
        }
    }
}

impl<S: StationOps> PeerStations<S> {
    fn new(ops: S, ifindex: u32) -> Self {
        PeerStations {
            ops,
            ifindex,
            slots: [None; MAX_PEER_STAS],
        }
    }

    fn add(&mut self, mac: MacAddr) {
        let mut free = None;
        for (i, slot) in self.slots.iter().enumerate() {
            match slot {
                Some(existing) if *existing == mac => return,
                None if free.is_none() => free = Some(i),
                _ => {}
            }
        }
        let Some(slot) = free else {
            tracing::warn!("peer STA table full ({MAX_PEER_STAS}); skipping {mac}");
            return;
        };
        let aid = (slot + 1) as u16;
        match self.ops.add(self.ifindex, mac, aid) {
            Ok(()) => self.slots[slot] = Some(mac),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                self.slots[slot] = Some(mac);
            }
            Err(e) => tracing::warn!("couldn't add peer station {mac}: {e}"),
        }
    }

    fn remove(&mut self, mac: MacAddr) {
        for slot in &mut self.slots {
            if *slot == Some(mac) {
                *slot = None;
                break;
            }
        }
        if let Err(e) = self.ops.del(self.ifindex, mac)
            && e.kind() != io::ErrorKind::NotFound
            && e.raw_os_error() != Some(nix::libc::ENODEV)
        {
            tracing::warn!("couldn't remove peer station {mac}: {e}");
        }
    }
}

impl<S: StationOps> Drop for PeerStations<S> {
    fn drop(&mut self) {
        for i in 0..MAX_PEER_STAS {
            if let Some(mac) = self.slots[i].take() {
                let _ = self.ops.del(self.ifindex, mac);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct FakeStations {
        calls: Rc<RefCell<Vec<String>>>,
        next_add: Option<io::ErrorKind>,
        del_error: Option<i32>,
    }

    impl StationOps for FakeStations {
        fn add(&mut self, ifindex: u32, mac: MacAddr, aid: u16) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(format!("add {ifindex} {mac} aid={aid}"));
            if let Some(kind) = self.next_add.take() {
                return Err(io::Error::new(kind, "injected"));
            }
            Ok(())
        }

        fn del(&mut self, ifindex: u32, mac: MacAddr) -> io::Result<()> {
            self.calls.borrow_mut().push(format!("del {ifindex} {mac}"));
            if let Some(errno) = self.del_error {
                return Err(io::Error::from_raw_os_error(errno));
            }
            Ok(())
        }
    }

    fn peer(n: u8) -> MacAddr {
        MacAddr([0x02, 0, 0, 0, 0, n])
    }

    #[test]
    fn pae_dest_sets_eth_p_pae_and_ifindex() {
        let dest = pae_dest(17);
        assert_eq!(dest.sll_family, nix::libc::AF_PACKET as u16);
        assert_eq!(dest.sll_protocol, ETH_P_PAE.to_be());
        assert_eq!(dest.sll_ifindex, 17);
    }

    #[test]
    fn peer_stations_assigns_reuses_bounds_and_cleans_up_on_drop() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        {
            let mut stas = PeerStations::new(
                FakeStations {
                    calls: calls.clone(),
                    next_add: None,
                    del_error: Some(nix::libc::ENODEV),
                },
                5,
            );
            // Idempotent add.
            stas.add(peer(1));
            stas.add(peer(1));
            assert_eq!(calls.borrow().len(), 1);
            assert_eq!(calls.borrow()[0], "add 5 02:00:00:00:00:01 aid=1");

            // AlreadyExists still tracks the peer so it gets cleaned up on drop.
            stas.ops.next_add = Some(io::ErrorKind::AlreadyExists);
            stas.add(peer(2));
            assert_eq!(stas.slots[1], Some(peer(2)));

            // Other errors do not consume a slot.
            stas.ops.next_add = Some(io::ErrorKind::PermissionDenied);
            stas.add(peer(3));
            assert_eq!(stas.slots[2], None);

            // Remove frees AID 1 for reuse.
            stas.remove(peer(1));
            assert_eq!(stas.slots[0], None);
            stas.add(peer(4));
            assert_eq!(
                calls.borrow().last().unwrap(),
                "add 5 02:00:00:00:00:04 aid=1"
            );

            // Fill remaining slots up to MAX_PEER_STAS; an extra peer is skipped.
            for n in 10..(10 + MAX_PEER_STAS as u8) {
                stas.add(peer(n));
            }
            let before = calls.borrow().len();
            stas.add(peer(200));
            assert_eq!(calls.borrow().len(), before, "table full skips 33rd peer");
        }
        // Drop must emit a del for all MAX_PEER_STAS occupied slots.
        let dels = calls
            .borrow()
            .iter()
            .filter(|c| c.starts_with("del 5 "))
            .count();
        assert_eq!(dels, 1 + MAX_PEER_STAS);
    }
}
