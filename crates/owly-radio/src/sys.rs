//! The system operations a radio backend makes, behind [`Ops`] so that the
//! sequences built on them can be tested without root or a card.
//!
//! [`System`] makes them through nl80211 and rtnetlink, sysfs and procfs,
//! and NetworkManager's `nmcli`.

use std::fs;
use std::io;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::radio::MacAddr;

use crate::nl80211::{Kind, Nl80211, Wiphy};
use crate::rtnl::Rtnl;

/// The cell beacons as rarely as it may. Its beacons carry AWDL's BSSID,
/// which no AWDL device beacons with, and an iPhone restarted beside a cell
/// beaconing every 100 TU didn't list us where one beside a cell beaconing
/// every 10 s did.
pub const IBSS_BEACON_TU: u32 = 10_000;

/// The cell's BSSID where it can't have AWDL's (`cell_own_bssid` in the
/// quirks table): locally administered, and the same on every computer, as
/// AWDL's is.
pub const IBSS_OWN_BSSID: MacAddr = MacAddr([0x02, 0x6f, 0x77, 0x6c, 0x79, 0x01]);

pub trait Ops: Send + Sync {
    /// Network interfaces backed by a Wi-Fi card.
    fn wifi_interfaces(&self) -> Vec<String>;
    /// `managed`, `monitor`, `IBSS`, `AP`, ... as `iw` names them.
    fn iface_type(&self, iface: &str) -> Option<String>;
    /// The kernel driver's name, such as `mt7925e`.
    fn driver(&self, iface: &str) -> Option<String>;
    /// The card's PCI or USB ID, such as `14c3:0717`.
    fn device_id(&self, iface: &str) -> Option<String>;
    /// The wiphy, such as `phy0`.
    fn phy(&self, iface: &str) -> Option<String>;
    /// What the wiphy can do.
    fn wiphy(&self, phy: &str) -> Option<Wiphy>;
    fn mac(&self, iface: &str) -> Option<MacAddr>;
    fn index(&self, iface: &str) -> Option<u32>;
    fn exists(&self, iface: &str) -> bool;
    /// The frequency in MHz the interface is on: a station's AP, a joined
    /// cell, a started AP, a tuned monitor.
    fn link_freq(&self, iface: &str) -> Option<u32>;
    /// Whether the station passes traffic: its IPv4 gateway answers a ping.
    fn gateway_reachable(&self, iface: &str) -> bool;
    /// The global regulatory domain, `00` for the world.
    fn regdom(&self) -> Option<String>;
    /// Asks for a regulatory domain; the kernel applies it a moment later.
    fn set_regdom(&self, alpha2: &str) -> io::Result<()>;

    fn add_iface(&self, phy: &str, name: &str, kind: Kind) -> io::Result<()>;
    fn del_iface(&self, name: &str) -> io::Result<()>;
    /// Changes an interface's type; it has to be down.
    fn set_kind(&self, iface: &str, kind: Kind) -> io::Result<()>;
    fn set_mac(&self, iface: &str, mac: MacAddr) -> io::Result<()>;
    fn set_up(&self, iface: &str, up: bool) -> io::Result<()>;
    /// Tunes a monitor interface (HT20).
    fn set_freq(&self, iface: &str, freq: u32) -> io::Result<()>;
    /// Joins `bssid` as an ad-hoc cell on a fixed channel: HT20, or with
    /// `ht40` HT40 with its second channel above.
    fn join_ibss(&self, iface: &str, freq: u32, bssid: MacAddr, ht40: bool) -> io::Result<()>;
    fn leave_ibss(&self, iface: &str) -> io::Result<()>;
    /// Sets `/proc/sys/<key>`, with `key` in slashes.
    fn sysctl(&self, key: &str, value: &str) -> io::Result<()>;
    /// mt76's debugfs directory for this wiphy.
    fn mt76_dir(&self, phy: &str) -> PathBuf;
    /// rtw88's debugfs directory for this wiphy.
    fn rtw88_dir(&self, phy: &str) -> PathBuf;
    fn read(&self, path: &Path) -> Option<String>;
    fn write(&self, path: &Path, value: &str) -> io::Result<()>;

    /// Tells NetworkManager to manage the interface, or leave it alone.
    fn set_managed(&self, iface: &str, managed: bool);
    /// The UUID of the connection NetworkManager has up on a station.
    fn nm_connection(&self, station: &str) -> Option<String>;
    /// Brings a NetworkManager connection up on a station.
    fn connection_up(&self, uuid: &str, station: &str) -> io::Result<()>;
    /// Forces the station to reassociate.
    fn reconnect(&self, station: &str);
    fn sleep(&self, d: Duration);
}

/// The real system.
#[derive(Debug, Default, Clone, Copy)]
pub struct System;

const NET: &str = "/sys/class/net";

impl System {
    /// A wiphy's debugfs directory, where its driver keeps its own.
    fn debugfs(&self, phy: &str) -> PathBuf {
        let debug = Path::new("/sys/kernel/debug");
        if !debug.join("ieee80211").exists() {
            // Needs CAP_SYS_ADMIN, which owlyd doesn't have: its unit has
            // systemd mount debugfs instead. This is for running as root.
            let _ = self.run("mount", &["-t", "debugfs", "none", "/sys/kernel/debug"]);
        }
        debug.join("ieee80211").join(phy)
    }

    fn run(&self, program: &str, args: &[&str]) -> io::Result<()> {
        let out = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| io::Error::new(e.kind(), format!("{program}: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            let said = String::from_utf8_lossy(&out.stderr);
            Err(io::Error::other(format!(
                "{program} {}: {}",
                args.join(" "),
                said.trim()
            )))
        }
    }

    fn output(&self, program: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn ifindex(&self, iface: &str) -> io::Result<u32> {
        self.index(iface)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no interface {iface}")))
    }

    fn interface(&self, iface: &str) -> Option<crate::nl80211::Interface> {
        let index = self.index(iface)?;
        Nl80211::open().ok()?.interface(index).ok()
    }

    fn wiphy_index(&self, phy: &str) -> io::Result<u32> {
        fs::read_to_string(Path::new("/sys/class/ieee80211").join(phy).join("index"))?
            .trim()
            .parse()
            .map_err(io::Error::other)
    }
}

/// A sysfs ID file's value without its `0x`.
fn sysfs_id(path: &Path) -> Option<String> {
    let v = fs::read_to_string(path).ok()?;
    let v = v.trim();
    Some(v.strip_prefix("0x").unwrap_or(v).to_ascii_lowercase())
}

impl Ops for System {
    fn wifi_interfaces(&self) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(NET)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().join("phy80211").exists())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    }

    fn iface_type(&self, iface: &str) -> Option<String> {
        Some(self.interface(iface)?.iftype.name())
    }

    fn driver(&self, iface: &str) -> Option<String> {
        let link = fs::read_link(Path::new(NET).join(iface).join("device/driver")).ok()?;
        Some(link.file_name()?.to_string_lossy().into_owned())
    }

    fn device_id(&self, iface: &str) -> Option<String> {
        let dev = fs::canonicalize(Path::new(NET).join(iface).join("device")).ok()?;
        // PCI: the device itself. USB: the interface's parent, the device.
        if let (Some(v), Some(d)) = (sysfs_id(&dev.join("vendor")), sysfs_id(&dev.join("device"))) {
            return Some(format!("{v}:{d}"));
        }
        let usb = dev.parent()?;
        Some(format!(
            "{}:{}",
            sysfs_id(&usb.join("idVendor"))?,
            sysfs_id(&usb.join("idProduct"))?
        ))
    }

    fn phy(&self, iface: &str) -> Option<String> {
        let link = fs::canonicalize(Path::new(NET).join(iface).join("phy80211")).ok()?;
        Some(link.file_name()?.to_string_lossy().into_owned())
    }

    fn wiphy(&self, phy: &str) -> Option<Wiphy> {
        let index = self.wiphy_index(phy).ok()?;
        Nl80211::open().ok()?.wiphy(index).ok()
    }

    fn mac(&self, iface: &str) -> Option<MacAddr> {
        fs::read_to_string(Path::new(NET).join(iface).join("address"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn index(&self, iface: &str) -> Option<u32> {
        fs::read_to_string(Path::new(NET).join(iface).join("ifindex"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn exists(&self, iface: &str) -> bool {
        Path::new(NET).join(iface).exists()
    }

    fn link_freq(&self, iface: &str) -> Option<u32> {
        self.interface(iface)?.freq
    }

    fn gateway_reachable(&self, iface: &str) -> bool {
        let Some(routes) = self.output("ip", &["-4", "route", "show", "default", "dev", iface])
        else {
            return false;
        };
        let Some(gw) = routes.split_whitespace().skip_while(|w| *w != "via").nth(1) else {
            return false;
        };
        self.run("ping", &["-c1", "-W1", "-I", iface, gw]).is_ok()
    }

    fn regdom(&self) -> Option<String> {
        Nl80211::open().ok()?.regdom().ok()?
    }

    fn set_regdom(&self, alpha2: &str) -> io::Result<()> {
        Nl80211::open()?.set_regdom(alpha2)
    }

    fn add_iface(&self, phy: &str, name: &str, kind: Kind) -> io::Result<()> {
        let wiphy = self.wiphy_index(phy)?;
        Nl80211::open()?.new_interface(wiphy, name, kind).map(drop)
    }

    fn del_iface(&self, name: &str) -> io::Result<()> {
        Nl80211::open()?.del_interface(self.ifindex(name)?)
    }

    fn set_kind(&self, iface: &str, kind: Kind) -> io::Result<()> {
        Nl80211::open()?.set_kind(self.ifindex(iface)?, kind)
    }

    fn set_mac(&self, iface: &str, mac: MacAddr) -> io::Result<()> {
        Rtnl::open()?.set_mac(self.ifindex(iface)?, mac)
    }

    fn set_up(&self, iface: &str, up: bool) -> io::Result<()> {
        Rtnl::open()?.set_up(self.ifindex(iface)?, up)
    }

    fn set_freq(&self, iface: &str, freq: u32) -> io::Result<()> {
        Nl80211::open()?.set_freq(self.ifindex(iface)?, freq)
    }

    fn join_ibss(&self, iface: &str, freq: u32, bssid: MacAddr, ht40: bool) -> io::Result<()> {
        Nl80211::open()?.join_ibss(
            self.ifindex(iface)?,
            b"owly",
            freq,
            bssid,
            IBSS_BEACON_TU,
            ht40,
        )
    }

    fn leave_ibss(&self, iface: &str) -> io::Result<()> {
        Nl80211::open()?.leave_ibss(self.ifindex(iface)?)
    }

    fn sysctl(&self, key: &str, value: &str) -> io::Result<()> {
        fs::write(Path::new("/proc/sys").join(key), value)
    }

    fn mt76_dir(&self, phy: &str) -> PathBuf {
        self.debugfs(phy).join("mt76")
    }

    fn rtw88_dir(&self, phy: &str) -> PathBuf {
        self.debugfs(phy).join("rtw88")
    }

    fn read(&self, path: &Path) -> Option<String> {
        fs::read_to_string(path).ok().map(|s| s.trim().to_string())
    }

    fn write(&self, path: &Path, value: &str) -> io::Result<()> {
        fs::write(path, value)
    }

    fn set_managed(&self, iface: &str, managed: bool) {
        let _ = self.run(
            "nmcli",
            &[
                "device",
                "set",
                iface,
                "managed",
                if managed { "yes" } else { "no" },
            ],
        );
    }

    fn nm_connection(&self, station: &str) -> Option<String> {
        let out = self.output(
            "nmcli",
            &["-g", "GENERAL.CON-UUID", "device", "show", station],
        )?;
        let uuid = out.trim();
        (!uuid.is_empty() && uuid != "--").then(|| uuid.to_string())
    }

    fn connection_up(&self, uuid: &str, station: &str) -> io::Result<()> {
        self.run(
            "nmcli",
            &[
                "-w",
                "10",
                "connection",
                "up",
                "uuid",
                uuid,
                "ifname",
                station,
            ],
        )
    }

    fn reconnect(&self, station: &str) {
        if self
            .run("nmcli", &["-w", "20", "device", "connect", station])
            .is_err()
        {
            // NetworkManager isn't running; whatever manages the station
            // reconnects it once it drops.
            let _ = self
                .ifindex(station)
                .and_then(|i| Nl80211::open()?.disconnect(i));
        }
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// IFA_F_TENTATIVE in `/proc/net/if_inet6`'s flags.
const TENTATIVE: u32 = 0x40;

/// The interface's IPv6 link-local address, and whether it's still
/// tentative (in duplicate address detection).
pub fn link_local(iface: &str) -> Option<(Ipv6Addr, bool)> {
    parse_if_inet6(&fs::read_to_string("/proc/net/if_inet6").ok()?, iface)
}

/// The link-local line for `iface` in `/proc/net/if_inet6`: address, index,
/// prefix length, scope, flags and name, in hex but for the name.
pub fn parse_if_inet6(text: &str, iface: &str) -> Option<(Ipv6Addr, bool)> {
    text.lines().find_map(|line| {
        let f: Vec<_> = line.split_whitespace().collect();
        let [addr, _, _, scope, flags, name] = f[..] else {
            return None;
        };
        if name != iface || scope != "20" {
            return None;
        }
        let addr = u128::from_str_radix(addr, 16).ok()?;
        let flags = u32::from_str_radix(flags, 16).ok()?;
        Some((Ipv6Addr::from(addr), flags & TENTATIVE != 0))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_inet6_gives_the_link_local_and_its_state() {
        let text = "\
00000000000000000000000000000001 01 80 10 80       lo
fe80000000000000840804fffe8a2bf4 05 40 20 c0    awdl0
20010db8000000000000000000000001 05 40 00 80    awdl0
fe80000000000000840804fffe8a2bf5 06 40 20 80     mon0
";
        let (addr, tentative) = parse_if_inet6(text, "awdl0").unwrap();
        assert_eq!(
            addr,
            "fe80::8408:4ff:fe8a:2bf4".parse::<Ipv6Addr>().unwrap()
        );
        assert!(tentative);
        let (_, tentative) = parse_if_inet6(text, "mon0").unwrap();
        assert!(!tentative);
        assert_eq!(parse_if_inet6(text, "lo"), None, "not link scope");
        assert_eq!(parse_if_inet6(text, "wlan0"), None);
    }
}
