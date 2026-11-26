//! nl80211, the kernel's Wi-Fi configuration interface: what a card can do,
//! and the interfaces the radio modes set up on it (AWDL-2).
//!
//! The queries ([`Nl80211::wiphy`], [`Nl80211::interface`],
//! [`Nl80211::regdom`]) need no privileges, so the probe runs as anyone. The
//! changes need `CAP_NET_ADMIN`.

use std::io;

use crate::radio::MacAddr;

use crate::netlink::{Attrs, Genl, NLM_F_DUMP, as_str, as_u32, attr, attrs};

const CMD_GET_WIPHY: u8 = 1;
const CMD_SET_WIPHY: u8 = 2;
const CMD_GET_INTERFACE: u8 = 5;
const CMD_SET_INTERFACE: u8 = 6;
const CMD_NEW_INTERFACE: u8 = 7;
const CMD_DEL_INTERFACE: u8 = 8;
const CMD_NEW_STATION: u8 = 19;
const CMD_DEL_STATION: u8 = 20;
const CMD_REQ_SET_REG: u8 = 27;
const CMD_GET_REG: u8 = 31;
const CMD_JOIN_IBSS: u8 = 43;
const CMD_LEAVE_IBSS: u8 = 44;
const CMD_DISCONNECT: u8 = 48;

const ATTR_WIPHY: u16 = 1;
const ATTR_WIPHY_NAME: u16 = 2;
const ATTR_IFINDEX: u16 = 3;
const ATTR_IFNAME: u16 = 4;
const ATTR_IFTYPE: u16 = 5;
const ATTR_MAC: u16 = 6;
const ATTR_BEACON_INTERVAL: u16 = 12;
const ATTR_STA_AID: u16 = 16;
const ATTR_STA_LISTEN_INTERVAL: u16 = 18;
const ATTR_STA_SUPPORTED_RATES: u16 = 19;
const ATTR_WIPHY_BANDS: u16 = 22;
const ATTR_MNTR_FLAGS: u16 = 23;
const ATTR_HT_CAPABILITY: u16 = 31;
const ATTR_SUPPORTED_IFTYPES: u16 = 32;
const ATTR_REG_ALPHA2: u16 = 33;
const ATTR_WIPHY_FREQ: u16 = 38;
const ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
const ATTR_SSID: u16 = 52;
const ATTR_FREQ_FIXED: u16 = 60;
const ATTR_STA_FLAGS2: u16 = 67;
const ATTR_INTERFACE_COMBINATIONS: u16 = 120;
const ATTR_SOFTWARE_IFTYPES: u16 = 121;
const ATTR_FEATURE_FLAGS: u16 = 143;
const ATTR_STA_CAPABILITY: u16 = 171;
const ATTR_SPLIT_WIPHY_DUMP: u16 = 174;
const ATTR_WIPHY_SELF_MANAGED_REG: u16 = 216;
const ATTR_STA_SUPPORT_P2P_PS: u16 = 228;
const ATTR_MLO_LINKS: u16 = 312;

const BAND_ATTR_FREQS: u16 = 1;
const FREQ_ATTR_FREQ: u16 = 1;
const FREQ_ATTR_DISABLED: u16 = 2;
const FREQ_ATTR_NO_IR: u16 = 3;
const FREQ_ATTR_RADAR: u16 = 5;

const COMB_LIMITS: u16 = 1;
const COMB_MAXNUM: u16 = 2;
const COMB_NUM_CHANNELS: u16 = 4;
const LIMIT_MAX: u16 = 1;
const LIMIT_TYPES: u16 = 2;

const MNTR_FLAG_OTHER_BSS: u16 = 4;
const MNTR_FLAG_ACTIVE: u16 = 6;
const CHAN_HT20: u32 = 1;
const FEATURE_ACTIVE_MONITOR: u32 = 1 << 17;

const STA_FLAG_AUTHORIZED: u32 = 1 << 1;
const STA_FLAG_WME: u32 = 1 << 3;
const STA_FLAG_AUTHENTICATED: u32 = 1 << 5;
const STA_FLAG_ASSOCIATED: u32 = 1 << 7;

/// Mandatory/standard OFDM rates (6..54 Mbit/s in 500 kbit/s units), valid on
/// both 5 GHz and 2.4 GHz (ERP-OFDM).
const PEER_STA_RATES: [u8; 8] = [12, 18, 24, 36, 48, 72, 96, 108];
/// 26-byte `struct ieee80211_ht_cap` for HT20, 1 spatial stream (MCS 0-7).
const PEER_STA_HT_CAP: [u8; 26] = [
    0x8c, 0x01, 0x1b, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// An interface type, as nl80211 numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IfType {
    Adhoc,
    Station,
    Ap,
    Monitor,
    Other(u32),
}

impl IfType {
    pub fn from_nl(n: u32) -> IfType {
        match n {
            1 => IfType::Adhoc,
            2 => IfType::Station,
            3 => IfType::Ap,
            6 => IfType::Monitor,
            n => IfType::Other(n),
        }
    }

    pub fn to_nl(self) -> u32 {
        match self {
            IfType::Adhoc => 1,
            IfType::Station => 2,
            IfType::Ap => 3,
            IfType::Monitor => 6,
            IfType::Other(n) => n,
        }
    }

    /// As `iw` names it.
    pub fn name(self) -> String {
        match self {
            IfType::Adhoc => "IBSS".into(),
            IfType::Station => "managed".into(),
            IfType::Ap => "AP".into(),
            IfType::Monitor => "monitor".into(),
            IfType::Other(n) => format!("type {n}"),
        }
    }
}

/// A channel the card has, with what the regulatory domain allows on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    pub freq: u32,
    pub disabled: bool,
    /// "No IR": may not start transmitting there (no beacons, no cell).
    pub no_ir: bool,
    pub radar: bool,
}

impl Channel {
    /// Whether the card may start a cell, beacon or inject there.
    pub fn may_transmit(&self) -> bool {
        !self.disabled && !self.no_ir && !self.radar
    }
}

/// One allowed mix of interfaces (`iw phy info`, "valid interface
/// combinations").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Combination {
    /// Each limit: at most `.0` interfaces of the types in `.1`.
    pub limits: Vec<(u32, Vec<IfType>)>,
    pub max: u32,
    pub channels: u32,
}

impl Combination {
    /// Whether one interface of each type fits at once.
    pub fn allows(&self, types: &[IfType]) -> bool {
        if types.len() as u32 > self.max {
            return false;
        }
        let mut left: Vec<u32> = self.limits.iter().map(|l| l.0).collect();
        // Fewest choices first, so a narrow limit isn't spent on a type
        // a wider one would take.
        let mut types = types.to_vec();
        types.sort_by_key(|t| self.limits.iter().filter(|l| l.1.contains(t)).count());
        types.iter().all(|t| {
            let slot = self
                .limits
                .iter()
                .enumerate()
                .find(|(i, l)| left[*i] > 0 && l.1.contains(t));
            match slot {
                Some((i, _)) => {
                    left[i] -= 1;
                    true
                }
                None => false,
            }
        })
    }
}

/// What a wiphy can do.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Wiphy {
    pub index: u32,
    pub name: String,
    pub iftypes: Vec<IfType>,
    /// Types the driver doesn't count against its combinations (monitor, on
    /// mac80211 drivers).
    pub software: Vec<IfType>,
    pub combinations: Vec<Combination>,
    pub active_monitor: bool,
    /// The driver manages its own regulatory domain (Intel's LAR).
    pub self_managed_reg: bool,
    pub channels: Vec<Channel>,
}

impl Wiphy {
    pub fn supports(&self, t: IfType) -> bool {
        self.iftypes.contains(&t)
    }

    /// Whether interfaces of all these types may exist at once.
    pub fn allows(&self, types: &[IfType]) -> bool {
        if !types.iter().all(|t| self.supports(*t)) {
            return false;
        }
        let counted: Vec<IfType> = types
            .iter()
            .copied()
            .filter(|t| !self.software.contains(t))
            .collect();
        counted.len() <= 1 || self.combinations.iter().any(|c| c.allows(&counted))
    }

    pub fn channel(&self, freq: u32) -> Option<&Channel> {
        self.channels.iter().find(|c| c.freq == freq)
    }

    /// Merges one message of a split dump.
    fn absorb(&mut self, msg: &[u8]) {
        for (ty, v) in attrs(msg) {
            match ty {
                ATTR_WIPHY => self.index = as_u32(v).unwrap_or(self.index),
                ATTR_WIPHY_NAME => self.name = as_str(v).unwrap_or_default(),
                ATTR_SUPPORTED_IFTYPES => self.iftypes = iftypes(v),
                ATTR_SOFTWARE_IFTYPES => self.software = iftypes(v),
                ATTR_FEATURE_FLAGS => {
                    self.active_monitor = as_u32(v).unwrap_or(0) & FEATURE_ACTIVE_MONITOR != 0;
                }
                ATTR_WIPHY_SELF_MANAGED_REG => self.self_managed_reg = true,
                ATTR_INTERFACE_COMBINATIONS => {
                    self.combinations = attrs(v).map(|(_, c)| combination(c)).collect();
                }
                ATTR_WIPHY_BANDS => {
                    for (_, band) in attrs(v) {
                        let Some(freqs) = attr(band, BAND_ATTR_FREQS) else {
                            continue;
                        };
                        for (_, f) in attrs(freqs) {
                            let Some(freq) = attr(f, FREQ_ATTR_FREQ).and_then(as_u32) else {
                                continue;
                            };
                            let c = Channel {
                                freq,
                                disabled: attr(f, FREQ_ATTR_DISABLED).is_some(),
                                no_ir: attr(f, FREQ_ATTR_NO_IR).is_some(),
                                radar: attr(f, FREQ_ATTR_RADAR).is_some(),
                            };
                            match self.channels.iter_mut().find(|x| x.freq == freq) {
                                Some(x) => *x = c,
                                None => self.channels.push(c),
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn iftypes(v: &[u8]) -> Vec<IfType> {
    attrs(v).map(|(t, _)| IfType::from_nl(t.into())).collect()
}

fn combination(v: &[u8]) -> Combination {
    let mut c = Combination::default();
    for (ty, x) in attrs(v) {
        match ty {
            COMB_LIMITS => {
                c.limits = attrs(x)
                    .map(|(_, l)| {
                        (
                            attr(l, LIMIT_MAX).and_then(as_u32).unwrap_or(0),
                            attr(l, LIMIT_TYPES).map(iftypes).unwrap_or_default(),
                        )
                    })
                    .collect();
            }
            COMB_MAXNUM => c.max = as_u32(x).unwrap_or(0),
            COMB_NUM_CHANNELS => c.channels = as_u32(x).unwrap_or(0),
            _ => {}
        }
    }
    c
}

/// A wireless interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub iftype: IfType,
    pub wiphy: u32,
    pub mac: Option<MacAddr>,
    /// The channel it's on: an associated station's AP, a joined cell, a
    /// tuned monitor. For a multi-link station, its first link's.
    pub freq: Option<u32>,
    /// A station's network or a cell's name, once it has one.
    pub ssid: Option<Vec<u8>>,
}

impl Interface {
    fn parse(msg: &[u8]) -> Option<Interface> {
        let freq = attr(msg, ATTR_WIPHY_FREQ).and_then(as_u32).or_else(|| {
            let links = attr(msg, ATTR_MLO_LINKS)?;
            attrs(links).find_map(|(_, l)| attr(l, ATTR_WIPHY_FREQ).and_then(as_u32))
        });
        Some(Interface {
            index: attr(msg, ATTR_IFINDEX).and_then(as_u32)?,
            name: attr(msg, ATTR_IFNAME).and_then(as_str)?,
            iftype: IfType::from_nl(attr(msg, ATTR_IFTYPE).and_then(as_u32)?),
            wiphy: attr(msg, ATTR_WIPHY).and_then(as_u32)?,
            mac: attr(msg, ATTR_MAC).and_then(|m| Some(MacAddr(m.try_into().ok()?))),
            freq,
            ssid: attr(msg, ATTR_SSID).map(<[u8]>::to_vec),
        })
    }
}

/// How a new or changed interface should run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Station,
    Adhoc,
    Ap,
    /// A monitor; an active one ACKs unicast to its own address.
    Monitor {
        active: bool,
    },
}

impl Kind {
    pub fn iftype(self) -> IfType {
        match self {
            Kind::Station => IfType::Station,
            Kind::Adhoc => IfType::Adhoc,
            Kind::Ap => IfType::Ap,
            Kind::Monitor { .. } => IfType::Monitor,
        }
    }

    /// The type, and a monitor's flags. Flags replace mac80211's default,
    /// control frames and other BSSs' frames passed up, so a new passive
    /// monitor gets none: with an empty set, a driver that filters by BSSID
    /// (mt76, rtw89) drops AWDL's frames, which carry AWDL's BSSID. An
    /// interface changed into a passive monitor gets the empty set, as
    /// `iw set monitor none` sends it. An active monitor asks for other
    /// BSSs' frames as well as being active: without them an mt7921e passes
    /// up a peer's action frames but drops its data frames, mDNS included.
    fn put(self, a: &mut Attrs, new: bool) {
        a.u32(ATTR_IFTYPE, self.iftype().to_nl());
        if let Kind::Monitor { active } = self
            && (active || !new)
        {
            let mut flags = Attrs::new();
            if active {
                flags.flag(MNTR_FLAG_ACTIVE);
                flags.flag(MNTR_FLAG_OTHER_BSS);
            }
            a.nested(ATTR_MNTR_FLAGS, &flags);
        }
    }
}

/// An nl80211 connection.
pub struct Nl80211 {
    genl: Genl,
}

impl Nl80211 {
    pub fn open() -> io::Result<Nl80211> {
        Ok(Nl80211 {
            genl: Genl::open("nl80211")?,
        })
    }

    pub fn wiphy(&mut self, index: u32) -> io::Result<Wiphy> {
        let mut a = Attrs::new();
        a.u32(ATTR_WIPHY, index).flag(ATTR_SPLIT_WIPHY_DUMP);
        let msgs = self.genl.request(CMD_GET_WIPHY, NLM_F_DUMP, &a)?;
        let mut w = Wiphy::default();
        let mut found = false;
        for m in &msgs {
            if attr(m, ATTR_WIPHY).and_then(as_u32) == Some(index) {
                found = true;
                w.absorb(m);
            }
        }
        if !found {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no wiphy {index}"),
            ));
        }
        Ok(w)
    }

    pub fn interface(&mut self, ifindex: u32) -> io::Result<Interface> {
        let mut a = Attrs::new();
        a.u32(ATTR_IFINDEX, ifindex);
        let msgs = self.genl.request(CMD_GET_INTERFACE, 0, &a)?;
        msgs.iter()
            .find_map(|m| Interface::parse(m))
            .ok_or_else(|| io::Error::other(format!("no interface {ifindex}")))
    }

    /// Adds an interface on a wiphy; returns its index.
    pub fn new_interface(&mut self, wiphy: u32, name: &str, kind: Kind) -> io::Result<u32> {
        let mut a = Attrs::new();
        a.u32(ATTR_WIPHY, wiphy).str(ATTR_IFNAME, name);
        kind.put(&mut a, true);
        let msgs = self.genl.request(CMD_NEW_INTERFACE, 0, &a)?;
        msgs.iter()
            .find_map(|m| attr(m, ATTR_IFINDEX).and_then(as_u32))
            .ok_or_else(|| io::Error::other(format!("{name} was added without an index")))
    }

    pub fn del_interface(&mut self, ifindex: u32) -> io::Result<()> {
        let mut a = Attrs::new();
        a.u32(ATTR_IFINDEX, ifindex);
        self.genl.request(CMD_DEL_INTERFACE, 0, &a).map(drop)
    }

    /// Changes an interface's type. The interface has to be down.
    pub fn set_kind(&mut self, ifindex: u32, kind: Kind) -> io::Result<()> {
        let mut a = Attrs::new();
        a.u32(ATTR_IFINDEX, ifindex);
        kind.put(&mut a, false);
        self.genl.request(CMD_SET_INTERFACE, 0, &a).map(drop)
    }

    /// Tunes a monitor interface, 20 MHz wide (HT20).
    pub fn set_freq(&mut self, ifindex: u32, freq: u32) -> io::Result<()> {
        let mut a = Attrs::new();
        a.u32(ATTR_IFINDEX, ifindex)
            .u32(ATTR_WIPHY_FREQ, freq)
            .u32(ATTR_WIPHY_CHANNEL_TYPE, CHAN_HT20);
        self.genl.request(CMD_SET_WIPHY, 0, &a).map(drop)
    }

    /// Joins (or starts) an HT20 ad-hoc cell on a fixed channel and BSSID.
    pub fn join_ibss(
        &mut self,
        ifindex: u32,
        ssid: &[u8],
        freq: u32,
        bssid: MacAddr,
        beacon_interval: u32,
    ) -> io::Result<()> {
        let mut a = Attrs::new();
        a.u32(ATTR_IFINDEX, ifindex)
            .bytes(ATTR_SSID, ssid)
            .u32(ATTR_WIPHY_FREQ, freq)
            .u32(ATTR_WIPHY_CHANNEL_TYPE, CHAN_HT20)
            .flag(ATTR_FREQ_FIXED)
            .bytes(ATTR_MAC, &bssid.0)
            .u32(ATTR_BEACON_INTERVAL, beacon_interval);
        self.genl.request(CMD_JOIN_IBSS, 0, &a).map(drop)
    }

    pub fn leave_ibss(&mut self, ifindex: u32) -> io::Result<()> {
        let mut a = Attrs::new();
        a.u32(ATTR_IFINDEX, ifindex);
        self.genl.request(CMD_LEAVE_IBSS, 0, &a).map(drop)
    }

    /// Drops a station's association.
    pub fn disconnect(&mut self, ifindex: u32) -> io::Result<()> {
        let mut a = Attrs::new();
        a.u32(ATTR_IFINDEX, ifindex);
        self.genl.request(CMD_DISCONNECT, 0, &a).map(drop)
    }

    /// The global regulatory domain's country code (`00` for the world).
    pub fn regdom(&mut self) -> io::Result<Option<String>> {
        let msgs = self.genl.request(CMD_GET_REG, 0, &Attrs::new())?;
        Ok(msgs
            .iter()
            .find_map(|m| attr(m, ATTR_REG_ALPHA2).and_then(as_str)))
    }

    /// Asks for a regulatory domain. The kernel applies it asynchronously.
    pub fn set_regdom(&mut self, alpha2: &str) -> io::Result<()> {
        let mut a = Attrs::new();
        a.str(ATTR_REG_ALPHA2, alpha2);
        self.genl.request(CMD_REQ_SET_REG, 0, &a).map(drop)
    }

    /// Registers an AWDL peer as an unauthorized station on a hidden AP
    /// interface (`WME | AUTHENTICATED | ASSOCIATED`, with `AUTHORIZED`
    /// strictly clear) so drivers such as `mt7921e` allocate a per-peer
    /// hardware WCID while mac80211 continues blocking normal L2/L3 ingress.
    pub fn add_peer_station(&mut self, ifindex: u32, mac: MacAddr, aid: u16) -> io::Result<()> {
        let a = peer_station_add_attrs(ifindex, mac, aid);
        self.genl.request(CMD_NEW_STATION, 0, &a).map(drop)
    }

    /// Removes a peer station from a hidden AP interface.
    pub fn del_peer_station(&mut self, ifindex: u32, mac: MacAddr) -> io::Result<()> {
        let a = peer_station_del_attrs(ifindex, mac);
        self.genl.request(CMD_DEL_STATION, 0, &a).map(drop)
    }
}

fn peer_station_add_attrs(ifindex: u32, mac: MacAddr, aid: u16) -> Attrs {
    let mask = STA_FLAG_AUTHORIZED | STA_FLAG_WME | STA_FLAG_AUTHENTICATED | STA_FLAG_ASSOCIATED;
    let set = STA_FLAG_WME | STA_FLAG_AUTHENTICATED | STA_FLAG_ASSOCIATED;
    let mut flags2 = [0u8; 8];
    flags2[..4].copy_from_slice(&mask.to_ne_bytes());
    flags2[4..].copy_from_slice(&set.to_ne_bytes());

    let mut a = Attrs::new();
    a.u32(ATTR_IFINDEX, ifindex)
        .bytes(ATTR_MAC, &mac.0)
        .u16(ATTR_STA_AID, aid)
        .u16(ATTR_STA_LISTEN_INTERVAL, 10)
        .bytes(ATTR_STA_SUPPORTED_RATES, &PEER_STA_RATES)
        .u16(ATTR_STA_CAPABILITY, 0x0401)
        .bytes(ATTR_HT_CAPABILITY, &PEER_STA_HT_CAP)
        .u8(ATTR_STA_SUPPORT_P2P_PS, 0)
        .bytes(ATTR_STA_FLAGS2, &flags2);
    a
}

fn peer_station_del_attrs(ifindex: u32, mac: MacAddr) -> Attrs {
    let mut a = Attrs::new();
    a.u32(ATTR_IFINDEX, ifindex).bytes(ATTR_MAC, &mac.0);
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::attr;

    fn monitor_flags(kind: Kind, new: bool) -> Option<Vec<u8>> {
        let mut a = Attrs::new();
        kind.put(&mut a, new);
        attr(&a.0, ATTR_MNTR_FLAGS).map(<[u8]>::to_vec)
    }

    #[test]
    fn a_new_passive_monitor_keeps_mac80211s_default_flags() {
        assert_eq!(monitor_flags(Kind::Monitor { active: false }, true), None);
        // Changing a station into one: `iw set monitor none`.
        assert_eq!(
            monitor_flags(Kind::Monitor { active: false }, false),
            Some(vec![])
        );
        let mut active = Attrs::new();
        active.flag(MNTR_FLAG_ACTIVE);
        active.flag(MNTR_FLAG_OTHER_BSS);
        for new in [true, false] {
            assert_eq!(
                monitor_flags(Kind::Monitor { active: true }, new),
                Some(active.0.clone())
            );
        }
        assert_eq!(monitor_flags(Kind::Adhoc, true), None);
    }

    fn flags(types: &[u32]) -> Attrs {
        let mut a = Attrs::new();
        for t in types {
            a.flag(*t as u16);
        }
        a
    }

    fn freq(f: u32, extra: &[u16]) -> Attrs {
        let mut a = Attrs::new();
        a.u32(FREQ_ATTR_FREQ, f);
        for e in extra {
            a.flag(*e);
        }
        a
    }

    /// The two halves of a split dump for a card like the MT7925: station,
    /// IBSS, AP and monitor, monitor counted as software, one combination
    /// of a station and an AP or IBSS.
    fn dump() -> Vec<Vec<u8>> {
        let mut first = Attrs::new();
        first
            .u32(ATTR_WIPHY, 0)
            .str(ATTR_WIPHY_NAME, "phy0")
            .nested(ATTR_SUPPORTED_IFTYPES, &flags(&[1, 2, 3, 6]))
            .nested(ATTR_SOFTWARE_IFTYPES, &flags(&[6]))
            .u32(ATTR_FEATURE_FLAGS, FEATURE_ACTIVE_MONITOR | 1);
        let mut freqs = Attrs::new();
        freqs
            .nested(0, &freq(2437, &[]))
            .nested(1, &freq(5220, &[FREQ_ATTR_NO_IR]))
            .nested(2, &freq(5260, &[FREQ_ATTR_RADAR]))
            .nested(3, &freq(5745, &[FREQ_ATTR_DISABLED]));
        let mut band = Attrs::new();
        band.nested(BAND_ATTR_FREQS, &freqs);
        let mut bands = Attrs::new();
        bands.nested(0, &band);
        let mut limit_sta = Attrs::new();
        limit_sta
            .u32(LIMIT_MAX, 1)
            .nested(LIMIT_TYPES, &flags(&[2]));
        let mut limit_ap = Attrs::new();
        limit_ap
            .u32(LIMIT_MAX, 1)
            .nested(LIMIT_TYPES, &flags(&[1, 3]));
        let mut limits = Attrs::new();
        limits.nested(1, &limit_sta).nested(2, &limit_ap);
        let mut comb = Attrs::new();
        comb.nested(COMB_LIMITS, &limits)
            .u32(COMB_MAXNUM, 2)
            .u32(COMB_NUM_CHANNELS, 1);
        let mut combs = Attrs::new();
        combs.nested(1, &comb);
        let mut second = Attrs::new();
        second
            .u32(ATTR_WIPHY, 0)
            .nested(ATTR_WIPHY_BANDS, &bands)
            .nested(ATTR_INTERFACE_COMBINATIONS, &combs);
        vec![first.0, second.0]
    }

    #[test]
    fn a_split_dump_merges_into_one_wiphy() {
        let mut w = Wiphy::default();
        for m in dump() {
            w.absorb(&m);
        }
        assert_eq!(w.name, "phy0");
        assert!(w.supports(IfType::Adhoc) && w.supports(IfType::Monitor));
        assert!(w.active_monitor);
        assert!(!w.self_managed_reg);
        let allowed: Vec<_> = w
            .channels
            .iter()
            .filter(|c| c.may_transmit())
            .map(|c| c.freq)
            .collect();
        assert_eq!(allowed, [2437]);
        assert!(w.channel(5220).unwrap().no_ir);
        // A monitor beside anything; an IBSS beside the station; not two
        // stations.
        assert!(w.allows(&[IfType::Station, IfType::Monitor]));
        assert!(w.allows(&[IfType::Station, IfType::Adhoc, IfType::Monitor]));
        assert!(w.allows(&[IfType::Station, IfType::Ap]));
        assert!(!w.allows(&[IfType::Adhoc, IfType::Ap]));
        assert!(!w.allows(&[IfType::Station, IfType::Station]));
        assert!(!w.allows(&[IfType::Other(10)]));
    }

    #[test]
    fn combinations_spend_narrow_limits_first() {
        let c = Combination {
            limits: vec![
                (1, vec![IfType::Station, IfType::Ap]),
                (1, vec![IfType::Ap]),
            ],
            max: 2,
            channels: 1,
        };
        assert!(c.allows(&[IfType::Ap, IfType::Station]));
        assert!(!c.allows(&[IfType::Station, IfType::Station]));
    }

    #[test]
    fn an_interface_parses_with_its_channel() {
        let mut a = Attrs::new();
        a.u32(ATTR_IFINDEX, 2)
            .str(ATTR_IFNAME, "wlan0")
            .u32(ATTR_IFTYPE, 2)
            .u32(ATTR_WIPHY, 0)
            .bytes(ATTR_MAC, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])
            .bytes(ATTR_SSID, b"home");
        let i = Interface::parse(&a.0).unwrap();
        assert_eq!(i.iftype, IfType::Station);
        assert_eq!(i.mac.unwrap().to_string(), "aa:bb:cc:dd:ee:01");
        assert_eq!(i.freq, None, "not associated");

        // A multi-link station has its channels per link.
        let mut link = Attrs::new();
        link.u32(ATTR_WIPHY_FREQ, 5220);
        let mut links = Attrs::new();
        links.nested(1, &link);
        a.nested(ATTR_MLO_LINKS, &links);
        assert_eq!(Interface::parse(&a.0).unwrap().freq, Some(5220));
        a.u32(ATTR_WIPHY_FREQ, 2437);
        assert_eq!(Interface::parse(&a.0).unwrap().freq, Some(2437));
    }

    /// The real card, read-only, when there is one: what `iw` shows.
    #[test]
    fn this_computers_wifi_reads_without_root() {
        let Ok(mut nl) = Nl80211::open() else { return };
        let Ok(dir) = std::fs::read_dir("/sys/class/ieee80211") else {
            return;
        };
        for e in dir.flatten() {
            let index: u32 = std::fs::read_to_string(e.path().join("index"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let w = nl.wiphy(index).unwrap();
            assert_eq!(w.name, e.file_name().to_string_lossy());
            assert!(w.supports(IfType::Station), "{w:?}");
            assert!(!w.channels.is_empty(), "{w:?}");
        }
        assert!(nl.regdom().is_ok());
    }

    #[test]
    fn peer_station_attrs_keep_authorized_clear() {
        let mac = MacAddr([0x86, 0x08, 0x04, 0x8a, 0x2b, 0xf4]);
        let add = peer_station_add_attrs(9, mac, 3);
        assert_eq!(attr(&add.0, ATTR_IFINDEX).and_then(as_u32), Some(9));
        assert_eq!(attr(&add.0, ATTR_MAC), Some(&mac.0[..]));
        assert_eq!(
            attr(&add.0, ATTR_STA_AID).and_then(crate::netlink::as_u16),
            Some(3)
        );
        assert_eq!(
            attr(&add.0, ATTR_STA_LISTEN_INTERVAL).and_then(crate::netlink::as_u16),
            Some(10)
        );
        assert_eq!(
            attr(&add.0, ATTR_STA_SUPPORTED_RATES),
            Some(&PEER_STA_RATES[..])
        );
        assert_eq!(
            attr(&add.0, ATTR_STA_CAPABILITY).and_then(crate::netlink::as_u16),
            Some(0x0401)
        );
        let ht = attr(&add.0, ATTR_HT_CAPABILITY).unwrap();
        assert_eq!(ht.len(), 26);
        assert_eq!(&ht[..4], &[0x8c, 0x01, 0x1b, 0xff]);
        assert_eq!(
            attr(&add.0, ATTR_STA_SUPPORT_P2P_PS).and_then(crate::netlink::as_u8),
            Some(0)
        );
        let flags2 = attr(&add.0, ATTR_STA_FLAGS2).unwrap();
        assert_eq!(flags2.len(), 8);
        let mask = u32::from_ne_bytes(flags2[..4].try_into().unwrap());
        let set = u32::from_ne_bytes(flags2[4..8].try_into().unwrap());
        assert_ne!(mask & STA_FLAG_AUTHORIZED, 0, "AUTHORIZED must be masked");
        assert_eq!(set & STA_FLAG_AUTHORIZED, 0, "AUTHORIZED must stay clear");
        assert_eq!(
            set,
            STA_FLAG_WME | STA_FLAG_AUTHENTICATED | STA_FLAG_ASSOCIATED
        );

        let del = peer_station_del_attrs(9, mac);
        assert_eq!(attr(&del.0, ATTR_IFINDEX).and_then(as_u32), Some(9));
        assert_eq!(attr(&del.0, ATTR_MAC), Some(&mac.0[..]));
    }
}
