//! The capability probe: which card the radio would use, what nl80211 says
//! it can do, what the quirks table knows about it, and what stands in the
//! way. Needs no root and changes nothing, so `owly doctor` and owlyd's
//! `Probe()` run it for anyone.

use std::path::Path;

use crate::radio::{Capabilities, Missing};
use serde::Serialize;

use crate::injection::AWDL_IFACE;
use crate::injection::{AP, IBSS, Injection, MONITOR, Settings};
use crate::nl80211::{IfType, Wiphy};
use crate::quirks::{Mode, Quirk, Source, Status};
use crate::rundir::RunDir;
use crate::sys::Ops;

/// AWDL's social channels (AWDL-11) and their frequencies.
pub const SOCIAL: [(u8, u32); 3] = [(6, 2437), (44, 5220), (149, 5745)];

/// The social channel at a frequency.
pub fn social_channel(freq: u32) -> Option<u8> {
    SOCIAL.iter().find(|(_, f)| *f == freq).map(|(c, _)| *c)
}

pub fn social_freq(channel: u8) -> Option<u32> {
    SOCIAL.iter().find(|(c, _)| *c == channel).map(|(_, f)| *f)
}

/// The station the radio runs beside or in place of, and the card behind
/// it.
#[derive(Debug, Clone)]
pub struct Station {
    pub name: String,
    pub driver: String,
    pub device: Option<String>,
    pub phy: String,
    pub quirk: Quirk,
    pub source: Source,
    /// None when nl80211 couldn't be read.
    pub wiphy: Option<Wiphy>,
}

impl Station {
    /// The channels to try where the mode picks one, in order, of those
    /// the card may transmit on: as frequencies.
    pub fn tx_channels(&self, settings: &Settings) -> Vec<u32> {
        let order = settings.channels.as_ref().unwrap_or(&self.quirk.channels);
        order
            .iter()
            .filter_map(|c| social_freq(*c))
            .filter(|f| {
                self.wiphy
                    .as_ref()
                    .and_then(|w| w.channel(*f))
                    .is_some_and(|c| c.may_transmit())
            })
            .collect()
    }

    pub fn has(&self, t: IfType) -> bool {
        self.wiphy.as_ref().is_some_and(|w| w.supports(t))
    }

    pub fn active_monitor(&self) -> bool {
        self.wiphy.as_ref().is_some_and(|w| w.active_monitor)
    }
}

/// The station: the one `/etc/owly/radio.toml` names, else the best managed
/// Wi-Fi interface (preferring tested drivers, non-disruptive links such as an
/// unassociated adapter over an active AP station, and 5 GHz social-channel
/// support while preserving OS interface order on ties).
///
/// Refuses a card the quirks table doesn't mark tested unless allowed.
pub fn find_station(ops: &dyn Ops, settings: &Settings) -> Result<Station, Missing> {
    let ours = [AWDL_IFACE, MONITOR, IBSS, AP];
    let name = match &settings.station {
        Some(s) if ops.exists(s) => Some(s.clone()),
        Some(_) => None,
        None => {
            let candidates: Vec<String> = ops
                .wifi_interfaces()
                .into_iter()
                .filter(|i| {
                    !ours.contains(&i.as_str()) && ops.iface_type(i).as_deref() == Some("managed")
                })
                .collect();
            select_best_station(ops, settings, &candidates)
        }
    };
    let Some(name) = name else {
        return Err(missing(
            "hardware",
            match &settings.station {
                Some(s) => format!("The Wi-Fi interface Owly is set to use, {s}, doesn't exist."),
                None => "This computer has no Wi-Fi interface that Owly can use.".into(),
            },
        ));
    };
    let driver = ops.driver(&name).unwrap_or_default();
    let device = ops.device_id(&name);
    let (quirk, source) = settings.quirks.get(&driver, device.as_deref());
    let card = if driver.is_empty() {
        "unknown driver".to_string()
    } else {
        match &device {
            Some(d) => format!("{driver}, {d}"),
            None => driver.clone(),
        }
    };
    match quirk.status {
        Status::Tested => {}
        _ if settings.allow_untested => {}
        // A card with its own entry has worked somewhere, just not well or
        // widely enough to be on by default: don't tell its owner it's
        // never been tried.
        Status::Untested if source == Source::Fallback => {
            return Err(missing(
                "hardware",
                format!(
                    "Owly hasn't been tested on this computer's Wi-Fi ({card}). To try it anyway, set allow_untested = true in /etc/owly/radio.toml, and please report how it goes."
                ),
            ));
        }
        Status::Untested => {
            let why = quirk
                .issues
                .first()
                .map(|i| format!("{i} "))
                .unwrap_or_default();
            return Err(missing(
                "hardware",
                format!(
                    "Owly isn't on by default for this computer's Wi-Fi ({card}) yet, though it has worked on other machines (see Supported hardware in Owly's README). {why}To use it, set allow_untested = true in /etc/owly/radio.toml, and please report how it goes."
                ),
            ));
        }
        Status::Broken => {
            let why = quirk.issues.first().cloned().unwrap_or_default();
            return Err(missing(
                "hardware",
                format!(
                    "Owly is known not to work on this computer's Wi-Fi ({card}). {why} To try it anyway, set allow_untested = true in /etc/owly/radio.toml."
                ),
            ));
        }
    }
    let phy = ops
        .phy(&name)
        .ok_or_else(|| missing("hardware", format!("{name} has no Wi-Fi radio behind it.")))?;
    let wiphy = ops.wiphy(&phy);
    Ok(Station {
        name,
        driver,
        device,
        phy,
        quirk: quirk.clone(),
        source,
        wiphy,
    })
}

fn select_best_station(
    ops: &dyn Ops,
    settings: &Settings,
    candidates: &[String],
) -> Option<String> {
    if candidates.len() <= 1 {
        return candidates.first().cloned();
    }
    candidates
        .iter()
        .enumerate()
        .max_by_key(|(idx, iface)| {
            let driver = ops.driver(iface).unwrap_or_default();
            let device = ops.device_id(iface);
            let (quirk, _) = settings.quirks.get(&driver, device.as_deref());
            let status_rank: u8 = match quirk.status {
                Status::Tested => 2,
                Status::Untested => 1,
                Status::Broken => 0,
            };
            let non_disruptive = match quirk.mode {
                Mode::Shared => ops
                    .link_freq(iface)
                    .is_none_or(|f| social_channel(f).is_some()),
                Mode::Exclusive | Mode::ActiveMonitor => ops.link_freq(iface).is_none(),
            };
            let wiphy = ops.phy(iface).and_then(|p| ops.wiphy(&p));
            let order = settings.channels.as_ref().unwrap_or(&quirk.channels);
            let has_5ghz_social = order.iter().any(|&c| {
                (c == 44 || c == 149)
                    && social_freq(c).is_some_and(|f| {
                        wiphy
                            .as_ref()
                            .is_some_and(|w| w.channel(f).is_some_and(|ch| ch.may_transmit()))
                    })
            });
            (
                status_rank,
                non_disruptive,
                has_5ghz_social,
                std::cmp::Reverse(*idx),
            )
        })
        .map(|(_, iface)| iface.clone())
}

/// A card's abilities, from nl80211.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Card {
    pub phy: String,
    /// An ad-hoc cell, for exclusive mode.
    pub ibss: bool,
    /// An AP, for exclusive mode's hidden AP on cards without ad-hoc mode.
    pub ap: bool,
    /// An active monitor, which ACKs unicast to its own address.
    pub active_monitor: bool,
    /// A monitor interface beside the station, for shared mode. Whether
    /// the card can also inject while associated only a test shows; the
    /// quirks table records it.
    pub monitor_beside_station: bool,
    /// An ad-hoc interface beside the station; else exclusive mode makes
    /// the station itself the cell.
    pub ibss_beside_station: bool,
    /// The driver keeps its own regulatory domain (Intel's LAR).
    pub self_managed_reg: bool,
    /// The global regulatory domain.
    pub regdom: Option<String>,
    /// AWDL's social channels (AWDL-11), and whether the card may transmit
    /// on each.
    pub channels: Vec<ChannelUse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChannelUse {
    pub channel: u8,
    pub freq: u32,
    /// The card has it and may start transmitting there.
    pub transmit: bool,
    /// Why not, when it may not: `absent`, `disabled`, `no-ir` or `radar`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<&'static str>,
}

/// What nl80211 says the card can do.
pub fn card(ops: &dyn Ops, station: &Station) -> Option<Card> {
    let w = station.wiphy.as_ref()?;
    let channels = SOCIAL
        .iter()
        .map(|&(channel, freq)| {
            let why = match w.channel(freq) {
                None => Some("absent"),
                Some(c) if c.disabled => Some("disabled"),
                Some(c) if c.radar => Some("radar"),
                Some(c) if c.no_ir => Some("no-ir"),
                Some(_) => None,
            };
            ChannelUse {
                channel,
                freq,
                transmit: why.is_none(),
                why,
            }
        })
        .collect();
    Some(Card {
        phy: station.phy.clone(),
        ibss: w.supports(IfType::Adhoc),
        ap: w.supports(IfType::Ap),
        active_monitor: w.active_monitor,
        monitor_beside_station: w.allows(&[IfType::Station, IfType::Monitor]),
        ibss_beside_station: w.allows(&[IfType::Station, IfType::Adhoc, IfType::Monitor]),
        self_managed_reg: w.self_managed_reg,
        regdom: ops.regdom(),
        channels,
    })
}

/// The report with the settings in `/etc/owly/radio.toml`, without owlyd:
/// what `owly doctor` and the omdrop hooks say when owlyd can't be reached.
pub fn from_config(run: RunDir) -> Capabilities {
    match Injection::from_config(run) {
        Ok(backend) => backend.probe(),
        Err(e) => {
            let mut caps = Capabilities::none();
            caps.missing.push(missing(
                "backend",
                format!("Owly's radio settings can't be read: {e}"),
            ));
            caps
        }
    }
}

/// The whole report.
pub fn capabilities(ops: &dyn Ops, settings: &Settings) -> Capabilities {
    let mut caps = Capabilities::none();
    caps.issues.extend(firewall(ops));
    let station = match find_station(ops, settings) {
        Ok(s) => s,
        Err(m) => {
            caps.missing.push(m);
            return caps;
        }
    };
    caps.hardware = true;
    caps.station = Some(station.name.clone());
    caps.driver = Some(station.driver.clone());
    caps.device = station.device.clone();
    caps.status = Some(station.quirk.status);
    caps.mode = Some(station.quirk.mode);
    let card = card(ops, &station);
    caps.card = card.clone();
    caps.issues
        .splice(0..0, station.quirk.issues.iter().cloned());
    let Some(card) = &card else {
        caps.missing.push(missing(
            "backend",
            format!("Owly can't read what {} can do from nl80211.", station.name),
        ));
        return caps;
    };
    if let Some(m) = mode_problem(&station, settings, card) {
        caps.missing.push(m);
        return caps;
    }
    match station.quirk.mode {
        Mode::Shared => match ops.link_freq(&station.name) {
            None => caps.missing.push(missing(
                "radio",
                "Wi-Fi isn't connected, and AirDrop shares its channel. Connect to Wi-Fi first.",
            )),
            Some(f) => match social_channel(f) {
                Some(c) => caps.channel = Some(c),
                None => caps.missing.push(missing("radio", wrong_channel(f))),
            },
        },
        Mode::Exclusive | Mode::ActiveMonitor => {
            let freqs = station.tx_channels(settings);
            caps.channel = freqs.first().and_then(|f| social_channel(*f));
            if caps.channel == Some(6) {
                caps.issues.push(
                    "AirDrop runs on channel 6 here, where it gets one or two of the iPhone's sixteen slots, so transfers are slow: a 2.4 MB photo takes 10-17 s.".into(),
                );
            }
            let pending = settings
                .country
                .as_ref()
                .is_some_and(|c| card.regdom.as_ref() != Some(c) && !card.self_managed_reg);
            if freqs.is_empty() && !pending {
                caps.missing
                    .push(missing("radio", no_channel(settings, card)));
            }
        }
    }
    caps
}

/// What the card lacks for the mode its quirks ask for.
fn mode_problem(station: &Station, settings: &Settings, card: &Card) -> Option<Missing> {
    match station.quirk.mode {
        Mode::Shared if !card.monitor_beside_station => Some(missing(
            "hardware",
            "This Wi-Fi card can't run a monitor interface beside its station, which shared mode needs.",
        )),
        Mode::Exclusive if !card.ibss && !card.ap => Some(missing(
            "hardware",
            "This Wi-Fi card has neither ad-hoc mode nor an AP mode, so it can't run exclusive mode.",
        )),
        Mode::Exclusive if !card.ibss && !settings.hostapd.exists() => Some(missing(
            "backend",
            format!(
                "This Wi-Fi card has no ad-hoc mode, so exclusive mode runs a hidden AP, which needs hostapd ({}). Install hostapd.",
                settings.hostapd.display()
            ),
        )),
        Mode::ActiveMonitor if !card.active_monitor => Some(missing(
            "hardware",
            "This Wi-Fi card's quirks ask for active-monitor mode, but the card doesn't support an active monitor.",
        )),
        _ => None,
    }
}

fn no_channel(settings: &Settings, card: &Card) -> String {
    let mut say = "This Wi-Fi card may not transmit on any of AirDrop's channels (6, 44, 149) here"
        .to_string();
    if settings.channels.is_some() {
        say.push_str(" that /etc/owly/radio.toml allows");
    }
    say.push('.');
    if card.regdom.as_deref() == Some("00") && !card.self_managed_reg {
        say.push_str(
            " The kernel's regulatory domain is the world's, which allows little; set country in /etc/owly/radio.toml to where you are.",
        );
    }
    say
}

/// A host firewall that drops the receiver's port leaves the phone with
/// nothing to show (NET-4). ufw's settings file is readable by anyone; its
/// rules aren't, so this can only say it's on.
fn firewall(ops: &dyn Ops) -> Option<String> {
    let conf = ops.read(Path::new("/etc/ufw/ufw.conf"))?;
    conf.lines()
        .any(|l| l.trim() == "ENABLED=yes")
        .then(|| {
            "UFW is on. Unless it allows TCP 8771 from fe80::/10 on awdl0, it blocks the AirDrop receiver and the phone never sees this computer (`omdrop firewall install` adds the rule).".to_string()
        })
}

pub fn missing(id: &'static str, say: impl Into<String>) -> Missing {
    Missing {
        id,
        say: say.into(),
    }
}

pub fn wrong_channel(freq: u32) -> String {
    format!(
        "Your Wi-Fi network is on {freq} MHz, but AirDrop can only share channel 6, 44 or 149 with it. Moving the router to one of those makes this work."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quirks::Quirks;

    // spec: AWDL-11
    #[test]
    fn only_the_social_channels() {
        assert_eq!(social_channel(2437), Some(6));
        assert_eq!(social_channel(5220), Some(44));
        assert_eq!(social_channel(5745), Some(149));
        for f in [2412, 5180, 5300, 5240] {
            assert_eq!(social_channel(f), None, "{f}");
        }
        assert_eq!(social_freq(149), Some(5745));
        assert_eq!(social_freq(36), None);
    }

    struct MockStation {
        name: &'static str,
        driver: &'static str,
        device: Option<&'static str>,
        phy: &'static str,
        link_freq: Option<u32>,
        wiphy: Option<Wiphy>,
    }

    struct MockOps {
        stations: Vec<MockStation>,
    }

    impl Ops for MockOps {
        fn wifi_interfaces(&self) -> Vec<String> {
            self.stations.iter().map(|s| s.name.into()).collect()
        }
        fn iface_type(&self, iface: &str) -> Option<String> {
            self.exists(iface).then(|| "managed".into())
        }
        fn driver(&self, iface: &str) -> Option<String> {
            self.stations
                .iter()
                .find(|s| s.name == iface)
                .map(|s| s.driver.into())
        }
        fn device_id(&self, iface: &str) -> Option<String> {
            self.stations
                .iter()
                .find(|s| s.name == iface)
                .and_then(|s| s.device.map(str::to_string))
        }
        fn phy(&self, iface: &str) -> Option<String> {
            self.stations
                .iter()
                .find(|s| s.name == iface)
                .map(|s| s.phy.into())
        }
        fn wiphy(&self, phy: &str) -> Option<Wiphy> {
            self.stations
                .iter()
                .find(|s| s.phy == phy)
                .and_then(|s| s.wiphy.clone())
        }
        fn mac(&self, _iface: &str) -> Option<crate::radio::MacAddr> {
            None
        }
        fn index(&self, _iface: &str) -> Option<u32> {
            None
        }
        fn exists(&self, iface: &str) -> bool {
            self.stations.iter().any(|s| s.name == iface)
        }
        fn link_freq(&self, iface: &str) -> Option<u32> {
            self.stations
                .iter()
                .find(|s| s.name == iface)
                .and_then(|s| s.link_freq)
        }
        fn gateway_reachable(&self, _iface: &str) -> bool {
            false
        }
        fn regdom(&self) -> Option<String> {
            None
        }
        fn set_regdom(&self, _alpha2: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn add_iface(
            &self,
            _phy: &str,
            _name: &str,
            _kind: crate::nl80211::Kind,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn del_iface(&self, _name: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn set_kind(&self, _iface: &str, _kind: crate::nl80211::Kind) -> std::io::Result<()> {
            Ok(())
        }
        fn set_mac(&self, _iface: &str, _mac: crate::radio::MacAddr) -> std::io::Result<()> {
            Ok(())
        }
        fn set_up(&self, _iface: &str, _up: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn set_freq(&self, _iface: &str, _freq: u32) -> std::io::Result<()> {
            Ok(())
        }
        fn join_ibss(&self, _iface: &str, _freq: u32) -> std::io::Result<()> {
            Ok(())
        }
        fn leave_ibss(&self, _iface: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn sysctl(&self, _key: &str, _value: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn mt76_dir(&self, phy: &str) -> std::path::PathBuf {
            std::path::PathBuf::from(phy)
        }
        fn read(&self, _path: &Path) -> Option<String> {
            None
        }
        fn write(&self, _path: &Path, _value: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn set_managed(&self, _iface: &str, _managed: bool) {}
        fn nm_connection(&self, _station: &str) -> Option<String> {
            None
        }
        fn connection_up(&self, _uuid: &str, _station: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn reconnect(&self, _station: &str) {}
        fn sleep(&self, _d: std::time::Duration) {}
    }

    fn ch(freq: u32) -> crate::nl80211::Channel {
        crate::nl80211::Channel {
            freq,
            disabled: false,
            no_ir: false,
            radar: false,
        }
    }

    fn settings_with(quirks: Quirks, station: Option<&str>) -> Settings {
        Settings {
            station: station.map(str::to_string),
            allow_untested: false,
            reconnect_after: None,
            country: None,
            channels: None,
            aggregation: None,
            tx_rate: None,
            tx_amsdu: false,
            hostapd: std::path::PathBuf::from("/usr/bin/hostapd"),
            quirks,
            run_dir: RunDir::new(Path::new("/tmp")),
        }
    }

    #[test]
    fn prefers_unassociated_5ghz_usb_dongle_over_associated_onboard_card() {
        let ops = MockOps {
            stations: vec![
                MockStation {
                    name: "wlo1",
                    driver: "iwlwifi",
                    device: Some("8086:7af0"),
                    phy: "phy0",
                    link_freq: Some(5220),
                    wiphy: Some(Wiphy {
                        channels: vec![ch(2437), ch(5220), ch(5745)],
                        ..Wiphy::default()
                    }),
                },
                MockStation {
                    name: "wlx9cefd5f73ae2",
                    driver: "mt76x2u",
                    device: Some("0e8d:7612"),
                    phy: "phy3",
                    link_freq: None,
                    wiphy: Some(Wiphy {
                        active_monitor: true,
                        channels: vec![ch(2437), ch(5220), ch(5745)],
                        ..Wiphy::default()
                    }),
                },
            ],
        };
        let quirks = Quirks::load(Path::new("/nonexistent-owly-overrides")).unwrap();
        let chosen = find_station(&ops, &settings_with(quirks.clone(), None)).unwrap();
        assert_eq!(chosen.name, "wlx9cefd5f73ae2");

        // Explicit station override still wins unconditionally.
        let forced = find_station(&ops, &settings_with(quirks, Some("wlo1"))).unwrap();
        assert_eq!(forced.name, "wlo1");
    }

    #[test]
    fn prefers_tested_dongle_over_untested_or_broken_first_card() {
        let quirks = Quirks::parse(
            r#"
            [drivers.broken_first]
            status = "broken"
            mode = "exclusive"
            [drivers.mt76x2u]
            status = "tested"
            mode = "active-monitor"
            channels = [149, 44, 6]
            [drivers."*"]
            status = "untested"
            mode = "shared"
            "#,
        )
        .unwrap();
        let ops = MockOps {
            stations: vec![
                MockStation {
                    name: "wlan0",
                    driver: "broken_first",
                    device: None,
                    phy: "phy0",
                    link_freq: None,
                    wiphy: Some(Wiphy {
                        channels: vec![ch(2437)],
                        ..Wiphy::default()
                    }),
                },
                MockStation {
                    name: "wlan1",
                    driver: "mt76x2u",
                    device: Some("0e8d:7612"),
                    phy: "phy1",
                    link_freq: Some(5745),
                    wiphy: Some(Wiphy {
                        active_monitor: true,
                        channels: vec![ch(2437), ch(5745)],
                        ..Wiphy::default()
                    }),
                },
            ],
        };
        let chosen = find_station(&ops, &settings_with(quirks, None)).unwrap();
        assert_eq!(chosen.name, "wlan1");
    }

    #[test]
    fn unreadable_wiphy_does_not_get_a_5ghz_bonus() {
        let quirks = Quirks::parse(
            r#"
            [drivers.known]
            status = "tested"
            mode = "active-monitor"
            channels = [149, 6]
            [drivers.unreadable]
            status = "tested"
            mode = "active-monitor"
            channels = [149, 6]
            [drivers."*"]
            status = "untested"
            mode = "shared"
            "#,
        )
        .unwrap();
        let ops = MockOps {
            stations: vec![
                MockStation {
                    name: "wlan0",
                    driver: "known",
                    device: None,
                    phy: "phy0",
                    link_freq: None,
                    wiphy: Some(Wiphy {
                        channels: vec![ch(2437)],
                        ..Wiphy::default()
                    }),
                },
                MockStation {
                    name: "wlan1",
                    driver: "unreadable",
                    device: None,
                    phy: "phy1",
                    link_freq: None,
                    wiphy: None,
                },
            ],
        };

        let chosen = find_station(&ops, &settings_with(quirks, None)).unwrap();
        assert_eq!(chosen.name, "wlan0");
    }
}
