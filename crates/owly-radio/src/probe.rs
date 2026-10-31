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

/// The station: the one `/etc/owly/radio.toml` names, else the first
/// managed Wi-Fi interface. Refuses a card the quirks table doesn't mark
/// tested unless allowed.
pub fn find_station(ops: &dyn Ops, settings: &Settings) -> Result<Station, Missing> {
    let ours = [AWDL_IFACE, MONITOR, IBSS, AP];
    let name = match &settings.station {
        Some(s) if ops.exists(s) => Some(s.clone()),
        Some(_) => None,
        None => ops.wifi_interfaces().into_iter().find(|i| {
            !ours.contains(&i.as_str()) && ops.iface_type(i).as_deref() == Some("managed")
        }),
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
        Status::Untested => {
            return Err(missing(
                "hardware",
                format!(
                    "Owly hasn't been tested on this computer's Wi-Fi ({card}). To try it anyway, set allow_untested = true in /etc/owly/radio.toml, and please report how it goes."
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
        Mode::Shared | Mode::FirmwareMonitorShared => match ops.link_freq(&station.name) {
            None => caps.missing.push(missing(
                "radio",
                "Wi-Fi isn't connected, and AirDrop shares its channel. Connect to Wi-Fi first.",
            )),
            Some(f) => match social_channel(f) {
                Some(c) => caps.channel = Some(c),
                None => caps.missing.push(missing("radio", wrong_channel(f))),
            },
        },
        Mode::Exclusive | Mode::ActiveMonitor | Mode::FirmwareMonitor => {
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
        Mode::FirmwareMonitorShared if !station.has(IfType::Monitor) => Some(missing(
            "hardware",
            "This Wi-Fi driver doesn't expose a monitor interface. Install matching Nexmon-patched firmware and brcmfmac driver for this Raspberry Pi.",
        )),
        Mode::Shared | Mode::FirmwareMonitorShared if !card.monitor_beside_station => {
            Some(missing(
                "hardware",
                "This Wi-Fi card can't run a monitor interface beside its station, which shared mode needs.",
            ))
        }
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
        Mode::FirmwareMonitor if !station.has(IfType::Monitor) => Some(missing(
            "hardware",
            "This Wi-Fi driver doesn't expose a monitor interface. On a Raspberry Pi 5 or wireless CM5, install a compatible Nexmon-patched firmware and brcmfmac driver before using the onboard radio.",
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
}
