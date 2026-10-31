//! What's known about each Wi-Fi driver, and the odd device, that the probe
//! can't detect: `drivers.toml`, built in, with `/etc/owly/drivers.toml`
//! read over it.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

pub use crate::radio::Status;
use serde::{Deserialize, Serialize};

/// The packaged table.
pub const PACKAGED: &str = include_str!("../drivers.toml");

/// Where a machine's own entries go.
pub const OVERRIDES: &str = "/etc/owly/drivers.toml";

/// The entry for drivers the table doesn't list.
const FALLBACK: &str = "*";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Quirk {
    pub status: Status,
    pub mode: Mode,
    #[serde(default)]
    pub reconnect_after_monitor: bool,
    #[serde(default)]
    pub mt76_pm_off: bool,
    /// The social channels to try, in order, where the mode picks its own
    /// (exclusive and active monitor). Shared mode uses the AP's.
    #[serde(default = "default_channels")]
    pub channels: Vec<u8>,
    /// Accept the phone's Block Ack session (AWDL-15). Needs
    /// the hardware to answer A-MPDUs with a Block Ack itself.
    #[serde(default)]
    pub rx_ampdu: bool,
    /// Send unicast without waiting for the hardware's ACK. Unset, owly-awdl
    /// does where the radio is fixed to its channel (exclusive and active
    /// monitor), as legacy did, and not in shared mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_noack: Option<bool>,
    /// The driver can encode injected frames with LDPC. For owly-awdl's rate
    /// selection, which doesn't use it yet.
    #[serde(default)]
    pub supports_tx_ldpc: bool,
    /// Known problems on this hardware, one sentence each, for the person
    /// at the computer. The probe reports them.
    #[serde(default)]
    pub issues: Vec<String>,
    /// The hardware, and what was observed. For people reading the table.
    #[serde(default)]
    pub notes: String,
}

fn default_channels() -> Vec<u8> {
    vec![44, 149, 6]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// AWDL on the AP's channel, with Wi-Fi left connected.
    Shared,
    /// Wi-Fi down for the session, an ad-hoc cell or hidden AP in its place.
    Exclusive,
    /// Wi-Fi down for the session, an active monitor in its place.
    ActiveMonitor,
    /// Firmware-backed monitor injection on one fixed channel, without a
    /// mac80211 ad-hoc cell or active-monitor ACKs.
    FirmwareMonitor,
    /// Firmware-backed monitor injection beside an associated station.
    FirmwareMonitorShared,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Shared => "shared",
            Mode::Exclusive => "exclusive",
            Mode::ActiveMonitor => "active-monitor",
            Mode::FirmwareMonitor => "firmware-monitor",
            Mode::FirmwareMonitorShared => "firmware-monitor-shared",
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    drivers: BTreeMap<String, Quirk>,
    #[serde(default)]
    devices: BTreeMap<String, Quirk>,
}

/// Where an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The device's own, by PCI or USB ID.
    Device,
    Driver,
    /// Neither is listed.
    Fallback,
}

/// The quirks table: a machine's overrides over the packaged entries.
#[derive(Debug, Clone)]
pub struct Quirks {
    drivers: BTreeMap<String, Quirk>,
    devices: BTreeMap<String, Quirk>,
}

impl Quirks {
    /// The packaged table, under `overrides` if that file exists.
    pub fn load(overrides: &Path) -> Result<Self, String> {
        let mut quirks = Quirks::parse(PACKAGED).map_err(|e| format!("packaged quirks: {e}"))?;
        match std::fs::read_to_string(overrides) {
            Ok(text) => {
                let local =
                    Quirks::parse(&text).map_err(|e| format!("{}: {e}", overrides.display()))?;
                quirks.drivers.extend(local.drivers);
                quirks.devices.extend(local.devices);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", overrides.display())),
        }
        if !quirks.drivers.contains_key(FALLBACK) {
            return Err(format!("the quirks table has no \"{FALLBACK}\" entry"));
        }
        Ok(quirks)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let file: File = toml::from_str(text).map_err(|e| e.to_string())?;
        for (name, q) in file.drivers.iter().chain(&file.devices) {
            q.check().map_err(|e| format!("{name}: {e}"))?;
        }
        Ok(Quirks {
            drivers: file.drivers,
            devices: file.devices,
        })
    }

    /// The device's entry, else its driver's, else the fallback.
    pub fn get(&self, driver: &str, device: Option<&str>) -> (&Quirk, Source) {
        if let Some(q) = device.and_then(|d| self.devices.get(d)) {
            return (q, Source::Device);
        }
        match self.drivers.get(driver) {
            Some(q) if driver != FALLBACK => (q, Source::Driver),
            _ => (&self.drivers[FALLBACK], Source::Fallback),
        }
    }
}

impl Quirk {
    fn check(&self) -> Result<(), String> {
        if let Some(c) = self.channels.iter().find(|c| ![6, 44, 149].contains(*c)) {
            return Err(format!("channel {c} isn't one of AWDL's (6, 44, 149)"));
        }
        if self.channels.is_empty() {
            return Err("channels is empty".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packaged() -> Quirks {
        Quirks::load(Path::new("/nonexistent")).unwrap()
    }

    #[test]
    fn the_packaged_table_has_the_mt7925() {
        let quirks = packaged();
        let (q, source) = quirks.get("mt7925e", Some("14c3:0717"));
        assert_eq!(source, Source::Driver);
        assert_eq!(q.status, Status::Tested);
        assert_eq!(q.mode, Mode::Shared);
        assert!(q.reconnect_after_monitor && q.mt76_pm_off);

        let (q, source) = quirks.get("brcmfmac", None);
        assert_eq!(source, Source::Driver);
        assert_eq!(q.status, Status::Untested);
        assert_eq!(q.mode, Mode::FirmwareMonitorShared);
    }

    #[test]
    fn every_mode_legacy_ran_is_here() {
        let quirks = packaged();
        let (intel, _) = quirks.get("iwlwifi", Some("8086:51f0"));
        assert_eq!(
            (intel.status, intel.mode),
            (Status::Tested, Mode::Exclusive)
        );
        assert_eq!(intel.channels, [6], "no Intel card has held a 5 GHz cell");
        let (usb, _) = quirks.get("mt76x2u", None);
        assert_eq!(
            (usb.mode, usb.channels.clone()),
            (Mode::ActiveMonitor, vec![149, 44, 6])
        );
        assert!(usb.rx_ampdu, "legacy turned -A on there");
        let (mt7921, _) = quirks.get("mt7921e", None);
        assert_eq!(mt7921.mode, Mode::ActiveMonitor);
        assert_eq!(mt7921.channels, [6]);
        assert!(!mt7921.issues.is_empty());
    }

    #[test]
    fn devices_the_driver_entry_is_wrong_for() {
        let quirks = packaged();
        // The MT7927 runs on the MT7925's driver, but isn't heard.
        let (q, source) = quirks.get("mt7925e", Some("14c3:7927"));
        assert_eq!(source, Source::Device);
        assert_eq!(q.status, Status::Broken);
        assert!(q.issues[0].contains("issues/44"), "{:?}", q.issues);
        // Intel's known-bad firmware.
        for id in ["8086:095a", "8086:24f3"] {
            assert_eq!(quirks.get("iwlwifi", Some(id)).0.status, Status::Broken);
        }
    }

    #[test]
    fn overrides_replace_whole_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drivers.toml");
        std::fs::write(
            &path,
            r#"
            [drivers.mt7925e]
            status = "tested"
            mode = "shared"
            rx_ampdu = true
            "#,
        )
        .unwrap();
        let quirks = Quirks::load(&path).unwrap();
        let (q, _) = quirks.get("mt7925e", None);
        assert!(q.rx_ampdu);
        assert!(!q.reconnect_after_monitor);
        assert_eq!(q.channels, [44, 149, 6]);
        assert_eq!(q.notes, "");
    }

    #[test]
    fn mistakes_are_refused() {
        let text = r#"
            [drivers.x]
            status = "tested"
            mode = "shared"
            reconect_after_monitor = true
        "#;
        assert!(Quirks::parse(text).is_err(), "a typo");
        let ok = text.replace("reconect", "reconnect");
        assert!(Quirks::parse(&ok).is_ok());
        assert!(Quirks::parse(&ok.replace("shared", "sharde")).is_err());
        assert!(Quirks::parse(&format!("{ok}channels = [36]\n")).is_err());
        assert!(Quirks::parse(&ok.replace("shared", "active-monitor")).is_ok());
    }
}
