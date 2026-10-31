//! `/etc/owly/radio.toml`: how the radio is set up on this machine.
//!
//! ```toml
//! station = "wlan0"        # the Wi-Fi interface to use; else the first station
//! allow_untested = false   # run on a card the quirks table doesn't mark tested
//! reconnect_after = true   # overrides the driver's reconnect_after_monitor
//! country = "DE"           # exclusive modes: the regulatory domain to ask for
//! channels = [6]           # exclusive modes: overrides the driver's channel order
//! aggregation = true       # overrides the driver's rx_ampdu: accept the phone's Block Ack session
//! tx_rate = "mcs7"         # the data frame rate
//! hostapd = "/usr/sbin/hostapd" # for a hidden AP, on cards with no ad-hoc mode; else found on PATH
//! tx_amsdu = true          # send unicast as A-MSDUs where the peer takes them
//! election_metric = 550    # overrides the sync master election metric (default 60)
//! ```
//!
//! `country` matters where the kernel's regulatory domain is the world's
//! (`00`), which allows no transmitting on 5 GHz: exclusive mode asks for it
//! and waits for the kernel to apply it before choosing a channel. Shared
//! mode follows the AP's.

use std::path::{Path, PathBuf};

use owly_awdl::TxRate;
use serde::Deserialize;

use crate::injection::Settings;
use crate::quirks::{self, Quirks};
use crate::rundir::RunDir;

pub const CONFIG: &str = "/etc/owly/radio.toml";

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub station: Option<String>,
    #[serde(default)]
    pub allow_untested: bool,
    pub reconnect_after: Option<bool>,
    pub country: Option<String>,
    pub channels: Option<Vec<u8>>,
    pub aggregation: Option<bool>,
    pub tx_rate: Option<String>,
    pub hostapd: Option<PathBuf>,
    #[serde(default)]
    pub tx_amsdu: bool,
    pub election_metric: Option<u32>,
}

impl Config {
    /// The file at `path`, or the defaults when there's none.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// The injection backend's settings, with the quirks table and its
    /// overrides from `/etc/owly`.
    pub fn settings(self, run_dir: RunDir) -> Result<Settings, String> {
        if let Some(c) = &self.country
            && !(c.len() == 2
                && c.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
        {
            return Err(format!(
                "{CONFIG}: country is a two-letter code in capitals, such as \"DE\", not {c:?}"
            ));
        }
        let tx_rate = match &self.tx_rate {
            Some(r) => Some(TxRate::parse(r).ok_or_else(|| {
                format!(
                    "{CONFIG}: tx_rate is a rate in Mbit/s (6, 9, 12, 18, 24, 36, 48 or 54), or mcs0 to mcs15 with an optional -sgi, not {r:?}"
                )
            })?),
            None => None,
        };
        if let Some(c) = self
            .channels
            .iter()
            .flatten()
            .find(|c| ![6, 44, 149].contains(*c))
        {
            return Err(format!(
                "{CONFIG}: channel {c} isn't one of AirDrop's (6, 44, 149)"
            ));
        }
        Ok(Settings {
            station: self.station,
            allow_untested: self.allow_untested,
            reconnect_after: self.reconnect_after,
            country: self.country,
            channels: self.channels,
            aggregation: self.aggregation,
            tx_rate,
            tx_amsdu: self.tx_amsdu,
            hostapd: self.hostapd.unwrap_or_else(crate::injection::hostapd),
            quirks: Quirks::load(Path::new(quirks::OVERRIDES))?,
            run_dir,
            election_metric: self.election_metric,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_means_defaults() {
        assert_eq!(
            Config::load(Path::new("/nonexistent/radio.toml")).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn reads_its_keys_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("radio.toml");
        std::fs::write(&path, "station = \"wlan1\"\nallow_untested = true\n").unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.station.as_deref(), Some("wlan1"));
        assert!(config.allow_untested);
        assert_eq!(config.reconnect_after, None);
        std::fs::write(&path, "stations = \"wlan1\"\n").unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn values_are_checked() {
        let run = RunDir::new("/nonexistent");
        let bad = Config {
            country: Some("de".into()),
            ..Config::default()
        };
        assert!(bad.settings(run.clone()).is_err());
        let bad = Config {
            channels: Some(vec![6, 36]),
            ..Config::default()
        };
        assert!(bad.settings(run.clone()).is_err());
        let good = Config {
            country: Some("DE".into()),
            channels: Some(vec![149, 6]),
            ..Config::default()
        };
        let s = good.settings(run.clone()).unwrap();
        assert_eq!(s.hostapd, crate::injection::hostapd());
        let bad = Config {
            tx_rate: Some("mcs20".into()),
            ..Config::default()
        };
        assert!(bad.settings(run).is_err());
    }

    #[test]
    fn election_metric_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("radio.toml");
        std::fs::write(&path, "election_metric = 550\n").unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.election_metric, Some(550));
        let run = RunDir::new("/nonexistent");
        let s = config.settings(run).unwrap();
        assert_eq!(s.election_metric, Some(550));
    }
}
