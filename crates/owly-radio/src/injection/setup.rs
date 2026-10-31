//! Each mode's setup, up to starting AWDL: blocking steps on [`Ops`], each
//! recorded in the journal before it's made. A setup that fails undoes
//! itself from the journal.

use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use owly_awdl::{Channel, Presence, RadioConstraints};

use crate::radio::{Announce, Error, MacAddr};

use super::{AP, IBSS, MONITOR, Settings};
use crate::journal::{Journal, Step};
use crate::nl80211::{IfType, Kind};
use crate::probe::{self, Station, social_channel};
use crate::quirks::Mode;
use crate::rundir::Process;
use crate::sys::Ops;

/// What a setup leaves for AWDL.
pub(crate) struct Prepared {
    pub mode: Mode,
    /// What to start owly-awdl with.
    pub awdl: owly_awdl::Config,
    pub announce: Announce,
    /// The hidden AP's hostapd, when the mode runs one.
    pub hostapd: Option<Child>,
}

/// Sets the radio up in the station's mode. Undoes what it did if a step
/// fails.
pub(crate) fn prepare(
    ops: &dyn Ops,
    settings: &Settings,
    journal: &mut Journal,
) -> Result<Prepared, Error> {
    let station = probe::find_station(ops, settings).map_err(|m| Error::no_radio(m.say))?;
    let mut s = Setup {
        ops,
        settings,
        journal,
        station,
    };
    let result = match s.station.quirk.mode {
        Mode::Shared | Mode::FirmwareMonitorShared => s.shared(),
        Mode::Exclusive | Mode::ActiveMonitor | Mode::FirmwareMonitor => s.exclusive(),
    };
    result.inspect_err(|_| {
        if let Err(stuck) = s.journal.undo(ops) {
            tracing::error!("{stuck}");
        }
    })
}

struct Setup<'a> {
    ops: &'a dyn Ops,
    settings: &'a Settings,
    journal: &'a mut Journal,
    station: Station,
}

impl Setup<'_> {
    fn record(&mut self, step: Step) -> Result<(), Error> {
        self.journal.record(step).map_err(|e| {
            Error::no_radio(format!(
                "Can't record the radio's changes in {}: {e}",
                self.settings.run_dir.path().display()
            ))
        })
    }

    fn station_mac(&self) -> Result<MacAddr, Error> {
        self.ops
            .mac(&self.station.name)
            .ok_or_else(|| Error::no_radio(format!("{} has no MAC address.", self.station.name)))
    }

    /// Shared mode: AWDL on the AP's channel, with the station left
    /// associated. A monitor interface carries the station's MAC, and the
    /// station ACKs the phone's unicast.
    fn shared(&mut self) -> Result<Prepared, Error> {
        let ops = self.ops;
        let name = self.station.name.clone();
        // Wi-Fi takes a few seconds after a driver reload to associate and
        // get an address; don't judge a link that's still coming up.
        let mut freq = None;
        for _ in 0..15 {
            freq = ops.link_freq(&name);
            if freq.is_some() && ops.gateway_reachable(&name) {
                break;
            }
            freq = None;
            ops.sleep(Duration::from_secs(1));
        }
        let Some(freq) = freq else {
            return Err(Error::not_now(
                "Wi-Fi isn't connected (or isn't passing traffic), and AirDrop shares its channel. Connect to Wi-Fi and try again.",
            ));
        };
        let channel =
            social_channel(freq).ok_or_else(|| Error::not_now(probe::wrong_channel(freq)))?;
        let sta_mac = self.station_mac()?;

        if self
            .settings
            .reconnect_after
            .unwrap_or(self.station.quirk.reconnect_after_monitor)
        {
            self.record(Step::Reconnect {
                station: name.clone(),
            })?;
        }
        // Before the monitor, so teardown deletes the monitor first and
        // then gives power management back.
        self.mt76()?;
        // On the station's MAC, the address the phone sends to.
        self.monitor(Kind::Monitor { active: false }, sta_mac)?;
        tracing::info!(
            station = %name, driver = %self.station.driver, channel,
            "shared mode on {name} ({freq} MHz)"
        );
        let radio = RadioConstraints {
            channel: Channel(channel),
            presence: Presence::Share,
        };
        Ok(self.finish(
            self.station.quirk.mode,
            radio,
            sta_mac,
            Announce::SHARED,
            None,
        ))
    }

    /// Exclusive and active-monitor modes: the station off the air, and
    /// AWDL alone on one channel the card may transmit on.
    fn exclusive(&mut self) -> Result<Prepared, Error> {
        let ops = self.ops;
        let name = self.station.name.clone();
        let mode = self.station.quirk.mode;
        let sta_mac = self.station_mac()?;
        // Without a regulatory domain to ask for, the channels the card may
        // use are known now: don't take Wi-Fi down for none.
        if self.settings.country.is_none() && self.station.tx_channels(self.settings).is_empty() {
            return Err(no_channels());
        }

        // What to reconnect to afterwards; it has to be read while
        // connected. NetworkManager has to let go of the station, or it
        // brings it straight back.
        let connection = ops.nm_connection(&name);
        self.record(Step::Station {
            station: name.clone(),
            connection,
        })?;
        ops.set_managed(&name, false);
        ops.set_up(&name, false)
            .map_err(|e| Error::no_radio(format!("Couldn't take {name} down: {e}")))?;
        // Before the interfaces, so teardown gives power management back
        // once they're gone.
        self.mt76()?;

        self.regdom()?;
        let freqs = self.station.tx_channels(self.settings);
        if freqs.is_empty() {
            return Err(no_channels());
        }

        let mut hostapd = None;
        let freq = if mode == Mode::ActiveMonitor {
            self.active_monitor(sta_mac, &freqs)?
        } else if mode == Mode::FirmwareMonitor {
            self.firmware_monitor(sta_mac, &freqs)?
        } else {
            let freq = if self.station.has(IfType::Adhoc) {
                self.ibss_cell(sta_mac, &freqs)?
            } else {
                let (freq, child) = self.ap_cell(sta_mac, &freqs)?;
                hostapd = Some(child);
                freq
            };
            self.monitor(Kind::Monitor { active: false }, sta_mac)?;
            freq
        };
        let channel = social_channel(freq).expect("a social channel");
        tracing::info!(
            station = %name, driver = %self.station.driver, channel,
            "{mode} mode on channel {channel}"
        );
        // Our one channel in every slot, which is where we are, rather than
        // only the slots the phone gives it, which move while the phone
        // makes room for us.
        let radio = RadioConstraints {
            channel: Channel(channel),
            presence: Presence::Fixed,
        };
        Ok(self.finish(mode, radio, sta_mac, Announce::FIXED, hostapd))
    }

    /// AWDL on `radio`, on the station's MAC (AWDL-2), named after the
    /// host, with Block Ack, rate and A-MSDUs as radio.toml and the
    /// driver's quirks say. Unicast goes without ACKs on a fixed radio, as
    /// legacy sent it (patch `owl-05`), unless the driver's
    /// `tx_noack` says otherwise.
    fn finish(
        &self,
        mode: Mode,
        radio: RadioConstraints,
        addr: MacAddr,
        announce: Announce,
        hostapd: Option<Child>,
    ) -> Prepared {
        let name = self
            .ops
            .read(Path::new("/proc/sys/kernel/hostname"))
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "owly".into());
        let mut awdl = owly_awdl::Config::new(addr, &name, radio);
        if let Some(rate) = self.settings.tx_rate {
            awdl.rate = rate;
        }
        awdl.accept_addba = self
            .settings
            .aggregation
            .unwrap_or(self.station.quirk.rx_ampdu);
        if let Some(no_ack) = self.station.quirk.tx_noack {
            awdl.no_ack = no_ack;
        }
        awdl.amsdu = self.settings.tx_amsdu;
        Prepared {
            mode,
            awdl,
            announce,
            hostapd,
        }
    }

    /// Adds the monitor interface AWDL injects through.
    fn monitor(&mut self, kind: Kind, mac: MacAddr) -> Result<(), Error> {
        let ops = self.ops;
        if ops.exists(MONITOR) {
            let _ = ops.del_iface(MONITOR);
        }
        self.record(Step::Interface {
            name: MONITOR.into(),
        })?;
        if let Err(e) = ops.add_iface(&self.station.phy, MONITOR, kind) {
            // Not there, so undoing mustn't take it for one that vanished
            // and reconnect the station.
            let _ = self.journal.discard_last();
            return Err(Error::no_radio(format!(
                "Couldn't add a monitor interface to {}: {e}",
                self.station.name
            )));
        }
        ops.set_managed(MONITOR, false);
        if let Err(e) = ops.set_mac(MONITOR, mac)
            && ops.mac(MONITOR) != Some(mac)
        {
            return Err(Error::no_radio(format!(
                "Couldn't give the monitor interface the station's MAC address: {e}"
            )));
        }
        ops.set_up(MONITOR, true)
            .map_err(|e| Error::no_radio(format!("Couldn't bring up the monitor interface: {e}")))
    }

    /// mt76's runtime power management off for the session, where the
    /// quirks ask.
    fn mt76(&mut self) -> Result<(), Error> {
        if !self.station.quirk.mt76_pm_off {
            return Ok(());
        }
        let ops = self.ops;
        let dir = ops.mt76_dir(&self.station.phy);
        let runtime_pm = ops.read(&dir.join("runtime-pm"));
        let deep_sleep = ops.read(&dir.join("deep-sleep"));
        let (Some(runtime_pm), Some(deep_sleep)) = (runtime_pm, deep_sleep) else {
            tracing::warn!("can't read mt76's power management in {}", dir.display());
            return Ok(());
        };
        self.record(Step::Mt76 {
            dir: dir.clone(),
            runtime_pm,
            deep_sleep,
        })?;
        let _ = ops.write(&dir.join("runtime-pm"), "0");
        let _ = ops.write(&dir.join("deep-sleep"), "0");
        Ok(())
    }

    /// Asks for `country`'s regulatory domain and waits for the kernel to
    /// apply it, then reads the channels it allows. A driver that manages
    /// its own (Intel's LAR) ignores the request, so it isn't made.
    fn regdom(&mut self) -> Result<(), Error> {
        let Some(country) = self.settings.country.clone() else {
            return Ok(());
        };
        let ops = self.ops;
        let self_managed = self
            .station
            .wiphy
            .as_ref()
            .is_some_and(|w| w.self_managed_reg);
        let current = ops.regdom();
        if self_managed || current.as_deref() == Some(country.as_str()) {
            return Ok(());
        }
        self.record(Step::Regdom {
            alpha2: current.unwrap_or_else(|| "00".into()),
        })?;
        ops.set_regdom(&country).map_err(|e| {
            Error::no_radio(format!(
                "Couldn't set the regulatory domain to {country}: {e}"
            ))
        })?;
        let end = Instant::now() + Duration::from_secs(5);
        while ops.regdom().as_deref() != Some(country.as_str()) {
            if Instant::now() >= end {
                tracing::warn!("the kernel didn't apply regulatory domain {country} in 5 s");
                break;
            }
            ops.sleep(Duration::from_millis(100));
        }
        self.station.wiphy = ops.wiphy(&self.station.phy);
        Ok(())
    }

    /// An ad-hoc cell on AWDL's BSSID in the station's place. Joining that
    /// "IBSS" gives the firmware an address to ACK for and a BSSID filter
    /// that passes AWDL, and mac80211 a station entry per peer, so unicast
    /// is sent, retried and ACKed the ordinary way; a monitor alone on the
    /// AX201 never sees an ACK. The cell is HT, since an iPhone sends its
    /// unicast at HT rates, which a non-HT cell neither receives nor ACKs.
    /// Cards that refuse an ad-hoc interface beside the station, even down
    /// (some AX211s), get the station itself made the cell. Returns the
    /// frequency it started on.
    fn ibss_cell(&mut self, mac: MacAddr, freqs: &[u32]) -> Result<u32, Error> {
        let ops = self.ops;
        let name = self.station.name.clone();
        if ops.exists(IBSS) {
            let _ = ops.del_iface(IBSS);
        }
        self.record(Step::Interface { name: IBSS.into() })?;
        let cell = match ops.add_iface(&self.station.phy, IBSS, Kind::Adhoc) {
            Ok(()) => {
                ops.set_managed(IBSS, false);
                cell_mac(ops, IBSS, mac);
                IBSS.to_string()
            }
            Err(e) => {
                tracing::info!(
                    "{} refuses an ad-hoc interface beside its station ({e}); making {name} the cell",
                    self.station.phy
                );
                let key = format!("net/ipv6/conf/{name}/disable_ipv6");
                let was = ops
                    .read(&Path::new("/proc/sys").join(&key))
                    .unwrap_or_else(|| "0".into());
                self.record(Step::Ipv6 {
                    iface: name.clone(),
                    disable_ipv6: was,
                })?;
                self.record(Step::StationType {
                    station: name.clone(),
                })?;
                ops.set_kind(&name, Kind::Adhoc).map_err(|e| {
                    Error::no_radio(format!("Couldn't make {name} an ad-hoc cell: {e}"))
                })?;
                name.clone()
            }
        };
        // IP runs on awdl0. Left alone, the kernel and avahi take the cell
        // for a network too and send plain IPv6 on AWDL's BSSID.
        let _ = ops.sysctl(&format!("net/ipv6/conf/{cell}/disable_ipv6"), "1");
        ops.set_up(&cell, true)
            .map_err(|e| Error::no_radio(format!("Couldn't bring {cell} up: {e}")))?;
        for &f in freqs {
            if let Err(e) = ops.join_ibss(&cell, f) {
                tracing::info!("no ad-hoc cell on {f} MHz: {e}");
                continue;
            }
            // mac80211 scans the channel once before it starts the cell.
            if self.wait(Duration::from_secs(10), || ops.link_freq(&cell) == Some(f)) {
                return Ok(f);
            }
            tracing::info!("the ad-hoc cell on {f} MHz didn't start");
            let _ = ops.leave_ibss(&cell);
        }
        Err(Error::no_radio(
            "Couldn't start AWDL's ad-hoc cell on any of AirDrop's channels.",
        ))
    }

    /// The cell on a card without ad-hoc mode: a hidden AP on the station's
    /// MAC, run by hostapd. It beacons every 1000 TU rather than the cell's
    /// 10000: the RTL8852BU's driver holds starting and stopping an AP for
    /// its beacons, so 10 s beacons made a start take 21.6 s and a stop 15 s.
    fn ap_cell(&mut self, mac: MacAddr, freqs: &[u32]) -> Result<(u32, Child), Error> {
        let ops = self.ops;
        let hostapd = self.settings.hostapd.clone();
        if !hostapd.exists() {
            return Err(Error::no_radio(format!(
                "This Wi-Fi card has no ad-hoc mode, and there's no hostapd ({}) to run a hidden AP instead.",
                hostapd.display()
            )));
        }
        if ops.exists(AP) {
            let _ = ops.del_iface(AP);
        }
        self.record(Step::Interface { name: AP.into() })?;
        ops.add_iface(&self.station.phy, AP, Kind::Ap)
            .map_err(|e| Error::no_radio(format!("Couldn't add the AP interface {AP}: {e}")))?;
        cell_mac(ops, AP, mac);
        let _ = ops.sysctl(&format!("net/ipv6/conf/{AP}/disable_ipv6"), "1");
        ops.set_managed(AP, false);
        let run = &self.settings.run_dir;
        let conf = run.file("hostapd.conf");
        let log = run.file("hostapd.log");
        for &f in freqs {
            let channel = social_channel(f).expect("a social channel");
            write_hostapd_conf(&conf, channel)
                .map_err(|e| Error::no_radio(format!("{}: {e}", conf.display())))?;
            let mut child = spawn_hostapd(&hostapd, &conf, &log)
                .map_err(|e| Error::no_radio(format!("Couldn't start hostapd: {e}")))?;
            let process = Process::of(child.id())
                .ok_or_else(|| Error::no_radio("hostapd exited at once."))?;
            self.record(Step::Process {
                what: "hostapd".into(),
                process,
            })?;
            let started = self.wait(Duration::from_secs(5), || {
                matches!(child.try_wait(), Ok(None)) && ops.link_freq(AP) == Some(f)
            });
            if started {
                return Ok((f, child));
            }
            tracing::info!("no hidden AP on {f} MHz");
            process.stop(Duration::from_secs(2));
            let _ = child.wait();
        }
        Err(Error::no_radio(
            "Couldn't start the hidden AP on any of AirDrop's channels.",
        ))
    }

    /// The active-monitor radio, for cards with neither ad-hoc mode nor
    /// injection while associated. The monitor is an active one, which ACKs
    /// unicast to its own address, so it carries the station's MAC and
    /// stands in for the cell. An active monitor alone accepted channel
    /// changes but stayed on its old channel (MT7612U, kernel 7.2), so the
    /// station becomes a passive monitor first, which gives mac80211 the
    /// channel context that makes them take effect; it's tuned too, since
    /// with only the active monitor set to 44 an MT7612U heard nothing.
    fn active_monitor(&mut self, mac: MacAddr, freqs: &[u32]) -> Result<u32, Error> {
        let ops = self.ops;
        let name = self.station.name.clone();
        self.record(Step::StationType {
            station: name.clone(),
        })?;
        ops.set_kind(&name, Kind::Monitor { active: false })
            .and_then(|()| ops.set_up(&name, true))
            .map_err(|e| Error::no_radio(format!("Couldn't make {name} a monitor: {e}")))?;
        self.monitor(Kind::Monitor { active: true }, mac)?;
        for &f in freqs {
            let _ = ops.set_freq(&name, f);
            match ops.set_freq(MONITOR, f) {
                Ok(()) => return Ok(f),
                Err(e) => tracing::info!("the active monitor can't tune to {f} MHz: {e}"),
            }
        }
        Err(Error::no_radio(
            "Couldn't tune the active monitor to any of AirDrop's channels.",
        ))
    }

    /// Nexmon's firmware supplies capture and injection through an ordinary
    /// monitor netdev. It has no mac80211 cell or active-monitor interface,
    /// so keep the station down and tune the monitor itself.
    fn firmware_monitor(&mut self, mac: MacAddr, freqs: &[u32]) -> Result<u32, Error> {
        self.monitor(Kind::Monitor { active: false }, mac)?;
        for &freq in freqs {
            match self.ops.set_freq(MONITOR, freq) {
                Ok(()) => return Ok(freq),
                Err(e) => tracing::info!("the firmware monitor can't tune to {freq} MHz: {e}"),
            }
        }
        Err(Error::no_radio(
            "Couldn't tune the firmware monitor to any of AirDrop's channels.",
        ))
    }

    /// Polls `done` every 50 ms for up to `limit`.
    fn wait(&self, limit: Duration, mut done: impl FnMut() -> bool) -> bool {
        let mut waited = Duration::ZERO;
        loop {
            if done() {
                return true;
            }
            if waited >= limit {
                return false;
            }
            self.ops.sleep(Duration::from_millis(50));
            waited += Duration::from_millis(50);
        }
    }
}

fn no_channels() -> Error {
    Error::no_radio(
        "This Wi-Fi card may not transmit on any of AirDrop's channels (6, 44, 149) here.",
    )
}

/// Gives the cell or hidden AP the station's MAC, the address the phone
/// sends to, so it ACKs the phone's unicast. A cell left on a MAC of its
/// own still lets the monitor hear everything, only unACKed, so a driver
/// that refuses gets a warning rather than no radio, as in legacy.
fn cell_mac(ops: &dyn Ops, iface: &str, mac: MacAddr) {
    if let Err(e) = ops.set_mac(iface, mac) {
        tracing::warn!(
            "couldn't give {iface} the station's MAC {mac}, so it won't ACK the phone: {e}"
        );
    }
}

/// A hidden, WPA2-protected AP with a random name and passphrase, so
/// nothing ever joins it: it's there for its MAC to ACK the phone.
fn write_hostapd_conf(path: &Path, channel: u8) -> std::io::Result<()> {
    use std::io::Write;
    let mut random = [0u8; 20];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut random)?;
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let conf = format!(
        "interface={AP}\ndriver=nl80211\nssid=owly-{}\nignore_broadcast_ssid=1\nhw_mode={}\nchannel={channel}\nieee80211n=1\nbeacon_int=1000\nwpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase={}\n",
        hex(&random[..4]),
        if channel == 6 { "g" } else { "a" },
        hex(&random[4..]),
    );
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(conf.as_bytes())
}

/// hostapd in the foreground, in a process group of its own, logging to
/// `log`.
fn spawn_hostapd(binary: &Path, conf: &Path, log: &Path) -> std::io::Result<Child> {
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?;
    Command::new(binary)
        .arg(conf)
        .stdin(Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out)
        .process_group(0)
        .spawn()
}
