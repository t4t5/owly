//! The injection backend in each mode, against fake system operations, a
//! stand-in for AWDL and a fake hostapd: what it changes, in what order,
//! what it starts AWDL with, that it undoes it, and that a session whose
//! owner died is undone from the journal.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use owly_awdl::election::Ranking;
use owly_awdl::{Presence, TxRate};
use owly_radio::injection::{AP, Awdl, IBSS, Injection, MONITOR, Settings, StartAwdl};
use owly_radio::journal::Step;
use owly_radio::nl80211::{Channel, Combination, IfType, Kind, Wiphy};
use owly_radio::quirks::{Mode, Quirks, Status};
use owly_radio::radio::{Announce, Backend, ErrorKind, LinkState, MacAddr, PeerInfo};
use owly_radio::rundir::{Process, RunDir};
use owly_radio::sys::Ops;
use tokio::sync::watch;

const STATION: &str = "wlan0";
const STATION_MAC: &str = "aa:bb:cc:dd:ee:01";
const PHONE: &str = "86:08:04:8a:2b:f4";
const UUID: &str = "8d2c9f8e-1b4f-4d47-9a45-3b0c2a6f1e10";

struct Iface {
    kind: String,
    mac: MacAddr,
    freq: Option<u32>,
}

/// A Wi-Fi card with a station on `wlan0`, connected through
/// NetworkManager. `awdl0` exists once the stand-in AWDL has touched
/// `<dir>/awdl0`; the hidden AP is on the channel the fake hostapd writes
/// to `<dir>/hostapd.channel`.
struct FakeOps {
    dir: PathBuf,
    driver: String,
    device: Option<String>,
    wiphy: Mutex<Wiphy>,
    /// What the AP the station is associated with is on.
    freq: Option<u32>,
    regdom: Mutex<String>,
    /// The channels on which an ad-hoc cell starts.
    ibss_starts: Vec<u32>,
    /// The card refuses an ad-hoc interface beside its station.
    ibss_refused: bool,
    fail_monitor: bool,
    monitor_mac_locked: bool,
    fail_monitor_tune: bool,
    /// UFW is on.
    ufw: bool,
    /// NetworkManager reconnects by itself once it has the station back.
    autoconnect: bool,
    managed: Mutex<BTreeMap<String, bool>>,
    ifaces: Mutex<BTreeMap<String, Iface>>,
    calls: Mutex<Vec<String>>,
}

fn channel(freq: u32) -> Channel {
    Channel {
        freq,
        disabled: false,
        no_ir: false,
        radar: false,
    }
}

/// A card like the MT7925: station, IBSS, AP, monitor and an active one;
/// monitor counted as software; a station beside an IBSS or AP.
fn wiphy() -> Wiphy {
    Wiphy {
        index: 0,
        name: "phy0".into(),
        iftypes: vec![IfType::Adhoc, IfType::Station, IfType::Ap, IfType::Monitor],
        software: vec![IfType::Monitor],
        combinations: vec![Combination {
            limits: vec![
                (1, vec![IfType::Station]),
                (1, vec![IfType::Adhoc, IfType::Ap]),
            ],
            max: 2,
            channels: 1,
        }],
        active_monitor: true,
        self_managed_reg: false,
        channels: vec![channel(2437), channel(5220), channel(5745)],
    }
}

impl FakeOps {
    fn new(dir: &Path) -> Self {
        let mut ifaces = BTreeMap::new();
        ifaces.insert(
            STATION.to_string(),
            Iface {
                kind: "managed".into(),
                mac: STATION_MAC.parse().unwrap(),
                freq: Some(5220),
            },
        );
        FakeOps {
            dir: dir.to_path_buf(),
            driver: "mt7925e".into(),
            device: Some("14c3:0717".into()),
            wiphy: Mutex::new(wiphy()),
            freq: Some(5220),
            regdom: Mutex::new("DE".into()),
            ibss_starts: vec![2437, 5220, 5745],
            ibss_refused: false,
            fail_monitor: false,
            monitor_mac_locked: false,
            fail_monitor_tune: false,
            ufw: false,
            autoconnect: true,
            managed: Mutex::new(BTreeMap::new()),
            ifaces: Mutex::new(ifaces),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn call(&self, c: String) {
        self.calls.lock().unwrap().push(c);
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn awdl(&self) -> bool {
        self.dir.join("awdl0").exists()
    }

    fn kind(&self, iface: &str) -> Option<String> {
        self.ifaces
            .lock()
            .unwrap()
            .get(iface)
            .map(|i| i.kind.clone())
    }
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Station => "managed",
        Kind::Adhoc => "IBSS",
        Kind::Ap => "AP",
        Kind::Monitor { active: false } => "monitor",
        Kind::Monitor { active: true } => "active-monitor",
    }
}

impl Ops for FakeOps {
    fn wifi_interfaces(&self) -> Vec<String> {
        self.ifaces.lock().unwrap().keys().cloned().collect()
    }
    fn iface_type(&self, iface: &str) -> Option<String> {
        self.kind(iface).map(|k| {
            if k == "active-monitor" {
                "monitor".into()
            } else {
                k
            }
        })
    }
    fn driver(&self, _iface: &str) -> Option<String> {
        Some(self.driver.clone())
    }
    fn device_id(&self, _iface: &str) -> Option<String> {
        self.device.clone()
    }
    fn phy(&self, _iface: &str) -> Option<String> {
        Some("phy0".into())
    }
    fn wiphy(&self, _phy: &str) -> Option<Wiphy> {
        Some(self.wiphy.lock().unwrap().clone())
    }
    fn mac(&self, iface: &str) -> Option<MacAddr> {
        if iface == "awdl0" && self.awdl() {
            // The AWDL address: the monitor interface's in these tests.
            return self.mac(MONITOR);
        }
        self.ifaces.lock().unwrap().get(iface).map(|i| i.mac)
    }
    fn index(&self, iface: &str) -> Option<u32> {
        self.exists(iface).then_some(7)
    }
    fn exists(&self, iface: &str) -> bool {
        if iface == "awdl0" {
            return self.awdl();
        }
        self.ifaces.lock().unwrap().contains_key(iface)
    }
    fn link_freq(&self, iface: &str) -> Option<u32> {
        if iface == AP {
            let ch = std::fs::read_to_string(self.dir.join("hostapd.channel")).ok()?;
            return match ch.trim() {
                "6" => Some(2437),
                "44" => Some(5220),
                "149" => Some(5745),
                _ => None,
            };
        }
        self.ifaces.lock().unwrap().get(iface)?.freq
    }
    fn gateway_reachable(&self, iface: &str) -> bool {
        self.link_freq(iface).is_some()
    }
    fn regdom(&self) -> Option<String> {
        Some(self.regdom.lock().unwrap().clone())
    }
    fn set_regdom(&self, alpha2: &str) -> io::Result<()> {
        self.call(format!("regdom {alpha2}"));
        *self.regdom.lock().unwrap() = alpha2.into();
        // The world allows no transmitting on 5 GHz; anywhere else does.
        let world = alpha2 == "00";
        for c in &mut self.wiphy.lock().unwrap().channels {
            c.no_ir = world && c.freq > 5000;
        }
        Ok(())
    }
    fn add_iface(&self, phy: &str, name: &str, kind: Kind) -> io::Result<()> {
        self.call(format!("add {phy} {name} {}", kind_name(kind)));
        if self.fail_monitor && matches!(kind, Kind::Monitor { .. }) {
            return Err(io::Error::other("EOPNOTSUPP"));
        }
        if self.ibss_refused && kind == Kind::Adhoc && self.exists(STATION) {
            return Err(io::Error::other("EOPNOTSUPP"));
        }
        self.ifaces.lock().unwrap().insert(
            name.into(),
            Iface {
                kind: kind_name(kind).into(),
                mac: if self.monitor_mac_locked && matches!(kind, Kind::Monitor { .. }) {
                    STATION_MAC.parse().unwrap()
                } else {
                    "02:00:00:00:00:99".parse().unwrap()
                },
                freq: None,
            },
        );
        Ok(())
    }
    fn del_iface(&self, name: &str) -> io::Result<()> {
        self.call(format!("del {name}"));
        self.ifaces
            .lock()
            .unwrap()
            .remove(name)
            .map(drop)
            .ok_or_else(|| io::Error::other("ENODEV"))
    }
    fn set_kind(&self, iface: &str, kind: Kind) -> io::Result<()> {
        self.call(format!("type {iface} {}", kind_name(kind)));
        let mut ifaces = self.ifaces.lock().unwrap();
        let i = ifaces
            .get_mut(iface)
            .ok_or_else(|| io::Error::other("ENODEV"))?;
        i.kind = kind_name(kind).into();
        i.freq = None;
        Ok(())
    }
    fn set_mac(&self, iface: &str, mac: MacAddr) -> io::Result<()> {
        self.call(format!("mac {iface} {mac}"));
        if iface == MONITOR && self.monitor_mac_locked {
            return Err(io::Error::other("EOPNOTSUPP"));
        }
        self.ifaces.lock().unwrap().get_mut(iface).unwrap().mac = mac;
        Ok(())
    }
    fn set_up(&self, iface: &str, up: bool) -> io::Result<()> {
        self.call(format!("{} {iface}", if up { "up" } else { "down" }));
        if iface == STATION && !up {
            self.ifaces.lock().unwrap().get_mut(STATION).unwrap().freq = None;
        }
        Ok(())
    }
    fn set_freq(&self, iface: &str, freq: u32) -> io::Result<()> {
        self.call(format!("freq {iface} {freq}"));
        if iface == MONITOR && self.fail_monitor_tune {
            return Err(io::Error::other("EINVAL"));
        }
        let mut ifaces = self.ifaces.lock().unwrap();
        let i = ifaces
            .get_mut(iface)
            .ok_or_else(|| io::Error::other("ENODEV"))?;
        i.freq = Some(freq);
        Ok(())
    }
    fn join_ibss(&self, iface: &str, freq: u32) -> io::Result<()> {
        self.call(format!("join {iface} {freq}"));
        if !self.ibss_starts.contains(&freq) {
            return Err(io::Error::other("EINVAL"));
        }
        self.ifaces.lock().unwrap().get_mut(iface).unwrap().freq = Some(freq);
        Ok(())
    }
    fn leave_ibss(&self, iface: &str) -> io::Result<()> {
        self.call(format!("leave {iface}"));
        if let Some(i) = self.ifaces.lock().unwrap().get_mut(iface) {
            i.freq = None;
        }
        Ok(())
    }
    fn sysctl(&self, key: &str, value: &str) -> io::Result<()> {
        self.call(format!("sysctl {key}={value}"));
        Ok(())
    }
    fn mt76_dir(&self, phy: &str) -> PathBuf {
        PathBuf::from(format!("/debug/{phy}/mt76"))
    }
    fn read(&self, path: &Path) -> Option<String> {
        if path.starts_with("/debug") {
            return Some("1".into());
        }
        if path.ends_with("disable_ipv6") {
            return Some("0".into());
        }
        if path == Path::new("/etc/ufw/ufw.conf") && self.ufw {
            return Some("# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low".into());
        }
        None
    }
    fn write(&self, path: &Path, value: &str) -> io::Result<()> {
        self.call(format!("write {} {value}", path.display()));
        Ok(())
    }
    fn set_managed(&self, iface: &str, managed: bool) {
        // NetworkManager only matters for the station here.
        if iface == STATION {
            self.call(format!("managed {iface} {managed}"));
        }
        self.managed.lock().unwrap().insert(iface.into(), managed);
    }
    fn nm_connection(&self, station: &str) -> Option<String> {
        let managed = *self.managed.lock().unwrap().get(station).unwrap_or(&true);
        let up = self.kind(station).as_deref() == Some("managed");
        (managed && up && (self.autoconnect || self.link_freq(station).is_some()))
            .then(|| UUID.to_string())
    }
    fn connection_up(&self, uuid: &str, station: &str) -> io::Result<()> {
        self.call(format!("connect {uuid} {station}"));
        Ok(())
    }
    fn reconnect(&self, station: &str) {
        self.call(format!("reconnect {station}"));
    }
    /// Briefly, so polls see the fake hostapd start but nothing waits long.
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d.min(Duration::from_millis(5)));
    }
}

struct Fx {
    dir: tempfile::TempDir,
    ops: Arc<FakeOps>,
    /// What AWDL was last started with, and whether it still runs.
    awdl: Arc<Mutex<Option<(owly_awdl::Config, bool)>>>,
}

/// AWDL as the backend runs it: makes `awdl0` and hears the phone, until
/// stopped. Told to by
/// `<dir>/awdl.fail`, it fails a moment after starting.
struct StandIn {
    dir: PathBuf,
    started: Arc<Mutex<Option<(owly_awdl::Config, bool)>>>,
    failed: watch::Receiver<Option<String>>,
}

impl Awdl for StandIn {
    fn index(&self) -> u32 {
        7
    }
    fn failed(&self) -> watch::Receiver<Option<String>> {
        self.failed.clone()
    }
    fn stop(self: Box<Self>) {
        let _ = std::fs::remove_file(self.dir.join("awdl0"));
        if let Some((_, running)) = &mut *self.started.lock().unwrap() {
            *running = false;
        }
    }
}

impl Fx {
    fn new() -> Self {
        Fx::with(|_| {})
    }

    fn with(change: impl FnOnce(&mut FakeOps)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut ops = FakeOps::new(dir.path());
        change(&mut ops);
        let d = dir.path().display();
        // hostapd starts the AP on its configuration's channel, unless
        // told that channel fails, then runs until killed.
        script(
            &dir.path().join("hostapd"),
            &format!(
                "ch=$(sed -n 's/^channel=//p' \"$1\")\n\
                 cp \"$1\" {d}/hostapd.conf.$ch\n\
                 if [ -e {d}/hostapd.fail.$ch ]; then exit 1; fi\n\
                 echo $ch > {d}/hostapd.channel\n\
                 trap 'rm -f {d}/hostapd.channel; exit 0' TERM\n\
                 while :; do sleep 0.1; done\n"
            ),
        );
        Fx {
            dir,
            ops: Arc::new(ops),
            awdl: Arc::default(),
        }
    }

    fn settings(&self) -> Settings {
        Settings {
            station: None,
            allow_untested: false,
            reconnect_after: None,
            country: None,
            channels: None,
            aggregation: None,
            tx_rate: None,
            tx_amsdu: false,
            hostapd: self.dir.path().join("hostapd"),
            quirks: Quirks::load(Path::new("/nonexistent")).unwrap(),
            run_dir: self.run(),
        }
    }

    fn run(&self) -> RunDir {
        RunDir::new(self.dir.path().join("run"))
    }

    fn backend(&self) -> Injection {
        self.backend_with(self.settings())
    }

    fn backend_with(&self, settings: Settings) -> Injection {
        let dir = self.dir.path().to_path_buf();
        let started = self.awdl.clone();
        let start: StartAwdl = Arc::new(move |monitor, tap, cfg, peers| {
            assert_eq!((monitor, tap), (MONITOR, "awdl0"));
            *started.lock().unwrap() = Some((cfg, true));
            std::fs::write(dir.join("awdl0"), "").unwrap();
            let phone = PeerInfo {
                mac: PHONE.parse().unwrap(),
                name: "iPhone".into(),
                devclass: 2,
                rssi: None,
            };
            peers.send_replace(vec![phone]);
            let (fail, failed) = watch::channel(None);
            if dir.join("awdl.fail").exists() {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(300));
                    fail.send_replace(Some("the monitor's socket failed".into()));
                });
            }
            Ok(Box::new(StandIn {
                dir: dir.clone(),
                started: started.clone(),
                failed,
            }))
        });
        Injection::with_awdl(self.ops.clone(), settings, start)
    }

    fn journal(&self) -> Option<Vec<Step>> {
        self.run().read_json("journal.json")
    }

    /// What AWDL was last started with.
    fn awdl(&self) -> owly_awdl::Config {
        self.awdl.lock().unwrap().clone().expect("AWDL started").0
    }

    fn awdl_running(&self) -> bool {
        self.awdl.lock().unwrap().as_ref().is_some_and(|(_, r)| *r)
    }

    /// The calls made since `from`.
    fn since(&self, from: usize) -> Vec<String> {
        self.ops.calls()[from..].to_vec()
    }
}

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Intel: exclusive, channel 6.
fn intel(o: &mut FakeOps) {
    o.driver = "iwlwifi".into();
    o.device = Some("8086:51f0".into());
}

/// The MT7612U: an active monitor, 149 first.
fn mt7612u(o: &mut FakeOps) {
    o.driver = "mt76x2u".into();
    o.device = Some("0e8d:7612".into());
    let mut w = o.wiphy.lock().unwrap();
    w.iftypes.retain(|t| *t != IfType::Adhoc);
}

fn firmware_exclusive_settings(fx: &Fx) -> Settings {
    let path = fx.dir.path().join("drivers.toml");
    std::fs::write(
        &path,
        "[drivers.brcmfmac]\nstatus = \"untested\"\nmode = \"firmware-monitor\"\n",
    )
    .unwrap();
    let mut settings = fx.settings();
    settings.allow_untested = true;
    settings.quirks = Quirks::load(&path).unwrap();
    settings
}

#[test]
fn probe_finds_the_mt7925_ready() {
    let fx = Fx::new();
    let caps = fx.backend().probe();
    assert!(caps.hardware);
    assert_eq!(caps.missing, []);
    assert_eq!(caps.station.as_deref(), Some(STATION));
    assert_eq!(caps.device.as_deref(), Some("14c3:0717"));
    assert_eq!(caps.status, Some(Status::Tested));
    assert_eq!(caps.mode, Some(Mode::Shared));
    assert_eq!(caps.channel, Some(44));
    let card = caps.card.unwrap();
    assert!(card.ibss);
    assert!(card.active_monitor);
    assert!(card.monitor_beside_station);
    assert_eq!(card.regdom.as_deref(), Some("DE"));
    assert!(card.channels.iter().all(|c| c.transmit), "{card:?}");
    // The card's known issue, for the person at the computer.
    assert!(caps.issues[0].contains("490 kB/s"), "{:?}", caps.issues);
}

// spec: AWDL-11
#[test]
fn probe_explains_what_stands_in_the_way() {
    let fx = Fx::with(|o| o.freq = Some(5180));
    fx.ops.ifaces.lock().unwrap().get_mut(STATION).unwrap().freq = Some(5180);
    let caps = fx.backend().probe();
    assert!(caps.hardware);
    assert_eq!(caps.missing.len(), 1);
    assert_eq!(caps.missing[0].id, "radio");
    assert!(caps.missing[0].say.contains("5180 MHz"), "{caps:?}");

    let fx = Fx::new();
    fx.ops.ifaces.lock().unwrap().get_mut(STATION).unwrap().freq = None;
    let caps = fx.backend().probe();
    assert!(caps.missing[0].say.contains("isn't connected"), "{caps:?}");

    let fx = Fx::with(|o| o.driver = "brcmfmac".into());
    let caps = fx.backend().probe();
    assert!(!caps.hardware);
    assert_eq!(caps.missing[0].id, "hardware");
    assert!(caps.missing[0].say.contains("brcmfmac"), "{caps:?}");
    let mut settings = fx.settings();
    settings.allow_untested = true;
    let caps = fx.backend_with(settings).probe();
    assert!(caps.hardware, "{caps:?}");
    assert_eq!(caps.mode, Some(Mode::FirmwareMonitorShared));

    // The MT7927, on the MT7925's driver, is known not to work.
    let fx = Fx::with(|o| o.device = Some("14c3:7927".into()));
    let caps = fx.backend().probe();
    assert!(!caps.hardware);
    assert!(
        caps.missing[0].say.contains("known not to work")
            && caps.missing[0].say.contains("issues/44"),
        "{caps:?}"
    );

    let fx = Fx::with(|o| o.ifaces.lock().unwrap().clear());
    let caps = fx.backend().probe();
    assert!(!caps.hardware);
    assert!(
        caps.missing[0].say.contains("no Wi-Fi interface"),
        "{caps:?}"
    );
}

#[test]
fn firmware_monitor_requires_patched_driver_capabilities() {
    let fx = Fx::with(|o| {
        o.driver = "brcmfmac".into();
        o.wiphy
            .lock()
            .unwrap()
            .iftypes
            .retain(|t| *t != IfType::Monitor);
    });
    let mut settings = fx.settings();
    settings.allow_untested = true;
    let caps = fx.backend_with(settings).probe();
    assert_eq!(caps.missing[0].id, "hardware");
    assert!(caps.missing[0].say.contains("Nexmon"), "{caps:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn firmware_monitor_uses_one_fixed_channel_and_restores_station() {
    let fx = Fx::with(|o| {
        o.driver = "brcmfmac".into();
        o.wiphy
            .lock()
            .unwrap()
            .iftypes
            .retain(|t| *t != IfType::Adhoc && *t != IfType::Ap);
    });
    let mut backend = fx.backend_with(firmware_exclusive_settings(&fx));
    assert_eq!(backend.probe().missing, []);
    let link = backend.up().await.unwrap();
    assert_eq!(link.mac, STATION_MAC.parse().unwrap());
    assert_eq!(link.announce, Some(Announce::FIXED));
    assert_eq!(fx.awdl().radio.channel.0, 44);
    assert_eq!(fx.awdl().radio.presence, Presence::Fixed);
    let calls = fx.ops.calls();
    assert_eq!(
        calls,
        [
            format!("managed {STATION} false"),
            format!("down {STATION}"),
            format!("add phy0 {MONITOR} monitor"),
            format!("mac {MONITOR} {STATION_MAC}"),
            format!("up {MONITOR}"),
            format!("freq {MONITOR} 5220"),
        ]
    );
    backend.down().await.unwrap();
    assert_eq!(
        fx.since(calls.len()),
        [
            format!("down {MONITOR}"),
            format!("del {MONITOR}"),
            format!("up {STATION}"),
            format!("managed {STATION} true"),
        ]
    );
    assert_eq!(fx.journal(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn firmware_monitor_accepts_an_inherited_station_mac() {
    let fx = Fx::with(|o| {
        o.driver = "brcmfmac".into();
        o.monitor_mac_locked = true;
    });
    let mut backend = fx.backend_with(firmware_exclusive_settings(&fx));
    let link = backend.up().await.unwrap();
    assert_eq!(link.mac, STATION_MAC.parse().unwrap());
    backend.down().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn firmware_monitor_restores_wifi_when_no_channel_can_be_tuned() {
    let fx = Fx::with(|o| {
        o.driver = "brcmfmac".into();
        o.fail_monitor_tune = true;
    });
    let mut backend = fx.backend_with(firmware_exclusive_settings(&fx));
    let error = backend.up().await.err().expect("channel tuning must fail");
    assert!(error.to_string().contains("firmware monitor"), "{error}");
    assert!(!fx.ops.exists(MONITOR));
    assert_eq!(fx.ops.kind(STATION).as_deref(), Some("managed"));
    assert_eq!(fx.journal(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn nexmon_shared_mode_keeps_the_station_connected() {
    let fx = Fx::with(|o| o.driver = "brcmfmac".into());
    let mut settings = fx.settings();
    settings.allow_untested = true;
    let mut backend = fx.backend_with(settings);
    assert_eq!(backend.probe().mode, Some(Mode::FirmwareMonitorShared));
    let link = backend.up().await.unwrap();
    assert_eq!(link.announce, Some(Announce::SHARED));
    assert_eq!(fx.awdl().radio.presence, Presence::Share);
    assert_eq!(fx.awdl().radio.channel.0, 44);
    let calls = fx.ops.calls();
    assert!(calls.contains(&format!("add phy0 {MONITOR} monitor")));
    assert!(!calls.iter().any(|c| c == &format!("down {STATION}")));
    assert!(
        !calls
            .iter()
            .any(|c| c == &format!("managed {STATION} false"))
    );
    backend.down().await.unwrap();
    assert_eq!(fx.ops.kind(STATION).as_deref(), Some("managed"));
    assert_eq!(fx.journal(), None);
}

#[test]
fn probe_explains_exclusive_cards() {
    // Intel, connected or not, runs on channel 6.
    let fx = Fx::with(intel);
    let caps = fx.backend().probe();
    assert_eq!(caps.missing, [], "{caps:?}");
    assert_eq!(caps.mode, Some(Mode::Exclusive));
    assert_eq!(caps.channel, Some(6));
    assert!(caps.issues[0].contains("5 GHz"), "{:?}", caps.issues);
    assert!(caps.issues[1].contains("slow"), "{:?}", caps.issues);

    // Under the world's regulatory domain nothing on 5 GHz may transmit,
    // and here 6 isn't allowed either.
    let fx = Fx::with(|o| {
        intel(o);
        let mut w = o.wiphy.lock().unwrap();
        for c in &mut w.channels {
            c.no_ir = true;
        }
        *o.regdom.lock().unwrap() = "00".into();
    });
    let caps = fx.backend().probe();
    assert_eq!(caps.missing[0].id, "radio");
    assert!(caps.missing[0].say.contains("set country"), "{caps:?}");
    // With a country to ask for, the start sets it first.
    let mut settings = fx.settings();
    settings.country = Some("DE".into());
    assert_eq!(fx.backend_with(settings).probe().missing, []);

    // No ad-hoc mode: a hidden AP, which needs hostapd.
    let fx = Fx::with(|o| {
        o.driver = "rtw89_8852bu".into();
        o.wiphy
            .lock()
            .unwrap()
            .iftypes
            .retain(|t| *t != IfType::Adhoc);
    });
    let mut settings = fx.settings();
    settings.allow_untested = true;
    settings.hostapd = PathBuf::from("/nonexistent/hostapd");
    let caps = fx.backend_with(settings).probe();
    assert_eq!(caps.missing[0].id, "backend");
    assert!(caps.missing[0].say.contains("hostapd"), "{caps:?}");

    // An active monitor the card doesn't have.
    let fx = Fx::with(|o| {
        mt7612u(o);
        o.wiphy.lock().unwrap().active_monitor = false;
    });
    let caps = fx.backend().probe();
    assert_eq!(caps.missing[0].id, "hardware");
    assert!(caps.missing[0].say.contains("active monitor"), "{caps:?}");
}

// spec: NET-4
#[test]
fn probe_warns_of_ufw() {
    let fx = Fx::new();
    assert!(
        !fx.backend()
            .probe()
            .issues
            .iter()
            .any(|i| i.contains("UFW"))
    );
    let fx = Fx::with(|o| o.ufw = true);
    let caps = fx.backend().probe();
    assert!(
        caps.issues
            .iter()
            .any(|i| i.contains("UFW") && i.contains("8771")),
        "{:?}",
        caps.issues
    );
}

// spec: AWDL-2, NET-1
#[tokio::test(flavor = "multi_thread")]
async fn shared_mode_comes_up_and_goes_back() {
    let fx = Fx::new();
    let mut backend = fx.backend();
    let link = backend.up().await.unwrap();
    let station_mac: MacAddr = STATION_MAC.parse().unwrap();
    assert_eq!(link.name, "awdl0");
    assert_eq!(
        link.mac, station_mac,
        "AWDL-2: the station's MAC throughout"
    );
    assert_eq!(link.addr, station_mac.link_local());
    assert_eq!(link.announce, Some(Announce::SHARED));
    // The AP's channel, the master's slots on it, ACKs awaited.
    let awdl = fx.awdl();
    assert_eq!(awdl.radio.channel.0, 44);
    assert_eq!(awdl.radio.presence, Presence::Share);
    assert_eq!(awdl.radio.presence.ranking(), Ranking::CounterFirst);
    assert_eq!(awdl.addr, station_mac);
    assert!(!awdl.no_ack && !awdl.accept_addba);
    assert_eq!(awdl.rate, TxRate::BASIC);
    let calls = fx.ops.calls();
    assert_eq!(
        calls,
        [
            "write /debug/phy0/mt76/runtime-pm 0".to_string(),
            "write /debug/phy0/mt76/deep-sleep 0".into(),
            format!("add phy0 {MONITOR} monitor"),
            format!("mac {MONITOR} {STATION_MAC}"),
            format!("up {MONITOR}"),
        ]
    );
    let journal = fx.journal().unwrap();
    assert_eq!(
        journal[0],
        Step::Reconnect {
            station: STATION.into()
        }
    );
    assert!(matches!(journal[1], Step::Mt76 { .. }), "{journal:?}");
    assert_eq!(
        journal[2],
        Step::Interface {
            name: MONITOR.into()
        }
    );
    assert!(fx.awdl_running());

    let mut peers = link.peers.clone();
    peers.wait_for(|p| !p.is_empty()).await.unwrap();
    assert_eq!(peers.borrow()[0].mac.to_string(), PHONE);

    backend.down().await.unwrap();
    assert!(!fx.awdl_running());
    assert_eq!(
        fx.since(calls.len()),
        // The monitor goes before mt76's power management comes back.
        [
            format!("down {MONITOR}"),
            format!("del {MONITOR}"),
            "write /debug/phy0/mt76/runtime-pm 1".into(),
            "write /debug/phy0/mt76/deep-sleep 1".into(),
            format!("reconnect {STATION}"),
        ]
    );
    assert_eq!(fx.journal(), None);
    assert_eq!(*link.state.borrow(), LinkState::Up, "taken down, not lost");

    // Down again changes nothing.
    let n = fx.ops.calls().len();
    backend.down().await.unwrap();
    assert_eq!(fx.ops.calls().len(), n);
}

// spec: AWDL-2, AWDL-9, AWDL-12
#[tokio::test(flavor = "multi_thread")]
async fn exclusive_mode_runs_an_ad_hoc_cell() {
    let fx = Fx::with(intel);
    let mut backend = fx.backend();
    let link = backend.up().await.unwrap();
    assert_eq!(link.mac, STATION_MAC.parse().unwrap());
    assert_eq!(link.announce, Some(Announce::FIXED));
    // Fixed to channel 6, electing by metric (AWDL-9, AWDL-12), and
    // sending without ACKs.
    let awdl = fx.awdl();
    assert_eq!(awdl.radio.channel.0, 6);
    assert_eq!(awdl.radio.presence, Presence::Fixed);
    assert_eq!(awdl.radio.presence.ranking(), Ranking::MetricFirst);
    assert!(awdl.no_ack && !awdl.accept_addba);
    let calls = fx.ops.calls();
    assert_eq!(
        calls[..10],
        [
            format!("managed {STATION} false"),
            format!("down {STATION}"),
            format!("add phy0 {IBSS} IBSS"),
            format!("mac {IBSS} {STATION_MAC}"),
            format!("sysctl net/ipv6/conf/{IBSS}/disable_ipv6=1"),
            format!("up {IBSS}"),
            format!("join {IBSS} 2437"),
            format!("add phy0 {MONITOR} monitor"),
            format!("mac {MONITOR} {STATION_MAC}"),
            format!("up {MONITOR}"),
        ]
    );
    assert_eq!(
        fx.journal().unwrap()[0],
        Step::Station {
            station: STATION.into(),
            connection: Some(UUID.into())
        }
    );

    backend.down().await.unwrap();
    // NetworkManager reconnects by itself, so nothing's brought up.
    assert_eq!(
        fx.since(calls.len()),
        [
            format!("down {MONITOR}"),
            format!("del {MONITOR}"),
            format!("leave {IBSS}"),
            format!("down {IBSS}"),
            format!("del {IBSS}"),
            format!("up {STATION}"),
            format!("managed {STATION} true"),
        ]
    );
    assert_eq!(fx.journal(), None);

    // A driver's tx_noack wins over the mode's.
    let fx = Fx::with(intel);
    let overrides = fx.dir.path().join("drivers.toml");
    std::fs::write(
        &overrides,
        "[drivers.iwlwifi]\nstatus = \"tested\"\nmode = \"exclusive\"\nchannels = [6]\ntx_noack = false\n",
    )
    .unwrap();
    let mut settings = fx.settings();
    settings.quirks = Quirks::load(&overrides).unwrap();
    let mut backend = fx.backend_with(settings);
    backend.up().await.unwrap();
    assert!(!fx.awdl().no_ack);
    backend.down().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn exclusive_mode_tries_each_channel_in_order() {
    // An RTL8822BE starts no cell on 5 GHz: 44 and 149 fail, 6 works.
    let fx = Fx::with(|o| {
        o.driver = "rtw88_8822be".into();
        o.ibss_starts = vec![2437];
    });
    let mut backend = fx.backend();
    backend.up().await.unwrap();
    let joins: Vec<_> = fx
        .ops
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("join"))
        .collect();
    assert_eq!(
        joins,
        [
            format!("join {IBSS} 5220"),
            format!("join {IBSS} 5745"),
            format!("join {IBSS} 2437")
        ]
    );
    assert_eq!(fx.awdl().radio.channel.0, 6);
    backend.down().await.unwrap();

    // radio.toml's order wins over the driver's.
    let fx = Fx::with(|o| o.driver = "rtw88_8822be".into());
    let mut settings = fx.settings();
    settings.channels = Some(vec![149]);
    let mut backend = fx.backend_with(settings);
    backend.up().await.unwrap();
    assert_eq!(fx.awdl().radio.channel.0, 149);
    backend.down().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_card_that_refuses_a_cell_beside_its_station_becomes_the_cell() {
    let fx = Fx::with(|o| {
        intel(o);
        o.ibss_refused = true;
        o.autoconnect = false;
    });
    let mut backend = fx.backend();
    backend.up().await.unwrap();
    let calls = fx.ops.calls();
    assert!(calls.contains(&format!("type {STATION} IBSS")), "{calls:?}");
    assert!(calls.contains(&format!("join {STATION} 2437")), "{calls:?}");
    assert!(fx.journal().unwrap().contains(&Step::StationType {
        station: STATION.into()
    }));
    backend.down().await.unwrap();
    let after = fx.since(calls.len());
    // A station whose type changed is brought up at once.
    let tail = [
        format!("leave {STATION}"),
        format!("down {STATION}"),
        format!("type {STATION} managed"),
        format!("sysctl net/ipv6/conf/{STATION}/disable_ipv6=0"),
        format!("up {STATION}"),
        format!("managed {STATION} true"),
        format!("connect {UUID} {STATION}"),
    ];
    assert_eq!(after[after.len() - tail.len()..], tail);
    assert_eq!(fx.ops.kind(STATION).as_deref(), Some("managed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn exclusive_mode_runs_a_hidden_ap_without_ad_hoc_mode() {
    let fx = Fx::with(|o| {
        o.driver = "rtw89_8852bu".into();
        o.wiphy
            .lock()
            .unwrap()
            .iftypes
            .retain(|t| *t != IfType::Adhoc);
    });
    std::fs::write(fx.dir.path().join("hostapd.fail.44"), "").unwrap();
    let mut settings = fx.settings();
    settings.allow_untested = true;
    let mut backend = fx.backend_with(settings);
    let link = backend.up().await.unwrap();
    // 44 failed; 149 started.
    assert_eq!(fx.awdl().radio.channel.0, 149);
    let conf = std::fs::read_to_string(fx.dir.path().join("hostapd.conf.149")).unwrap();
    for line in [
        "interface=owlyap0",
        "ignore_broadcast_ssid=1",
        "hw_mode=a",
        "beacon_int=1000",
        "wpa=2",
    ] {
        assert!(conf.lines().any(|l| l == line), "{line} in {conf}");
    }
    let calls = fx.ops.calls();
    assert!(calls.contains(&format!("add phy0 {AP} AP")));
    assert!(calls.contains(&format!("mac {AP} {STATION_MAC}")));
    let hostapd = fx
        .journal()
        .unwrap()
        .into_iter()
        .rev()
        .find_map(|s| match s {
            Step::Process { what, process } if what == "hostapd" => Some(process),
            _ => None,
        })
        .unwrap();
    assert!(hostapd.alive());

    backend.down().await.unwrap();
    assert!(!hostapd.alive());
    assert!(fx.since(calls.len()).contains(&format!("del {AP}")));
    assert_eq!(*link.state.borrow(), LinkState::Up);
}

#[tokio::test(flavor = "multi_thread")]
async fn hostapd_exiting_loses_the_link() {
    let fx = Fx::with(|o| {
        o.driver = "rtw89_8852bu".into();
        o.wiphy
            .lock()
            .unwrap()
            .iftypes
            .retain(|t| *t != IfType::Adhoc);
    });
    let mut settings = fx.settings();
    settings.allow_untested = true;
    let mut backend = fx.backend_with(settings);
    let link = backend.up().await.unwrap();
    let hostapd = fx
        .journal()
        .unwrap()
        .into_iter()
        .find_map(|s| match s {
            Step::Process { what, process } if what == "hostapd" => Some(process),
            _ => None,
        })
        .unwrap();
    hostapd.signal(nix::sys::signal::Signal::SIGTERM);
    let mut state = link.state.clone();
    tokio::time::timeout(
        Duration::from_secs(5),
        state.wait_for(|s| *s != LinkState::Up),
    )
    .await
    .unwrap()
    .unwrap();
    let LinkState::Lost(why) = state.borrow().clone() else {
        unreachable!()
    };
    assert!(why.contains("hostapd exited"), "{why}");
    backend.down().await.unwrap();
    assert_eq!(fx.journal(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn active_monitor_mode() {
    let fx = Fx::with(mt7612u);
    let mut backend = fx.backend();
    let link = backend.up().await.unwrap();
    assert_eq!(link.announce, Some(Announce::FIXED));
    // 149 first; Block Ack accepted, as the quirks say.
    let awdl = fx.awdl();
    assert_eq!(awdl.radio.channel.0, 149);
    assert_eq!(awdl.radio.presence, Presence::Fixed);
    assert!(awdl.accept_addba && awdl.no_ack);
    let calls = fx.ops.calls();
    assert_eq!(
        calls[..9],
        [
            format!("managed {STATION} false"),
            format!("down {STATION}"),
            format!("type {STATION} monitor"),
            format!("up {STATION}"),
            format!("add phy0 {MONITOR} active-monitor"),
            format!("mac {MONITOR} {STATION_MAC}"),
            format!("up {MONITOR}"),
            format!("freq {STATION} 5745"),
            format!("freq {MONITOR} 5745"),
        ]
    );
    backend.down().await.unwrap();
    let after = fx.since(calls.len());
    assert!(
        after.contains(&format!("type {STATION} managed")),
        "{after:?}"
    );
    // A station whose type changed is brought up at once.
    assert_eq!(after.last().unwrap(), &format!("connect {UUID} {STATION}"));

    // radio.toml can turn aggregation off.
    let fx = Fx::with(mt7612u);
    let mut settings = fx.settings();
    settings.aggregation = Some(false);
    settings.tx_rate = TxRate::parse("mcs7");
    let mut backend = fx.backend_with(settings);
    backend.up().await.unwrap();
    let awdl = fx.awdl();
    assert!(!awdl.accept_addba);
    assert_eq!(awdl.rate, TxRate::parse("mcs7").unwrap());
    backend.down().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn exclusive_mode_sets_the_regulatory_domain_and_restores_it() {
    let fx = Fx::with(|o| {
        intel(o);
        // The world's domain: no 5 GHz.
        *o.regdom.lock().unwrap() = "00".into();
    });
    fx.ops.set_regdom("00").unwrap();
    let n = fx.ops.calls().len();
    let mut settings = fx.settings();
    settings.country = Some("DE".into());
    settings.channels = Some(vec![44, 6]);
    let mut backend = fx.backend_with(settings);
    backend.up().await.unwrap();
    // Asked for, then 44, which DE allows, chosen.
    assert!(fx.since(n).contains(&"regdom DE".to_string()));
    assert_eq!(fx.awdl().radio.channel.0, 44);
    backend.down().await.unwrap();
    assert_eq!(fx.ops.regdom().as_deref(), Some("00"));
}

#[tokio::test(flavor = "multi_thread")]
async fn awdl_failing_loses_the_link() {
    let fx = Fx::new();
    std::fs::write(fx.dir.path().join("awdl.fail"), "").unwrap();
    let mut backend = fx.backend();
    let link = backend.up().await.unwrap();
    let mut state = link.state.clone();
    tokio::time::timeout(
        Duration::from_secs(5),
        state.wait_for(|s| *s != LinkState::Up),
    )
    .await
    .unwrap()
    .unwrap();
    let LinkState::Lost(why) = state.borrow().clone() else {
        unreachable!()
    };
    assert!(why.contains("socket failed"), "{why}");
    backend.down().await.unwrap();
    assert_eq!(fx.journal(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_monitor_vanishing_loses_the_link() {
    let fx = Fx::new();
    let mut backend = fx.backend();
    let link = backend.up().await.unwrap();
    fx.ops.ifaces.lock().unwrap().remove(MONITOR);
    let mut state = link.state.clone();
    tokio::time::timeout(
        Duration::from_secs(5),
        state.wait_for(|s| *s != LinkState::Up),
    )
    .await
    .unwrap()
    .unwrap();
    backend.down().await.unwrap();
    // A monitor that vanished went with a driver or firmware reset, after
    // which the station needs its reconnect as much as after a delete.
    assert!(
        fx.ops
            .calls()
            .iter()
            .any(|c| *c == format!("reconnect {STATION}")),
        "{:?}",
        fx.ops.calls()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_setup_leaves_nothing_behind() {
    let fx = Fx::with(|o| o.fail_monitor = true);
    let e = fx.backend().up().await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::NoRadio);
    assert!(e.message.contains("monitor interface"), "{e}");
    assert_eq!(fx.journal(), None);
    assert!(!fx.ops.calls().iter().any(|c| c.starts_with("reconnect")));

    let fx = Fx::new();
    fx.ops.ifaces.lock().unwrap().get_mut(STATION).unwrap().freq = Some(2412);
    let e = fx.backend().up().await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::NotNow);
    assert_eq!(fx.ops.calls(), Vec::<String>::new(), "nothing changed");

    // Exclusive mode on a card that may transmit on none of AirDrop's
    // channels leaves Wi-Fi alone.
    let fx = Fx::with(|o| {
        intel(o);
        for c in &mut o.wiphy.lock().unwrap().channels {
            c.no_ir = true;
        }
    });
    let e = fx.backend().up().await.unwrap_err();
    assert!(e.message.contains("may not transmit"), "{e}");
    assert_eq!(fx.ops.calls(), Vec::<String>::new(), "nothing changed");

    // Exclusive mode gives the station back when no cell starts.
    let fx = Fx::with(|o| {
        intel(o);
        o.ibss_starts = vec![];
    });
    let e = fx.backend().up().await.unwrap_err();
    assert!(e.message.contains("ad-hoc cell"), "{e}");
    assert_eq!(fx.journal(), None);
    let calls = fx.ops.calls();
    assert_eq!(calls.last().unwrap(), &format!("managed {STATION} true"));
}

/// owlyd killed mid-session: the next owner of the journal undoes it.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_owners_session_is_undone_from_the_journal() {
    let fx = Fx::with(intel);
    let mut backend = fx.backend();
    backend.up().await.unwrap();
    let n = fx.ops.calls().len();
    // Gone without a teardown, as if killed.
    drop(backend);

    let mut next = fx.backend();
    next.recover().await.unwrap();
    assert!(!fx.ops.exists(MONITOR) && !fx.ops.exists(IBSS));
    assert_eq!(
        fx.since(n).last().unwrap(),
        &format!("managed {STATION} true")
    );
    assert_eq!(fx.journal(), None);
    // And again, with nothing left to do.
    let n = fx.ops.calls().len();
    next.recover().await.unwrap();
    assert_eq!(fx.ops.calls().len(), n);
}

#[tokio::test(flavor = "multi_thread")]
async fn one_owner_of_the_radio_at_a_time() {
    let fx = Fx::new();
    let mut first = fx.backend();
    first.up().await.unwrap();
    let e = fx.backend().up().await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::NotNow);
    assert!(e.message.contains("busy"), "{e}");
    first.down().await.unwrap();
}

#[test]
fn a_dead_holders_process_is_stopped_by_its_step() {
    // The journal stops a recorded process however it was started.
    let fx = Fx::new();
    let child = std::process::Command::new("sleep")
        .arg("600")
        .spawn()
        .unwrap();
    let process = Process::of(child.id()).unwrap();
    let reaper = std::thread::spawn(move || {
        let mut child = child;
        child.wait()
    });
    fx.run()
        .write_json(
            "journal.json",
            &[Step::Process {
                what: "hostapd".into(),
                process,
            }],
        )
        .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(fx.backend().recover()).unwrap();
    reaper.join().unwrap().unwrap();
    assert!(!process.alive());
    assert_eq!(fx.journal(), None);
}
