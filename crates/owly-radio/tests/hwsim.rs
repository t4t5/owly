//! Each mode's setup and teardown on `mac80211_hwsim`, and two simulated
//! radios hearing each other: syncing over the air and passing IPv6 (pings
//! between their `awdl0`s). Three radios,
//! each in a network namespace of its own so nothing touches the host's
//! Wi-Fi, routes or NetworkManager:
//!
//! - `owlyhwsim-ap`: an AP on channel 6 (hostapd), for shared mode.
//! - `owlyhwsim-sta`: the station, `owlysta0`, which runs each mode in turn.
//! - `owlyhwsim-peer`: `owlypeer0`, a second node for the pair test.
//!
//! The interfaces are renamed so that `nmcli`, which talks to the host's
//! NetworkManager whatever the namespace, can't name a real one.
//!
//! Needs root, `iw`, `ip` and `ping`; shared mode also needs `hostapd`, and
//! is skipped without it. It loads and unloads the
//! `mac80211_hwsim` module, so it runs only when asked to (`just hwsim`):
//! with `OWLY_HWSIM=1`, and with the module not loaded already. Otherwise
//! it passes without doing anything. A mode the simulated card can't run
//! (an active monitor, on kernels whose hwsim has none) is skipped, saying
//! so.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use owly_radio::injection::{IBSS, Injection, MONITOR, Settings};
use owly_radio::quirks::Quirks;
use owly_radio::radio::{Backend, LinkState};
use owly_radio::rundir::RunDir;
use owly_radio::sys::{Ops, System};

const AP_NS: &str = "owlyhwsim-ap";
const STA_NS: &str = "owlyhwsim-sta";
const PEER_NS: &str = "owlyhwsim-peer";
const STA: &str = "owlysta0";
const PEER: &str = "owlypeer0";
/// Which scenario a re-run of this test plays, inside a namespace.
const INNER: &str = "OWLY_HWSIM_INNER";
const TEST: &str = "modes_on_hwsim";

fn sh(script: &str) -> bool {
    Command::new("sh")
        .args(["-ec", script])
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn modes_on_hwsim() {
    if let Ok(scenario) = std::env::var(INNER) {
        return inner(&scenario);
    }
    if std::env::var("OWLY_HWSIM").as_deref() != Ok("1") {
        eprintln!("skipped: set OWLY_HWSIM=1 and run as root (just hwsim)");
        return;
    }
    assert!(nix::unistd::geteuid().is_root(), "OWLY_HWSIM needs root");
    assert!(
        !Path::new("/sys/module/mac80211_hwsim").exists(),
        "mac80211_hwsim is loaded already; unload it first"
    );
    let hostapd = sh("command -v hostapd >/dev/null");

    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().display();
    let setup = format!(
        r#"
        modprobe mac80211_hwsim radios=3
        set -- $(for p in /sys/class/ieee80211/*; do
            [ "$(basename "$(readlink -f "$p/device/driver")")" = mac80211_hwsim ] && basename "$p"
        done)
        [ $# = 3 ]
        for ns in {AP_NS} {STA_NS} {PEER_NS}; do ip netns add $ns; done
        iw phy "$1" set netns name {AP_NS}
        iw phy "$2" set netns name {STA_NS}
        iw phy "$3" set netns name {PEER_NS}
        rename() {{
            ip netns exec "$1" sh -ec "
                ip link set lo up
                old=\$(ls /sys/class/net | grep -vx lo | head -1)
                ip link set \"\$old\" name $2
            "
        }}
        rename {AP_NS} owlyap9
        rename {STA_NS} {STA}
        rename {PEER_NS} {PEER}
        "#
    );
    let ok = sh(&setup);
    let mut results = Vec::new();
    if ok {
        if hostapd {
            let ap = sh(&format!(
                r#"ip netns exec {AP_NS} sh -ec '
                    printf "%s\n" interface=owlyap9 driver=nl80211 ssid=owly-hwsim hw_mode=g channel=6 > {d}/hostapd.conf
                    hostapd -B -P {d}/hostapd.pid {d}/hostapd.conf > {d}/hostapd.log
                    ip addr add 10.99.0.1/24 dev owlyap9
                '"#
            ));
            assert!(ap, "starting the AP failed");
        } else {
            eprintln!("shared mode skipped: no hostapd");
        }
        if hostapd {
            results.push(("shared", run_in(STA_NS, "shared")));
        }
        results.push(("exclusive", run_in(STA_NS, "exclusive")));
        results.push(("active-monitor", run_in(STA_NS, "active-monitor")));
        // Both ends at once.
        let a = spawn_in(STA_NS, "pair");
        let b = spawn_in(PEER_NS, "pair");
        results.push(("pair, station", wait(a)));
        results.push(("pair, peer", wait(b)));
        let a = spawn_in(STA_NS, "pair-active");
        let b = spawn_in(PEER_NS, "pair-active");
        results.push(("active-monitor pair, station", wait(a)));
        results.push(("active-monitor pair, peer", wait(b)));
    }
    sh(&format!(
        "kill $(cat {d}/hostapd.pid 2>/dev/null) 2>/dev/null || true
         for ns in {STA_NS} {PEER_NS} {AP_NS}; do ip netns del $ns 2>/dev/null || true; done
         sleep 0.5
         modprobe -r mac80211_hwsim"
    ));
    assert!(ok, "setting up hwsim failed");
    let failed: Vec<String> = results
        .iter()
        .filter(|(_, (s, _))| !s.success())
        .map(|(n, (_, why))| format!("{n}:{why}"))
        .collect();
    assert!(failed.is_empty(), "failed on hwsim:\n{}", failed.join("\n"));
}

/// A scenario running in a namespace. Its stderr is passed on as it comes,
/// and its panic kept for the summary, where it can't scroll away.
struct Running {
    child: std::process::Child,
    panic: std::thread::JoinHandle<String>,
}

fn spawn_in(ns: &str, scenario: &str) -> Running {
    let mut child = Command::new("ip")
        .args(["netns", "exec", ns])
        .arg(std::env::current_exe().unwrap())
        .args([TEST, "--exact", "--nocapture"])
        .env(INNER, scenario)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let panic = std::thread::spawn(move || {
        let mut panic = String::new();
        let mut keep = 0;
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            eprintln!("{line}");
            if line.contains("panicked at") {
                keep = 8;
            }
            if keep > 0 && !line.starts_with("note:") {
                panic.push_str("\n    ");
                panic.push_str(&line);
                keep -= 1;
            }
        }
        panic
    });
    Running { child, panic }
}

fn run_in(ns: &str, scenario: &str) -> (ExitStatus, String) {
    wait(spawn_in(ns, scenario))
}

fn wait(mut r: Running) -> (ExitStatus, String) {
    let status = r.child.wait().unwrap();
    (status, r.panic.join().unwrap_or_default())
}

fn wait_for(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let end = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The settings for this namespace's radio in one mode.
fn settings(station: &str, mode: &str, run: &Path) -> Settings {
    let quirks = Quirks::parse(&format!(
        r#"
        [drivers.mac80211_hwsim]
        status = "tested"
        mode = "{mode}"
        channels = [6]
        [drivers."*"]
        status = "untested"
        mode = "shared"
        "#
    ))
    .unwrap();
    Settings {
        station: Some(station.into()),
        allow_untested: false,
        // No NetworkManager in here to reconnect through.
        reconnect_after: Some(false),
        country: None,
        channels: None,
        aggregation: None,
        tx_rate: None,
        tx_amsdu: false,
        hostapd: PathBuf::from("/usr/bin/hostapd"),
        quirks,
        run_dir: RunDir::new(run),
        election_metric: None,
    }
}

/// In a namespace: one scenario.
fn inner(scenario: &str) {
    let ops = System;
    let station = if ops.exists(STA) { STA } else { PEER };
    let run = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let played = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match scenario {
        "shared" => shared(&ops, station, run.path(), &rt),
        "exclusive" => exclusive(&ops, station, run.path(), &rt),
        "active-monitor" => active_monitor(&ops, station, run.path(), &rt),
        "pair" => pair(station, "exclusive", run.path(), &rt),
        "pair-active" => pair(station, "active-monitor", run.path(), &rt),
        _ => panic!("no scenario {scenario}"),
    }));
    if let Err(panic) = played {
        // A scenario that failed half way left the radio as it was then:
        // give it back from the journal, as owlyd would on its next start,
        // so the next scenario starts from a station.
        let mut backend =
            Injection::new(Arc::new(System), settings(station, "exclusive", run.path()));
        if let Err(e) = rt.block_on(backend.recover()) {
            eprintln!("recovering after the failure: {e}");
        }
        std::panic::resume_unwind(panic);
    }
}

/// Associate, then bring shared mode up and down: Wi-Fi stays connected.
fn shared(ops: &System, sta: &str, run: &Path, rt: &tokio::runtime::Runtime) {
    assert!(sh(&format!(
        "ip link set {sta} up
         iw dev {sta} connect owly-hwsim"
    )));
    wait_for("association", Duration::from_secs(10), || {
        ops.link_freq(sta) == Some(2437)
    });
    assert!(sh(&format!(
        "ip addr add 10.99.0.2/24 dev {sta}
         ip route add default via 10.99.0.1 dev {sta}"
    )));
    wait_for("the gateway", Duration::from_secs(10), || {
        ops.gateway_reachable(sta)
    });
    let sta_mac = ops.mac(sta).unwrap();

    let mut backend = Injection::new(Arc::new(System), settings(sta, "shared", run));
    let caps = backend.probe();
    assert_eq!(caps.missing, [], "{caps:?}");
    assert_eq!(caps.channel, Some(6));
    rt.block_on(async {
        let link = backend.up().await.unwrap();
        // AWDL-2, NET-1: awdl0 on the station's MAC, with its EUI-64
        // link-local address and no DAD pending.
        assert_eq!(link.mac, sta_mac);
        assert_eq!(link.addr, sta_mac.link_local());
        assert_eq!(
            owly_radio::sys::link_local("awdl0"),
            Some((link.addr, false))
        );
        assert_eq!(ops.iface_type(MONITOR).as_deref(), Some("monitor"));
        assert_eq!(ops.mac(MONITOR), Some(sta_mac));
        // AWDL lives a while on it.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(*link.state.borrow(), LinkState::Up);
        backend.down().await.unwrap();
    });
    assert!(!ops.exists(MONITOR));
    assert!(!ops.exists("awdl0"));
    // Wi-Fi stayed connected throughout.
    assert_eq!(ops.link_freq(sta), Some(2437));
    assert!(ops.gateway_reachable(sta));
    let _ = sh(&format!("iw dev {sta} disconnect"));
}

/// The station taken down, an ad-hoc cell on AWDL's BSSID in its place.
fn exclusive(ops: &System, sta: &str, run: &Path, rt: &tokio::runtime::Runtime) {
    let sta_mac = ops.mac(sta).unwrap();
    let mut backend = Injection::new(Arc::new(System), settings(sta, "exclusive", run));
    let caps = backend.probe();
    assert_eq!(caps.missing, [], "{caps:?}");
    assert!(caps.card.as_ref().unwrap().ibss, "{caps:?}");
    rt.block_on(async {
        let link = backend.up().await.unwrap();
        assert_eq!(link.mac, sta_mac);
        assert_eq!(
            owly_radio::sys::link_local("awdl0"),
            Some((link.addr, false))
        );
        // The cell is joined on channel 6, on the station's MAC, beside it
        // or in its place.
        let cell = if ops.exists(IBSS) { IBSS } else { sta };
        assert_eq!(ops.iface_type(cell).as_deref(), Some("IBSS"));
        assert_eq!(ops.link_freq(cell), Some(2437));
        assert_eq!(ops.mac(cell), Some(sta_mac));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(*link.state.borrow(), LinkState::Up);
        backend.down().await.unwrap();
    });
    assert!(!ops.exists(MONITOR) && !ops.exists(IBSS) && !ops.exists("awdl0"));
    assert_eq!(ops.iface_type(sta).as_deref(), Some("managed"));
    assert!(std::fs::read_to_string(format!("/sys/class/net/{sta}/operstate")).is_ok());
}

/// The station a passive monitor, an active monitor in the cell's place.
fn active_monitor(ops: &System, sta: &str, run: &Path, rt: &tokio::runtime::Runtime) {
    let mut backend = Injection::new(Arc::new(System), settings(sta, "active-monitor", run));
    let caps = backend.probe();
    if !caps.card.as_ref().is_some_and(|c| c.active_monitor) {
        eprintln!("active-monitor mode skipped: this kernel's hwsim has no active monitor");
        return;
    }
    assert_eq!(caps.missing, [], "{caps:?}");
    rt.block_on(async {
        let link = backend.up().await.unwrap();
        assert_eq!(ops.iface_type(sta).as_deref(), Some("monitor"));
        // hwsim on kernel 7.2 reports no channel for a monitor beside a
        // monitor. Where the kernel says, it's 6; the pair-active scenario
        // shows it by hearing the peer there.
        let freq = ops.link_freq(MONITOR).or_else(|| ops.link_freq(sta));
        assert!(matches!(freq, None | Some(2437)), "on {freq:?} MHz");
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(*link.state.borrow(), LinkState::Up);
        backend.down().await.unwrap();
    });
    assert!(!ops.exists(MONITOR));
    assert_eq!(ops.iface_type(sta).as_deref(), Some("managed"));
}

/// Two nodes on channel 6, exclusive or with active monitors: each
/// injects, and the other captures it and adds it as a peer. With owly-awdl, each then pings the other's
/// `awdl0` over the simulated air, which takes the two nodes in sync.
fn pair(sta: &str, mode: &str, run: &Path, rt: &tokio::runtime::Runtime) {
    let mut backend = Injection::new(Arc::new(System), settings(sta, mode, run));
    if mode == "active-monitor" && !backend.probe().card.is_some_and(|c| c.active_monitor) {
        eprintln!("active-monitor pair skipped: this kernel's hwsim has no active monitor");
        return;
    }
    rt.block_on(async {
        let link = backend.up().await.unwrap();
        let mut peers = link.peers.clone();
        let heard =
            tokio::time::timeout(Duration::from_secs(30), peers.wait_for(|p| !p.is_empty()))
                .await
                .ok()
                .and_then(|r| r.ok().map(|p| p[0].mac));
        let pinged = match heard {
            Some(mac) => {
                let peer = mac.link_local();
                let ping = format!("ping -6 -c 10 -i 0.3 -W 3 {peer}%awdl0");
                Some(
                    tokio::task::spawn_blocking(move || sh(&ping))
                        .await
                        .unwrap(),
                )
            }
            _ => None,
        };
        // Give the other end time to hear us too before leaving.
        tokio::time::sleep(Duration::from_secs(5)).await;
        backend.down().await.unwrap();
        assert!(heard.is_some(), "{sta} heard no AWDL peer in 30 s");
        assert_ne!(
            pinged,
            Some(false),
            "{sta} couldn't ping its peer over AWDL"
        );
    });
}
