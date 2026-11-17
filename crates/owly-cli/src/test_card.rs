//! `owly test-card`: tests this computer's Wi-Fi card with an iPhone, the
//! way a hardware report needs, and writes the result as JSON. Replaces
//! legacy's `tools/test-card.sh`.
//!
//! It probes the card, checks that NetworkManager leaves Owly's interfaces
//! alone, pings the gateway for a baseline, opens a window, waits for the
//! phone, has the tester send a photo each way, closes the window, and then
//! watches the station for the drop some drivers show after teardown. The
//! photos go through omdrop where it's installed (`omdrop on`, `omdrop
//! send`), whose hooks take the radio from owlyd, and the report says
//! whether omdrop-core or the Python implementation answered; otherwise this
//! takes the radio itself, and runs this binary's own `owly receive` and
//! `owly send`.
//!
//! The report names the card, the machine it's in, the driver, kernel, mode
//! and each step's result and timing. It holds no MAC or IP address, the
//! router's or the card's, no interface name (a USB adapter's `wlx…` name is
//! its MAC), not the phone's name, and nothing else about the network.

use std::ffi::OsStr;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use owlyd::api::{self, RadioProxy};
use serde::Serialize;
use tokio::process::Command;

use crate::doctor;
use crate::radio;

/// The interfaces NetworkManager must leave alone.
const OURS: [&str; 5] = ["awdl0", "owlymon0", "owlyibss0", "owlyap0", "owlygo0"];

/// Where distributions put NetworkManager when it isn't on `PATH`: openSUSE
/// has it in `/usr/sbin`, which a normal user's `PATH` leaves out.
const NM_DIRS: [&str; 2] = ["/usr/sbin", "/sbin"];

#[derive(clap::Args)]
pub struct Args {
    /// How long to watch Wi-Fi after teardown, in seconds (0 skips the
    /// watch).
    #[arg(long, default_value_t = 60)]
    watch: u32,
    /// What to send to the phone (default: a generated test image).
    #[arg(long)]
    file: Option<PathBuf>,
    /// The phone's AirDrop name (default: asked for).
    #[arg(long)]
    phone: Option<String>,
    /// Where to write the report (default: the current directory).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, Default, Serialize)]
struct Report {
    owly: &'static str,
    /// Seconds since 1970.
    time: u64,
    kernel: String,
    os: String,
    /// The maker and model, from DMI, such as `Framework Laptop 13`.
    machine: Option<String>,
    driver: Option<String>,
    device: Option<String>,
    status: Option<String>,
    mode: Option<String>,
    channel: Option<u64>,
    /// How the photos went: `owly`, `none`, or the omdrop implementation
    /// that answered, such as `omdrop-core 0.1.7` or `omdrop 0.18.2`.
    transfers: String,
    steps: Vec<Step>,
    wifi: Wifi,
}

#[derive(Debug, Serialize)]
struct Step {
    step: String,
    /// `pass`, `fail` or `skipped`.
    result: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ms: Option<u64>,
}

#[derive(Debug, Default, Serialize)]
struct Wifi {
    baseline: Option<Pings>,
    window: Option<Pings>,
    after: Option<Pings>,
}

/// A ping run against the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Pings {
    pub sent: u32,
    pub received: u32,
    /// The longest run of unanswered pings, a second each.
    pub longest_gap_s: u32,
}

impl Report {
    fn step(
        &mut self,
        step: &str,
        result: &'static str,
        detail: impl Into<String>,
        took: Option<Duration>,
    ) {
        let detail = detail.into();
        println!(
            "  -> {step}: {result}{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(" ({detail})")
            }
        );
        self.steps.push(Step {
            step: step.into(),
            result,
            detail,
            ms: took.map(|d| d.as_millis() as u64),
        });
    }
}

/// How the window is opened and the photos sent.
enum Path_ {
    Omdrop,
    /// This binary's own `receive` and `send`.
    Owly(PathBuf),
    None,
}

pub async fn run(bus: Option<&str>, args: Args) -> Result<ExitCode, String> {
    if nix::unistd::geteuid().is_root() {
        eprintln!(
            "owly: run test-card as yourself, not root: owlyd lends you the radio, and omdrop runs as you."
        );
        return Ok(ExitCode::from(2));
    }
    let mut report = Report {
        owly: env!("CARGO_PKG_VERSION"),
        time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        kernel: read("/proc/sys/kernel/osrelease"),
        os: os_name(),
        machine: machine(),
        transfers: "none".into(),
        ..Report::default()
    };

    heading("Probe");
    let caps = doctor::report(bus).await;
    print!("{}", doctor::text(&caps));
    let s = |k: &str| caps[k].as_str().map(String::from);
    let station = s("station").unwrap_or_default();
    report.driver = s("driver");
    report.device = s("device");
    report.status = s("status");
    report.mode = s("mode");
    report.channel = caps["channel"].as_u64();
    let out_dir = args.out.clone().unwrap_or_else(|| PathBuf::from("."));
    let file = out_dir.join(format!(
        "owly-test-{}-{}.json",
        report.driver.as_deref().unwrap_or("unknown"),
        report.time
    ));
    if !doctor::ready(&caps) {
        if caps["missing"].to_string().contains("allow_untested") {
            println!(
                "To test it anyway, put `allow_untested = true` in /etc/owly/radio.toml (as root), and run this again."
            );
        }
        report.step("probe", "fail", "not ready", None);
        return finish(&report, &file);
    }
    report.step("probe", "pass", "ready", None);

    nm_check(&mut report)?;

    let path = if which("omdrop") {
        Path_::Omdrop
    } else if let Ok(owly) = std::env::current_exe() {
        Path_::Owly(owly)
    } else {
        Path_::None
    };
    report.transfers = match path {
        Path_::Omdrop => omdrop_implementation().await,
        Path_::Owly(_) => "owly".into(),
        Path_::None => "none".into(),
    };

    let gateway = gateway(&station).await;
    if let Some(gw) = &gateway {
        heading("Baseline: ping the gateway for 10 s");
        let p = ping(&station, gw, Some(10)).await;
        report.wifi.baseline = p;
        if let Some(p) = p {
            report.step(
                "baseline",
                if p.received == 0 { "fail" } else { "pass" },
                format!("{}/{} replies", p.received, p.sent),
                None,
            );
            if p.received == 0 {
                println!(
                    "  The gateway didn't answer over Wi-Fi before Owly started, so Wi-Fi after teardown can't be judged. A firewall's strict reverse path check drops the replies when Ethernet is on the same network."
                );
            }
        }
    } else {
        report.step("baseline", "skipped", "Wi-Fi has no default route", None);
    }

    heading("Start");
    let radio = radio::connect(bus).await?;
    let started = Instant::now();
    let mut lease = None;
    let mut receiver = None;
    let wifi = crate::wifi::active();
    let ok = match &path {
        Path_::Omdrop => run_ok("omdrop", &["on", "forever"]).await,
        _ => match radio.acquire(0).await {
            Ok((l, _)) => {
                lease = Some(l);
                Ok(())
            }
            Err(e) => Err(radio::exit_code(&e).1),
        },
    };
    let took = started.elapsed();
    if let Err(e) = ok {
        report.step("start", "fail", e, Some(took));
        return finish(&report, &file);
    }
    report.step("start", "pass", "", Some(took));
    if let Path_::Owly(owly) = &path {
        let dir = std::env::temp_dir().join(format!("owly-test-{}", report.time));
        let _ = std::fs::create_dir_all(&dir);
        // It accepts by itself: its prompt would be hidden, and would
        // compete with this one for stdin.
        receiver = Command::new(owly)
            .args(["receive", "--accept", "--dir"])
            .arg(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok();
        println!("receiving into {}", dir.display());
    }
    let window_ping = match &gateway {
        Some(gw) => Some(spawn_ping(&station, gw, None)?),
        None => None,
    };

    heading("Find the phone");
    println!(
        "On the iPhone: Control Center > AirDrop > Everyone for 10 Minutes. Then open the share sheet on a photo, and keep the screen on."
    );
    let heard = wait_for_peers(&radio, Duration::from_secs(180)).await;
    println!();
    match &heard {
        Some(peers) => {
            println!("{}", peers.join("\n"));
            report.step("phone heard", "pass", "", None);
        }
        None => report.step("phone heard", "fail", "no AWDL peer in 180 s", None),
    }

    // The phone lists this computer only once a receiver answers its
    // /Discover.
    if matches!(path, Path_::None) {
        report.step(
            "phone -> computer",
            "skipped",
            "no AirDrop receiver: this owly binary can't find itself",
            None,
        );
    } else {
        let shown = ask("Does this computer show up in the iPhone's AirDrop share sheet?");
        report.step("shown on the phone", shown.result(), "", None);
        let got = ask("Send a photo from the iPhone to this computer. Did it arrive?");
        report.step("phone -> computer", got.result(), "", None);
    }

    if heard.is_some() && !matches!(path, Path_::None) {
        let photo = match &args.file {
            Some(f) => f.clone(),
            None => {
                let p = std::env::temp_dir().join(format!("owly-test-{}.png", report.time));
                std::fs::write(&p, test_image(report.time)).map_err(|e| e.to_string())?;
                p
            }
        };
        heading(&format!("Send {} to the phone", photo.display()));
        let phone = match &args.phone {
            Some(p) => p.clone(),
            None => prompt("The iPhone's AirDrop name (empty skips the send): "),
        };
        if phone.is_empty() {
            report.step("computer -> phone", "skipped", "no phone named", None);
        } else {
            println!("Accept it on the iPhone when asked.");
            let photo = photo.to_string_lossy().into_owned();
            let started = Instant::now();
            let sent = match &path {
                Path_::Omdrop => run_ok("omdrop", &["send", &phone, &photo]).await,
                Path_::Owly(owly) => {
                    run_ok(&owly.to_string_lossy(), &["send", "--to", &phone, &photo]).await
                }
                Path_::None => unreachable!(),
            };
            let took = started.elapsed();
            let arrived = ask("Did it arrive on the iPhone?");
            let detail = match sent {
                Ok(()) => String::new(),
                Err(e) => e,
            };
            report.step("computer -> phone", arrived.result(), detail, Some(took));
        }
    }

    heading("Stop");
    if let Some(p) = window_ping {
        report.wifi.window = stop_ping(p).await;
        if let Some(p) = report.wifi.window {
            println!(
                "Wi-Fi during the window: {}/{} replies, longest gap {} s",
                p.received, p.sent, p.longest_gap_s
            );
        }
    }
    drop(receiver);
    let started = Instant::now();
    let stopped = match (&path, lease) {
        (Path_::Omdrop, _) => run_ok("omdrop", &["off"]).await,
        (_, Some(l)) => {
            let released = radio.release(l).await.map_err(|e| e.to_string());
            crate::wifi::restore(wifi).await;
            released
        }
        _ => Ok(()),
    };
    let took = started.elapsed();
    match stopped {
        Ok(()) => report.step("stop", "pass", "", Some(took)),
        Err(e) => report.step("stop", "fail", e, Some(took)),
    }

    if gateway.is_some() && args.watch == 0 {
        report.step("Wi-Fi after teardown", "skipped", "--watch 0", None);
    } else if report.wifi.baseline.is_some_and(|p| p.received == 0) {
        report.step(
            "Wi-Fi after teardown",
            "skipped",
            "no replies in the baseline",
            None,
        );
    } else if let Some(gw) = &gateway {
        heading(&format!(
            "Watch Wi-Fi for {} s after teardown (Ctrl-C ends the watch early)",
            args.watch
        ));
        let p = watch(&station, gw, args.watch).await;
        report.wifi.after = p;
        if let Some(p) = p {
            let result = if p.longest_gap_s >= 5 { "fail" } else { "pass" };
            report.step(
                "Wi-Fi after teardown",
                result,
                format!(
                    "{}/{} replies, longest gap {} s",
                    p.received, p.sent, p.longest_gap_s
                ),
                None,
            );
            if p.longest_gap_s >= 5 {
                println!(
                    "  The station stopped receiving after teardown: this card needs reconnect_after_monitor = true."
                );
            }
        }
    }
    finish(&report, &file)
}

fn finish(report: &Report, file: &Path) -> Result<ExitCode, String> {
    heading("Summary");
    for s in &report.steps {
        println!("  {}: {}", s.step, s.result);
    }
    let json = serde_json::to_string_pretty(report).expect("the report serializes");
    std::fs::write(file, format!("{json}\n")).map_err(|e| format!("{}: {e}", file.display()))?;
    println!(
        "\nReport in {}. Attach it to the pull request or issue.",
        file.display()
    );
    Ok(if report.steps.iter().any(|s| s.result == "fail") {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn heading(s: &str) {
    println!("\n== {s}");
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn os_name() -> String {
    read("/etc/os-release")
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default()
}

/// Which implementation answers `omdrop` commands. omdrop runs the
/// Python one unless omdrop-core is installed and chosen, so a command on
/// PATH doesn't say: `omdrop version` adds an `omdrop-core` line for core.
async fn omdrop_implementation() -> String {
    let out = Command::new("omdrop").arg("version").output().await;
    implementation(&out.map_or_else(
        |_| String::new(),
        |o| String::from_utf8_lossy(&o.stdout).into_owned(),
    ))
}

/// `omdrop-core 0.1.7` where `omdrop version` lists core, else `omdrop
/// 0.18.2`, else `omdrop`.
fn implementation(version: &str) -> String {
    let line = |name: &str| {
        version
            .lines()
            .map(str::trim)
            .find(|l| l.split_whitespace().next() == Some(name))
    };
    line("omdrop-core")
        .or_else(|| line("omdrop"))
        .unwrap_or("omdrop")
        .to_string()
}

fn which(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join(program).is_file()))
}

/// The first `program` on `path`, else in `dirs`.
fn find_program(path: &OsStr, dirs: &[&str], program: &str) -> Option<PathBuf> {
    std::env::split_paths(path)
        .chain(dirs.iter().map(PathBuf::from))
        .map(|dir| dir.join(program))
        .find(|p| p.is_file())
}

/// The maker and model, from DMI. Lenovo puts the model's name in
/// `product_version`, and a number in `product_name`.
fn machine() -> Option<String> {
    let dmi = |f: &str| {
        Some(read(&format!("/sys/class/dmi/id/{f}"))).filter(|v| !v.is_empty() && !generic(v))
    };
    let vendor = dmi("sys_vendor");
    let model = if vendor.as_deref() == Some("LENOVO") {
        dmi("product_version").or_else(|| dmi("product_name"))
    } else {
        dmi("product_name").or_else(|| dmi("product_version"))
    };
    match (vendor, model) {
        (Some(v), Some(m)) if m.starts_with(&v) => Some(m),
        (Some(v), Some(m)) => Some(format!("{v} {m}")),
        (v, m) => v.or(m),
    }
}

/// What firmware puts in DMI fields it leaves unset.
fn generic(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    [
        "to be filled by o.e.m.",
        "system product name",
        "system manufacturer",
        "default string",
        "not applicable",
        "none",
        "o.e.m.",
    ]
    .contains(&v.as_str())
}

/// Its error names the subcommand but not the rest of the arguments, which
/// can hold the phone's name.
async fn run_ok(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .await
        .map_err(|e| format!("{program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        let sub = args.first().copied().unwrap_or_default();
        Err(format!("{program} {sub} exited with {status}"))
    }
}

/// NetworkManager has to leave Owly's interfaces alone, which the package's
/// configuration sees to. Managing them, it has kept the phone from ever
/// being heard, and crashed iwlwifi's firmware a second into the window.
fn nm_check(report: &mut Report) -> Result<(), String> {
    let running = std::process::Command::new("nmcli")
        .args(["-t", "-f", "RUNNING", "general"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "running");
    if !running {
        return Ok(());
    }
    heading("NetworkManager");
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found =
        find_program(&path, &NM_DIRS, "NetworkManager").and_then(|nm| Some((nm_config(&nm)?, nm)));
    let Some((config, nm)) = found else {
        report.step(
            "NetworkManager",
            "skipped",
            "can't read its configuration",
            None,
        );
        return Ok(());
    };
    let managed = nm_would_manage(&config);
    if managed.is_empty() {
        report.step(
            "NetworkManager",
            "pass",
            "leaves Owly's interfaces alone",
            None,
        );
        return Ok(());
    }
    report.step(
        "NetworkManager",
        "fail",
        format!("would manage {}", managed.join(", ")),
        None,
    );
    println!(
        "NetworkManager isn't told to leave {} alone, and the test is unlikely to pass while it manages them. The owly package installs /usr/lib/NetworkManager/conf.d/90-owly-unmanaged.conf for this: check `{} --print-config` for a file that overrides it.",
        managed.join(", "),
        nm.display()
    );
    if ask("Go on anyway?") != Answer::Yes {
        return Err("stopped".into());
    }
    Ok(())
}

/// NetworkManager's `--print-config`, or `None` where it can't give it. An
/// empty configuration would say it manages everything, which isn't known.
fn nm_config(nm: &Path) -> Option<String> {
    let out = std::process::Command::new(nm)
        .arg("--print-config")
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Which of Owly's interfaces NetworkManager's configuration doesn't leave
/// alone, from `NetworkManager --print-config`. That lists `[device*]`
/// sections highest priority first, and the first one that matches an
/// interface and sets `managed` decides it; keyfile's `unmanaged-devices`
/// counts where none does.
pub fn nm_would_manage(config: &str) -> Vec<&'static str> {
    let mut keyfile: Vec<&str> = Vec::new();
    // Each device section's match-device specs and its managed value.
    let mut devices: Vec<(Vec<&str>, Option<bool>)> = Vec::new();
    let mut section = "";
    for line in config.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name;
            if section.starts_with("device") {
                devices.push((Vec::new(), None));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let specs = || value.split([';', ',']).map(str::trim);
        match (section, key) {
            ("keyfile", "unmanaged-devices") => keyfile.extend(specs()),
            (s, "match-device") if s.starts_with("device") => {
                if let Some(d) = devices.last_mut() {
                    d.0.extend(specs());
                }
            }
            (s, "managed") if s.starts_with("device") => {
                if let Some(d) = devices.last_mut() {
                    d.1 = nm_bool(value);
                }
            }
            _ => {}
        }
    }
    OURS.iter()
        .copied()
        .filter(|n| {
            let named = |specs: &[&str]| specs.iter().any(|s| nm_names(s, n));
            let decided = devices
                .iter()
                .find_map(|(specs, managed)| managed.filter(|_| named(specs)));
            decided.unwrap_or(!named(&keyfile))
        })
        .collect()
}

/// Whether a NetworkManager device spec names the interface: exactly, or
/// as a glob ending in `*`.
fn nm_names(spec: &str, iface: &str) -> bool {
    let Some(name) = spec.strip_prefix("interface-name:") else {
        return false;
    };
    let name = name.strip_prefix('=').unwrap_or(name);
    match name.strip_suffix('*') {
        Some(prefix) => iface.starts_with(prefix),
        None => name == iface,
    }
}

fn nm_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

/// The station's IPv4 gateway, if it has a default route.
async fn gateway(station: &str) -> Option<String> {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default", "dev", station])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.split_whitespace()
        .skip_while(|w| *w != "via")
        .nth(1)
        .map(String::from)
}

/// Pings `gw` through `station`, so that a wired link to the same network,
/// whose route usually wins, doesn't answer for Wi-Fi.
fn ping_command(station: &str, gw: &str, count: Option<u32>) -> Command {
    let mut c = Command::new("ping");
    c.env("LC_ALL", "C")
        .args(["-O", "-i", "1", "-W", "1", "-I", station]);
    if let Some(n) = count {
        c.args(["-c", &n.to_string()]);
    }
    c.arg(gw).stdout(Stdio::piped()).stderr(Stdio::null());
    c
}

async fn ping(station: &str, gw: &str, count: Option<u32>) -> Option<Pings> {
    let out = ping_command(station, gw, count).output().await.ok()?;
    Some(pings(&String::from_utf8_lossy(&out.stdout)))
}

fn spawn_ping(
    station: &str,
    gw: &str,
    count: Option<u32>,
) -> Result<tokio::process::Child, String> {
    ping_command(station, gw, count)
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("ping: {e}"))
}

/// Ends a ping with SIGINT, as Ctrl-C would, and reads what it saw.
async fn stop_ping(child: tokio::process::Child) -> Option<Pings> {
    if let Some(pid) = child.id() {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGINT,
        );
    }
    let out = child.wait_with_output().await.ok()?;
    Some(pings(&String::from_utf8_lossy(&out.stdout)))
}

/// Pings for `seconds`, or until Ctrl-C.
async fn watch(station: &str, gw: &str, seconds: u32) -> Option<Pings> {
    let child = spawn_ping(station, gw, Some(seconds)).ok()?;
    let pid = child.id();
    let stop = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok()
            && let Some(pid) = pid
        {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGINT,
            );
        }
    });
    let out = child.wait_with_output().await.ok();
    stop.abort();
    Some(pings(&String::from_utf8_lossy(&out?.stdout)))
}

/// What a `ping -O` run saw: one line per reply (`icmp_seq=N ... time=`),
/// and one per ping unanswered by the next (`no answer yet for
/// icmp_seq=N`).
pub fn pings(text: &str) -> Pings {
    let mut answered = std::collections::BTreeSet::new();
    let mut sent = 0;
    for line in text.lines() {
        let Some(seq) = line
            .split_once("icmp_seq=")
            .and_then(|(_, r)| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        sent = sent.max(seq);
        if line.contains("bytes from") {
            answered.insert(seq);
        }
    }
    let mut longest = 0;
    let mut run = 0;
    for seq in 1..=sent {
        if answered.contains(&seq) {
            run = 0;
        } else {
            run += 1;
            longest = longest.max(run);
        }
    }
    Pings {
        sent,
        received: answered.len() as u32,
        longest_gap_s: longest,
    }
}

async fn wait_for_peers(radio: &RadioProxy<'_>, limit: Duration) -> Option<Vec<String>> {
    let start = Instant::now();
    while start.elapsed() < limit {
        if let Ok(peers) = radio.peers().await {
            let lines: Vec<_> = peers.iter().filter_map(api::peer_line).collect();
            if !lines.is_empty() {
                return Some(lines);
            }
        }
        print!(
            "\r  waiting for an AWDL peer... {:3} s",
            start.elapsed().as_secs()
        );
        let _ = std::io::stdout().flush();
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Yes,
    No,
    Skip,
}

impl Answer {
    fn result(self) -> &'static str {
        match self {
            Answer::Yes => "pass",
            Answer::No => "fail",
            Answer::Skip => "skipped",
        }
    }
}

fn prompt(q: &str) -> String {
    print!("{q}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line.trim().to_string()
}

fn ask(q: &str) -> Answer {
    loop {
        match prompt(&format!("{q} [y/n/s(kip)] ")).as_str() {
            "y" | "Y" => return Answer::Yes,
            "n" | "N" => return Answer::No,
            "s" | "S" | "" => return Answer::Skip,
            _ => {}
        }
    }
}

/// A 64×64 PNG in one colour, which the time picks, so the tester can tell
/// this run's photo from the last one's.
pub fn test_image(seed: u64) -> Vec<u8> {
    const SIDE: u32 = 64;
    let colour = [
        (seed >> 16) as u8 | 0x40,
        (seed >> 8) as u8 | 0x40,
        seed as u8 | 0x40,
    ];
    // Each row: filter type 0 (none), then its pixels.
    let row: Vec<u8> = std::iter::once(0)
        .chain(colour.iter().copied().cycle().take(3 * SIDE as usize))
        .collect();
    let raw = row.repeat(SIDE as usize);
    // zlib, with the data in stored (uncompressed) deflate blocks.
    let mut z = vec![0x78, 0x01];
    let mut chunks = raw.chunks(65_535).peekable();
    while let Some(c) = chunks.next() {
        z.push(u8::from(chunks.peek().is_none()));
        z.extend_from_slice(&(c.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        z.extend_from_slice(c);
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&SIDE.to_be_bytes());
    ihdr.extend_from_slice(&SIDE.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB
    for (ty, data) in [(b"IHDR", ihdr), (b"IDAT", z), (b"IEND", Vec::new())] {
        png.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut body = ty.to_vec();
        body.extend_from_slice(&data);
        png.extend_from_slice(&body);
        png.extend_from_slice(&crc32(&body).to_be_bytes());
    }
    png
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pings_count_replies_and_gaps() {
        let text = "\
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.1 ms
no answer yet for icmp_seq=2
no answer yet for icmp_seq=3
64 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=2.0 ms
no answer yet for icmp_seq=5

--- 192.168.1.1 ping statistics ---
5 packets transmitted, 2 received, 60% packet loss, time 4005ms
";
        assert_eq!(
            pings(text),
            Pings {
                sent: 5,
                received: 2,
                longest_gap_s: 2
            }
        );
        assert_eq!(pings("").sent, 0);
    }

    #[test]
    fn the_omdrop_implementation_comes_from_its_version() {
        let core = "omdrop 0.18.2\nomdrop-core 0.1.7\n";
        assert_eq!(implementation(core), "omdrop-core 0.1.7");
        assert_eq!(implementation("omdrop 0.18.2\n"), "omdrop 0.18.2");
        assert_eq!(implementation(""), "omdrop");
    }

    #[test]
    fn a_program_is_found_off_path() {
        let nowhere = OsStr::new("/nonexistent");
        let sh = Some(PathBuf::from("/bin/sh"));
        assert_eq!(find_program(nowhere, &["/bin"], "sh"), sh);
        assert_eq!(find_program(nowhere, &[], "sh"), None);
        assert_eq!(
            find_program(OsStr::new("/bin"), &["/nonexistent"], "sh"),
            sh
        );
    }

    #[test]
    fn a_config_that_cant_be_read_is_no_config() {
        assert_eq!(nm_config(Path::new("/nonexistent/NetworkManager")), None);
        assert_eq!(nm_config(Path::new("/bin/sh")), None);
        // NixOS has no /bin/echo, only /bin/sh.
        if Path::new("/bin/echo").exists() {
            let echoed = nm_config(Path::new("/bin/echo"));
            assert_eq!(echoed.as_deref(), Some("--print-config\n"));
        }
    }

    #[test]
    fn network_managers_unmanaged_list() {
        let config = "[keyfile]\nunmanaged-devices=interface-name:awdl0;interface-name:owlymon0,interface-name:owlyibss0\n";
        assert_eq!(nm_would_manage(config), ["owlyap0", "owlygo0"]);
        assert_eq!(nm_would_manage(""), OURS);
    }

    #[test]
    fn network_managers_device_sections() {
        // As the package installs it, beside legacy's keyfile list, which
        // used to replace it.
        let ours = include_str!("../../../packaging/90-owly-unmanaged.conf");
        let legacy = "[keyfile]\nunmanaged-devices=interface-name:awdl0;interface-name:mon0\n";
        assert!(nm_would_manage(ours).is_empty());
        assert!(nm_would_manage(&format!("{legacy}\n{ours}")).is_empty());
        // --print-config lists the section that wins first.
        let wins = "[device-zz]\nmatch-device=interface-name:owlyap0\nmanaged=1\n";
        assert_eq!(nm_would_manage(&format!("{wins}\n{ours}")), ["owlyap0"]);
        assert!(nm_would_manage(&format!("{ours}\n{wins}")).is_empty());
        // A section that doesn't set managed doesn't decide; a glob matches.
        let glob = "[device-a]\nmatch-device=interface-name:owly*\n[device-b]\nmatch-device=interface-name:owly*;interface-name:awdl0\nmanaged=no\n";
        assert!(nm_would_manage(glob).is_empty());
        // An empty override in /etc replaces the vendor file.
        assert_eq!(
            nm_would_manage("[device-owly-unmanaged]\nmanaged=1\n"),
            OURS
        );
    }

    #[test]
    fn the_test_image_is_a_png() {
        let png = test_image(0x123456);
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
        // The IHDR chunk's CRC, as any PNG reader checks it.
        let crc = u32::from_be_bytes(png[29..33].try_into().unwrap());
        assert_eq!(crc, crc32(&png[12..29]));
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }
}
