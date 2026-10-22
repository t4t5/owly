//! omdrop-core's radio backend hooks (`core/docs/backend-contract.md` in
//! omdrop-plugin, version 1), on Owly's radio.
//!
//! One binary, installed under each hook's name in `/usr/lib/omdrop/radio/`;
//! it acts on the name it's run by. `omdrop-owl <hook> <args>` does the
//! same, for trying them by hand.
//!
//! Each is a short client of owlyd, Owly's radio service, over the system
//! D-Bus API (`io.github.t4t5.Owly.Radio1`):
//!
//! | Hook | What it does |
//! |---|---|
//! | `probe --json` | owlyd's `Probe()`, as the contract's JSON |
//! | `up` | takes a lease with `AcquireDetached(0)`, which outlives the hook; exits once `awdl0` is up, printing the announcement burst |
//! | `tick <seq>` | exits 4 when the lease is gone, with owlyd's `LastEnd` reason, so core ends the window |
//! | `down <why>` | `Release`s the lease, which returns once owlyd has given Wi-Fi back |
//! | `peers` | owlyd's `Peers`, `<mac> rssi=?` per AWDL peer |
//!
//! The lease is detached because `up` and `down` are different processes:
//! it ends on `down`, or when the link is lost or owlyd stops, but not when
//! `up` exits. A window core loses track of (its supervisor killed) is
//! core's to close with `down`, as it does on its next `stop` or `start`.
//!
//! The hooks' run directory, `/run/omdrop-owl`, holds `lease`, the
//! window's lease number.
//!
//! Under the name `omdrop-discoverable` it's omdrop-awdl's helper instead,
//! for Omdrop's bash and Python version (`discoverable`), on the same
//! owlyd calls.
//!
//! **Test seam.** Like omdrop-radio, the hooks honour
//! `OMDROP_RADIO_TEST_ROOT` only when neither the real nor the effective
//! user is root and the exec wasn't marked secure. Under it, the run
//! directory moves into that root, and owlyd is the one on the bus whose
//! address is in `<root>/owly-fake/bus`: an `owlyd --fake`, whose fake
//! `awdl0` is the one omdrop-radio's own conformance tests check.
//! `omdrop-discoverable` honours it too, and finds omdrop-awdl's tools in
//! `<root>/omdrop`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use owly_radio::radio::{Announce, Capabilities, Missing};
use owly_radio::rundir::RunDir;
use owlyd::api::{self, LinkInfo, RadioProxy};
use tokio::signal::unix::{SignalKind, signal};

mod discoverable;

/// This contract's version, reported by `probe`.
const HOOKS: u32 = 1;

/// The omdrop-awdl helper contract `omdrop-discoverable` follows, reported
/// by `probe`: Omdrop's doctor wants one from every backend that probes. It
/// is also the version of omdrop-awdl's tools installed beside the helper.
const CONTRACT: &str = "0.10.0";

/// The hooks' own run directory, with the window's lease. owlyd's is
/// `/run/owly`.
const RUN_DIR: &str = "/run/omdrop-owl";

/// How long `down` waits for `Release`, which returns once Wi-Fi is back.
/// A teardown waits up to 21 s to reconnect, and the hook has 60 s in all.
const RELEASE: Duration = Duration::from_secs(30);

/// Before that, how long it waits for a setup that a cancelled `up` left
/// running to finish.
const SETTLE: Duration = Duration::from_secs(25);

/// `tick` runs every few seconds, and the window doesn't announce while it
/// does.
const TICK_LIMIT: Duration = Duration::from_secs(5);

/// `up`'s timeout is 300 s; setting up takes well under a minute.
const UP_LIMIT: Duration = Duration::from_secs(240);

/// The reasons core passes to `down`.
const WHYS: [&str; 4] = ["stopped", "expired", "start-failed", "radio-lost"];

fn main() -> ExitCode {
    let mut argv = std::env::args();
    let arg0 = argv.next().unwrap_or_default();
    let mut args: Vec<String> = argv.collect();
    let mut hook = Path::new(&arg0)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if hook == "omdrop-owl" && !args.is_empty() {
        hook = args.remove(0);
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let env = Env::new();
    match (hook.as_str(), &args[..]) {
        ("omdrop-discoverable", args) => discoverable::run(&env, args),
        ("probe", ["--json"]) => probe(&env),
        ("up", []) => up(&env),
        ("tick", [seq]) if canonical(seq) => tick(&env),
        ("down", [why]) if WHYS.contains(why) => down(&env, why),
        ("peers", []) => peers(&env),
        _ => {
            eprintln!(
                "usage: omdrop-owl probe --json | up | tick <seq> | down <why> | peers | omdrop-discoverable <command> (got {hook} {args:?})"
            );
            ExitCode::from(2)
        }
    }
}

/// The contract's canonical decimal, 1 to 2⁶³−1.
fn canonical(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('0')
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<i64>().is_ok()
}

/// Where the hooks keep state, and where owlyd is.
struct Env {
    run: RunDir,
    /// The bus owlyd is on: the system bus, or the test seam's.
    bus: Option<String>,
    /// omdrop-awdl's tools, beside `omdrop-discoverable`.
    tools: PathBuf,
    /// The test seam's root.
    test_root: Option<PathBuf>,
}

impl Env {
    fn new() -> Self {
        match test_root() {
            Some(root) => Env {
                run: RunDir::new(root.join("run/omdrop-owl")),
                bus: std::fs::read_to_string(root.join("owly-fake/bus"))
                    .ok()
                    .map(|a| a.trim().to_string()),
                tools: root.join("omdrop"),
                test_root: Some(root),
            },
            None => Env {
                run: RunDir::new(RUN_DIR),
                bus: None,
                tools: PathBuf::from(discoverable::TOOLS),
                test_root: None,
            },
        }
    }

    async fn radio(&self) -> zbus::Result<RadioProxy<'static>> {
        let address = match (&self.test_root, &self.bus) {
            (Some(_), None) => {
                return Err(zbus::Error::Address("no test bus".into()));
            }
            (_, bus) => bus.as_deref(),
        };
        let conn = api::connect(address).await?;
        api::radio(&conn).await
    }

    /// The window's lease, as `up` recorded it.
    fn lease(&self) -> Option<u64> {
        self.run.read("lease")?.trim().parse().ok()
    }

    /// `say`: what runs it as root.
    fn need_root(&self, say: &str) -> Result<(), ExitCode> {
        if self.test_root.is_some() || nix::unistd::geteuid().is_root() {
            Ok(())
        } else {
            eprintln!("{say}");
            Err(ExitCode::from(2))
        }
    }
}

/// What to tell someone when owlyd can't be reached.
fn no_owlyd(e: &zbus::Error) -> String {
    format!(
        "Owly's radio service, owlyd, isn't running ({e}). `systemctl enable --now owlyd` starts it."
    )
}

/// omdrop-radio's seam: honoured only without root, and not in a secure
/// exec (setuid, setgid or file capabilities).
fn test_root() -> Option<PathBuf> {
    let root = std::env::var_os("OMDROP_RADIO_TEST_ROOT")?;
    let unprivileged = !nix::unistd::getuid().is_root() && !nix::unistd::geteuid().is_root();
    (unprivileged && !at_secure() && !root.is_empty()).then(|| PathBuf::from(root))
}

/// `AT_SECURE` from the auxiliary vector; true when it can't be read.
fn at_secure() -> bool {
    const AT_SECURE: u64 = 23;
    let Ok(auxv) = std::fs::read("/proc/self/auxv") else {
        return true;
    };
    let word = std::mem::size_of::<usize>();
    let value = |b: &[u8]| {
        let mut v = [0; 8];
        v[..word].copy_from_slice(b);
        u64::from_ne_bytes(v)
    };
    auxv.chunks_exact(2 * word)
        .find(|pair| value(&pair[..word]) == AT_SECURE)
        .is_none_or(|pair| value(&pair[word..]) != 0)
}

fn probe(env: &Env) -> ExitCode {
    let caps = runtime().block_on(async {
        let answer = async {
            let radio = env.radio().await?;
            radio.probe().await
        };
        match tokio::time::timeout(Duration::from_secs(4), answer).await {
            Ok(Ok(json)) => serde_json::from_str::<serde_json::Value>(&json)
                .map_err(|e| format!("owlyd's probe: {e}")),
            Ok(Err(e)) => Err(no_owlyd(&e)),
            Err(_) => Err("Owly's radio service, owlyd, didn't answer.".to_string()),
        }
    });
    let json = match caps {
        Ok(caps) => caps,
        // Without owlyd, the probe runs here, and says what's missing.
        Err(say) => {
            let mut caps = local_probe(env);
            caps.missing.insert(0, Missing { id: "backend", say });
            serde_json::to_value(&caps).expect("capabilities serialize")
        }
    };
    let missing: Vec<_> = json["missing"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| serde_json::json!({ "id": m["id"], "say": m["say"] }))
        .collect();
    let out = serde_json::json!({
        // omdrop's name for this backend, whichever of owlyd's runs.
        "backend": "owl",
        "version": env!("CARGO_PKG_VERSION"),
        "contract": CONTRACT,
        "hooks": HOOKS,
        "hardware": json["hardware"].as_bool().unwrap_or(false),
        "missing": missing,
    });
    println!("{out}");
    ExitCode::SUCCESS
}

/// The probe without owlyd: the same report, from here.
fn local_probe(env: &Env) -> Capabilities {
    if env.test_root.is_some() {
        return Capabilities::none();
    }
    owly_radio::probe::from_config(RunDir::new("/run/owly"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime")
}

/// Takes the lease and records it.
fn up(env: &Env) -> ExitCode {
    if let Err(code) = env.need_root("Owly's radio hooks run as root, through omdrop-radio.") {
        return code;
    }
    match runtime().block_on(acquire(env)) {
        Ok(link) => {
            println!("{}", announce_json(link.and_then(|l| l.announce)));
            ExitCode::SUCCESS
        }
        Err((code, say)) => {
            if !say.is_empty() {
                eprintln!("{say}");
            }
            ExitCode::from(code)
        }
    }
}

/// Takes a detached lease, which outlives this process, and records it in
/// the run directory: Ok once `awdl0` is up, with the link it carries, or
/// the exit code and sentence for why not. 3 is retryable; SIGTERM is 3
/// with no sentence.
async fn acquire(env: &Env) -> Result<Option<LinkInfo>, (u8, String)> {
    if let Err(e) = env.run.create() {
        return Err((
            4,
            format!(
                "Owly can't create its run directory {}: {e}",
                env.run.path().display()
            ),
        ));
    }
    let mut term = signal(SignalKind::terminate()).expect("a SIGTERM handler");
    let radio = env.radio().await.map_err(|e| (4, no_owlyd(&e)))?;
    // A window is opened only with none open, so a detached lease is one a
    // window its owner lost track of left.
    if let Ok(leftover @ 1..) = radio.lease().await
        && radio.release(leftover).await.is_ok()
    {
        eprintln!("owly: gave back lease {leftover}, left by an earlier window");
    }
    env.run.remove("lease");
    let result = tokio::select! {
        r = radio.acquire_detached(0) => r,
        () = tokio::time::sleep(UP_LIMIT) => {
            return Err((3, "AirDrop's radio took too long to come up.".into()));
        }
        // Cancelled: owlyd finishes the setup, and `down start-failed`
        // gives it back.
        _ = term.recv() => return Err((3, String::new())),
    };
    let (lease, link) = result.map_err(|e| match api::api_error(&e) {
        Some(("NotNow" | "Busy", m)) => (3, m),
        Some((_, m)) => (4, m),
        None if api::unreachable(&e) => (4, no_owlyd(&e)),
        None => (4, format!("AirDrop's radio didn't come up: {e}")),
    })?;
    if let Err(e) = env.run.write("lease", format!("{lease}\n").as_bytes()) {
        let _ = radio.release(lease).await;
        return Err((4, format!("Owly can't record its radio session: {e}")));
    }
    let link = LinkInfo::from_dict(&link);
    eprintln!("owly: lease {lease}: {link:?}");
    Ok(link)
}

/// `None` while `lease` is owlyd's current one, and once it has ended, why:
/// owlyd's `LastEnd` reason, or nothing if another lease has ended since.
async fn ended(env: &Env, lease: u64) -> zbus::Result<Option<String>> {
    let radio = env.radio().await?;
    if radio.lease().await? == lease {
        return Ok(None);
    }
    let why = match radio.last_end().await? {
        (ended, why) if ended == lease => why,
        _ => String::new(),
    };
    Ok(Some(why))
}

fn tick(env: &Env) -> ExitCode {
    let Some(lease) = env.lease() else {
        eprintln!("AirDrop's radio isn't up.");
        return ExitCode::from(4);
    };
    let checked =
        runtime().block_on(async { tokio::time::timeout(TICK_LIMIT, ended(env, lease)).await });
    let why = match checked {
        Ok(Ok(None)) => return ExitCode::SUCCESS,
        Ok(Ok(Some(why))) => why,
        Ok(Err(e)) if api::unreachable(&e) => "Owly's radio service stopped".into(),
        Ok(Err(e)) => {
            eprintln!("owly: asking owlyd: {e}");
            return ExitCode::from(1);
        }
        Err(_) => {
            eprintln!("owly: owlyd didn't answer");
            return ExitCode::from(1);
        }
    };
    let why = why.strip_prefix("lost: ").unwrap_or(&why);
    if why.is_empty() {
        eprintln!("AirDrop's radio went down.");
    } else {
        eprintln!("AirDrop's radio went down: {why}.");
    }
    ExitCode::from(4)
}

fn down(env: &Env, why: &str) -> ExitCode {
    if let Err(code) = env.need_root("Owly's radio hooks run as root, through omdrop-radio.") {
        return code;
    }
    if !runtime().block_on(release(env)) {
        eprintln!("Owly's radio service is still giving Wi-Fi back.");
        return ExitCode::from(3);
    }
    eprintln!("owly: radio down ({why})");
    ExitCode::SUCCESS
}

/// Gives the window's lease back, and forgets it: true once owlyd has
/// given Wi-Fi back, or there was nothing to give back.
async fn release(env: &Env) -> bool {
    let recorded = env.lease();
    let released = async {
        let Ok(radio) = env.radio().await else {
            // No owlyd, so nothing of ours is up.
            return true;
        };
        // An `up` cancelled mid-setup left owlyd to finish it, and the
        // lease, unrecorded, to us.
        let end = tokio::time::Instant::now() + SETTLE;
        while matches!(radio.current_state().await.as_deref(), Ok("starting"))
            && tokio::time::Instant::now() < end
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let lease = match recorded {
            Some(l) => l,
            None => radio.lease().await.unwrap_or(0),
        };
        if lease == 0 {
            return true;
        }
        match tokio::time::timeout(RELEASE, radio.release(lease)).await {
            Ok(Ok(())) => true,
            // Already over, or not ours: someone else's lease.
            Ok(Err(e)) if api::unreachable(&e) => true,
            Ok(Err(e)) if matches!(api::api_error(&e), Some(("StaleLease", _))) => true,
            Ok(Err(e)) => {
                eprintln!("owly: releasing lease {lease}: {e}");
                false
            }
            Err(_) => false,
        }
    }
    .await;
    if released {
        env.run.remove("lease");
    }
    released
}

fn peers(env: &Env) -> ExitCode {
    let Some(lease) = env.lease() else {
        eprintln!("AirDrop's radio isn't up.");
        return ExitCode::from(4);
    };
    let peers = runtime().block_on(async {
        let radio = env.radio().await?;
        if radio.lease().await? != lease {
            return Ok(None);
        }
        radio.peers().await.map(Some)
    });
    match peers {
        Ok(Some(peers)) => {
            for p in peers.iter().filter_map(api::peer_line) {
                println!("{p}");
            }
            ExitCode::SUCCESS
        }
        Ok(None) => {
            eprintln!("AirDrop's radio isn't up.");
            ExitCode::from(4)
        }
        Err(e) => {
            eprintln!("{}", no_owlyd(&e));
            ExitCode::from(4)
        }
    }
}

/// `up`'s stdout for core: the burst its announcer repeats in (MDNS-7).
/// `plain`: owly-awdl adds AWDL's encapsulation itself.
fn announce_json(announce: Option<Announce>) -> serde_json::Value {
    match announce {
        Some(a) => serde_json::json!({
            "announce": {
                "count": a.count,
                "interval_us": a.interval.as_micros() as u64,
                "period_s": a.pause.as_secs().max(1),
                "plain": true,
            }
        }),
        None => serde_json::json!({}),
    }
}
