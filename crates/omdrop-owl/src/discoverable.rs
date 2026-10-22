//! omdrop-awdl's helper, `omdrop-discoverable`, which Omdrop's bash and
//! Python version runs through pkexec (`docs/radio-backend.md` in
//! omdrop-plugin, helper contract 0.10.0). Where omdrop-core is installed,
//! Omdrop runs the hooks instead; this is for Omdrop without it, until
//! Omdrop retires that version.
//!
//! | Command | What it does |
//! |---|---|
//! | `start <seconds>` | takes the lease, as `up` does, and leaves a supervisor running the window (0 s: until `stop`). 0 once `awdl0` is up; 3 or 4 as `up`; 5 when a window is already open, which then ends `<seconds>` from now |
//! | `stop` | ends the window, as `down` does. Always 0 |
//! | `status [--json]` | whether a window is open, how long it has left, why the last one ended, and whether a peer has been heard in it. Unprivileged |
//! | `peers` | as the `peers` hook |
//! | `probe --json` | as the `probe` hook |
//!
//! Under core, core supervises the window and announces in it. Here the
//! supervisor does, a process of its own (`__supervise`): it ends the
//! window when it expires or its lease does, and runs omdrop-awdl's
//! announcer, `awdl-airdrop-adv.py`, in the bursts owlyd's link asks for.
//! omdrop-awdl's sender, `send-to-peer`, and the rest of its tools are
//! installed beside the helper, unmodified (`omdrop-awdl/` in this crate).
//!
//! It shares the hooks' run directory, and `lease` in it. The window's own
//! files are `supervisor` (its pid and start time), `until` (when it ends, in Unix seconds,
//! or 0 for on `stop`), `rx-proven` (a peer has been heard) and
//! `announce.log`, with `reason` saying why the last window ended. `lock`
//! is held across `start`, `stop` and the supervisor ending the window.

use std::fs::File;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime};

use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use owly_radio::radio::Announce;
use owlyd::api::{self, LinkInfo};

use super::{Env, TICK_LIMIT, runtime};

/// Where Omdrop finds the helper, with omdrop-awdl's tools beside it.
pub const TOOLS: &str = "/usr/lib/omdrop";

/// The announcement's receiver flags, as omdrop-awdl sends them: 0x88
/// (SUPPORTS_MIXED_TYPES | SUPPORTS_DISCOVER_MAYBE) + SUPPORTS_URL.
const FLAGS: &str = "137";

/// The port Omdrop's Python receiver listens on.
const PORT: &str = "8771";

/// A burst takes a second at most; one that takes this long is killed.
const BURST_LIMIT: Duration = Duration::from_secs(10);

/// How long `status`, which Omdrop's panel asks often, waits for owlyd.
const STATUS_LIMIT: Duration = Duration::from_secs(2);

const AS_ROOT: &str = "omdrop-discoverable runs as root, through pkexec.";

pub fn run(env: &Env, args: &[&str]) -> ExitCode {
    match args {
        ["start", secs] if !secs.is_empty() && secs.bytes().all(|b| b.is_ascii_digit()) => {
            match secs.parse() {
                Ok(secs) => start(env, secs),
                Err(_) => usage(args),
            }
        }
        ["stop"] => stop(env),
        ["status"] => status(env, false),
        ["status", "--json"] => status(env, true),
        ["peers"] => super::peers(env),
        ["probe", "--json"] => super::probe(env),
        ["__supervise"] => supervise(env),
        _ => usage(args),
    }
}

fn usage(args: &[&str]) -> ExitCode {
    eprintln!(
        "usage: omdrop-discoverable start <seconds> | stop | status [--json] | peers | probe --json (got {args:?})"
    );
    ExitCode::from(2)
}

fn start(env: &Env, secs: u64) -> ExitCode {
    if let Err(code) = env.need_root(AS_ROOT) {
        return code;
    }
    if let Err(e) = env.run.create() {
        eprintln!(
            "Owly can't create its run directory {}: {e}",
            env.run.path().display()
        );
        return ExitCode::from(4);
    }
    let _lock = match lock(env) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Owly can't lock its run directory: {e}");
            return ExitCode::from(4);
        }
    };
    let until = if secs == 0 {
        0
    } else {
        now().saturating_add(secs)
    };
    if supervisor(env).is_some() {
        let _ = env.run.write("until", format!("{until}\n").as_bytes());
        eprintln!("owly: already discoverable, now {}", lasting(secs));
        return ExitCode::from(5);
    }
    for f in ["reason", "rx-proven"] {
        env.run.remove(f);
    }
    let _ = env.run.write("announce.log", b"");
    if let Err((code, say)) = runtime().block_on(super::acquire(env)) {
        if !say.is_empty() {
            eprintln!("{say}");
        }
        return ExitCode::from(code);
    }
    let recorded = env.run.write("until", format!("{until}\n").as_bytes());
    let spawned = recorded.and_then(|()| {
        let supervisor = Command::new(std::env::current_exe()?)
            .args(["omdrop-discoverable", "__supervise"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()?;
        let pid = supervisor.id() as i32;
        let since = started(pid).ok_or_else(|| std::io::Error::other("it exited at once"))?;
        env.run
            .write("supervisor", format!("{pid} {since}\n").as_bytes())
    });
    if let Err(e) = spawned {
        // A supervisor whose pid isn't recorded exits by itself.
        end(env, "start-failed");
        eprintln!("Owly can't start the window's supervisor: {e}");
        return ExitCode::from(4);
    }
    eprintln!("owly: discoverable {}", lasting(secs));
    ExitCode::SUCCESS
}

fn lasting(secs: u64) -> String {
    match secs {
        0 => "until stopped".into(),
        s => format!("for {s} s"),
    }
}

fn stop(env: &Env) -> ExitCode {
    if let Err(code) = env.need_root(AS_ROOT) {
        return code;
    }
    let _ = env.run.create();
    // Ending the window matters more than the lock, which only orders it
    // with a start or the supervisor.
    let _lock = lock(env).ok();
    if let Some(pid) = supervisor(env) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGTERM);
    }
    end(env, "stopped");
    ExitCode::SUCCESS
}

/// Ends the window, with the lock held: gives the radio back, and records
/// why.
fn end(env: &Env, why: &str) {
    if !runtime().block_on(super::release(env)) {
        eprintln!("Owly's radio service is still giving Wi-Fi back.");
    }
    for f in ["supervisor", "until", "rx-proven"] {
        env.run.remove(f);
    }
    let _ = env.run.write("reason", why.as_bytes());
    eprintln!("owly: radio down ({why})");
}

fn status(env: &Env, json: bool) -> ExitCode {
    // Open while its supervisor runs, unless owlyd says the lease has ended
    // before the supervisor has noticed. An owlyd slow to answer is left to
    // the supervisor.
    let visible = supervisor(env).is_some()
        && env.lease().is_some_and(|lease| {
            let ended = runtime().block_on(async {
                tokio::time::timeout(STATUS_LIMIT, super::ended(env, lease)).await
            });
            match ended {
                Ok(Ok(ended)) => ended.is_none(),
                Ok(Err(e)) => !api::unreachable(&e),
                Err(_) => true,
            }
        });
    let remaining = match until(env) {
        Some(u @ 1..) if visible => u.saturating_sub(now()).to_string(),
        _ => "null".into(),
    };
    let reason = env.run.read("reason").unwrap_or_default();
    let reason = reason.trim();
    let rx = visible && env.run.read("rx-proven").is_some();
    if json {
        // Omdrop reads `"visible":true` as text: no spaces.
        println!(
            "{{\"visible\":{visible},\"remaining\":{remaining},\"reason\":{},\"rx_proven\":{rx},\"peer_op\":\"\"}}",
            serde_json::Value::from(reason)
        );
    } else {
        println!("visible={visible} remaining={remaining} reason={reason} rx_proven={rx}");
    }
    ExitCode::SUCCESS
}

/// The window's background half, which `start` leaves running: ends the
/// window when it expires or its lease does, notes the first peer heard,
/// and announces.
fn supervise(env: &Env) -> ExitCode {
    // `start` holds the lock until it has recorded this process.
    drop(lock(env));
    let rt = runtime();
    let me = std::process::id() as i32;
    let link = rt
        .block_on(async { env.radio().await?.link().await })
        .ok()
        .and_then(|d| LinkInfo::from_dict(&d));
    let iface = link
        .as_ref()
        .map_or_else(|| "awdl0".to_string(), |l| l.interface.clone());
    let burst = link.and_then(|l| l.announce).unwrap_or(Announce::SHARED);
    loop {
        // Stopped, or replaced by another window.
        if supervisor(env) != Some(me) {
            return ExitCode::SUCCESS;
        }
        let until = until(env).unwrap_or(0);
        let why = if until > 0 && now() >= until {
            Some("expired")
        } else if let Some(lease) = env.lease() {
            let ended = rt.block_on(async {
                tokio::time::timeout(TICK_LIMIT, super::ended(env, lease)).await
            });
            match ended {
                Ok(Ok(None)) => None,
                Ok(Ok(Some(_))) => Some("radio-lost"),
                Ok(Err(e)) if api::unreachable(&e) => Some("radio-lost"),
                // owlyd is slow to answer: ask again next time.
                _ => None,
            }
        } else {
            Some("radio-lost")
        };
        if let Some(why) = why {
            let _lock = lock(env).ok();
            if supervisor(env) == Some(me) {
                end(env, why);
            }
            return ExitCode::SUCCESS;
        }
        if env.run.read("rx-proven").is_none() && rt.block_on(heard(env)) {
            let _ = env.run.write("rx-proven", b"");
        }
        announce(env, &iface, burst);
        let pause = match until {
            0 => burst.pause,
            u => burst
                .pause
                .min(Duration::from_secs(u.saturating_sub(now()))),
        };
        std::thread::sleep(pause);
    }
}

/// Whether owlyd has heard a peer: the window receives, as well as
/// transmits.
async fn heard(env: &Env) -> bool {
    let peers = tokio::time::timeout(TICK_LIMIT, async { env.radio().await?.peers().await });
    matches!(peers.await, Ok(Ok(p)) if !p.is_empty())
}

/// One burst of omdrop-awdl's announcement, sent plain: owly-awdl adds
/// AWDL's encapsulation itself.
fn announce(env: &Env, iface: &str, burst: Announce) {
    let log = File::options()
        .create(true)
        .append(true)
        .open(env.run.path().join("announce.log"));
    let (stdout, stderr) = match log.and_then(|f| Ok((f.try_clone()?, f))) {
        Ok((out, err)) => (Stdio::from(out), Stdio::from(err)),
        Err(_) => (Stdio::null(), Stdio::null()),
    };
    let child = Command::new(env.tools.join("awdl-airdrop-adv.py"))
        .args([
            "--iface", iface, "--plain", "--flags", FLAGS, "--port", PORT,
        ])
        .args(["--count", &burst.count.to_string()])
        .args(["--interval", &burst.interval.as_secs_f64().to_string()])
        // Run as root, Python would leave `__pycache__` in /usr/lib/omdrop,
        // which no package owns.
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn();
    let Ok(mut child) = child else {
        return;
    };
    let end = Instant::now() + BURST_LIMIT;
    while matches!(child.try_wait(), Ok(None)) {
        if Instant::now() > end {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The window's supervisor, if it's running: the process `start` recorded,
/// by its pid and its start time, so not another that has since been given
/// the same pid.
fn supervisor(env: &Env) -> Option<i32> {
    let recorded = env.run.read("supervisor")?;
    let (pid, since) = recorded.trim().split_once(' ')?;
    let pid = pid.parse().ok()?;
    (started(pid)? == since.parse::<u64>().ok()?).then_some(pid)
}

/// When a running process started, in clock ticks since boot, from
/// `/proc/<pid>/stat`: `None` once it has exited, zombie or not. (Its
/// `cmdline` won't do: that reads empty for a moment after `spawn` returns,
/// until the kernel has set up the new program's arguments.)
fn started(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The fields after the command name, which may hold spaces and
    // parentheses: the state, field 3, then the start time, field 22.
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    if matches!(fields.first(), Some(&("Z" | "X"))) {
        return None;
    }
    fields.get(19)?.parse().ok()
}

/// When the window ends, in Unix seconds: 0 for on `stop`.
fn until(env: &Env) -> Option<u64> {
    env.run.read("until")?.trim().parse().ok()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Orders `start`, `stop` and the supervisor's ending of the window.
fn lock(env: &Env) -> std::io::Result<Flock<File>> {
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(env.run.path().join("lock"))?;
    Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, e)| e.into())
}
