//! `omdrop-discoverable` against omdrop-awdl's helper contract (0.10.0,
//! `docs/radio-backend.md` in omdrop-plugin), the way Omdrop's bash and
//! Python version runs it: through pkexec, which clears the environment
//! (here, under the test seam, without root), and as a client of a fake
//! owlyd.
//!
//! 1. `start <seconds>` exits 0 once `awdl0` is up, and closes its output
//!    then: the window's supervisor runs on without it. 3 or 4 when it
//!    can't, the last stderr line a sentence; 5 when a window is already
//!    open, whose end it moves.
//! 2. `status --json` says whether the window is open, how long it has
//!    left, why the last one ended, and whether a peer has been heard.
//! 3. The window ends on `stop`, when it expires, and when its lease does.
//! 4. While it's open it announces, in the bursts owlyd's link asks for.
//! 5. `stop` is idempotent and safe with no window open.

mod fx;

use std::time::{Duration, Instant};

use fx::{Fx, PHONE, code, last_line};

fn status(fx: &Fx) -> serde_json::Value {
    let o = fx.helper(&["status", "--json"]);
    assert_eq!(code(&o), 0, "{o:?}");
    serde_json::from_slice(&o.stdout).unwrap()
}

/// `status --json`, once `done` holds of it, within 10 s.
fn status_once(fx: &Fx, done: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let s = status(fx);
        if done(&s) {
            return s;
        }
        assert!(Instant::now() < end, "status stayed {s}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The supervisor has gone: exited, or a zombie no one has reaped yet.
fn gone(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| Some(s.rsplit_once(')')?.1.split_whitespace().next()?.to_string()))
        .is_none_or(|state| state == "Z" || state == "X")
}

#[test]
fn probe_answers_as_the_hook_does() {
    let fx = Fx::new();
    let helper = fx.helper(&["probe", "--json"]);
    assert_eq!(code(&helper), 0);
    let hook = fx.run("probe", &["--json"]);
    assert_eq!(helper.stdout, hook.stdout);
    let json: serde_json::Value = serde_json::from_slice(&helper.stdout).unwrap();
    assert_eq!(json["backend"], "owl");
    assert_eq!(json["contract"], "0.10.0");
    assert_eq!(json["hardware"], true);
}

#[test]
fn a_window_from_start_to_stop() {
    let fx = Fx::new();
    assert_eq!(
        status(&fx),
        serde_json::json!({"visible": false, "remaining": null, "reason": "", "rx_proven": false, "peer_op": ""})
    );

    let o = fx.helper(&["start", "120"]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(fx.awdl0_up());
    assert_ne!(fx.lease(), None);
    let supervisor = fx.supervisor().unwrap();
    assert!(!gone(supervisor), "{}", status(&fx));
    let s = status(&fx);
    assert_eq!(s["visible"], true, "{s}");
    let remaining = s["remaining"].as_u64().unwrap();
    assert!((115..=120).contains(&remaining), "{s}");
    // Omdrop matches the text, not the JSON.
    let o = fx.helper(&["status", "--json"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("\"visible\":true"));

    // The fake radio has heard the phone.
    status_once(&fx, |s| s["rx_proven"] == true);
    let o = fx.helper(&["peers"]);
    assert_eq!(code(&o), 0);
    assert_eq!(
        String::from_utf8(o.stdout).unwrap(),
        format!("{PHONE} rssi=?\n")
    );

    // It announces in the link's bursts, plain, for Omdrop's receiver.
    let end = Instant::now() + Duration::from_secs(10);
    while fx.announced().is_empty() {
        assert!(Instant::now() < end, "no announcement");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        fx.announced()[0],
        "--iface awdl0 --plain --flags 137 --port 8771 --count 3 --interval 0.05"
    );

    // Omdrop asks again once its receiver is up, which moves the end.
    let o = fx.helper(&["start", "60"]);
    assert_eq!(code(&o), 5, "{o:?}");
    let remaining = status(&fx)["remaining"].as_u64().unwrap();
    assert!((55..=60).contains(&remaining));

    let o = fx.helper(&["stop"]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(!fx.awdl0_up());
    assert_eq!(fx.lease(), None);
    assert_eq!(
        status(&fx),
        serde_json::json!({"visible": false, "remaining": null, "reason": "stopped", "rx_proven": false, "peer_op": ""})
    );
    let end = Instant::now() + Duration::from_secs(5);
    while !gone(supervisor) {
        assert!(Instant::now() < end, "the supervisor outlived stop");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(fx.calls(), ["up", "down"]);
    assert_eq!(code(&fx.helper(&["peers"])), 4);
    assert_eq!(code(&fx.helper(&["stop"])), 0);
}

#[test]
fn a_window_ends_when_it_expires() {
    let fx = Fx::new();
    assert_eq!(code(&fx.helper(&["start", "1"])), 0);
    let s = status_once(&fx, |s| s["reason"] != "");
    assert_eq!(s["visible"], false);
    assert_eq!(s["reason"], "expired");
    assert!(!fx.awdl0_up());
    assert_eq!(fx.lease(), None);
    assert_eq!(fx.calls(), ["up", "down"]);
}

#[test]
fn a_window_of_0_s_lasts_until_stopped() {
    let fx = Fx::new();
    assert_eq!(code(&fx.helper(&["start", "0"])), 0);
    let s = status(&fx);
    assert_eq!(s["visible"], true, "{s}");
    assert_eq!(s["remaining"], serde_json::Value::Null);
    assert_eq!(code(&fx.helper(&["stop"])), 0);
    assert!(!fx.awdl0_up());
}

#[test]
fn a_lost_link_ends_the_window() {
    let fx = Fx::new();
    assert_eq!(code(&fx.helper(&["start", "120"])), 0);
    fx.fake("lose", "");
    let s = status_once(&fx, |s| s["reason"] != "");
    assert_eq!(s["visible"], false);
    assert_eq!(s["reason"], "radio-lost");
    assert!(!fx.awdl0_up());
    assert_eq!(fx.lease(), None);
}

#[test]
fn owlyd_stopping_ends_the_window() {
    let mut fx = Fx::new();
    assert_eq!(code(&fx.helper(&["start", "120"])), 0);
    let supervisor = fx.supervisor().unwrap();
    fx.stop_owlyd();
    let s = status(&fx);
    assert_eq!(s["visible"], false);
    let end = Instant::now() + Duration::from_secs(10);
    while !gone(supervisor) {
        assert!(Instant::now() < end, "the supervisor outlived owlyd");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(status(&fx)["reason"], "radio-lost");
}

#[test]
fn start_fails_with_a_sentence() {
    for (rc, say) in [("3", "Wi-Fi isn't connected."), ("4", "No radio here.")] {
        let fx = Fx::new();
        fx.fake("up.fail", &format!("{rc} {say}"));
        let o = fx.helper(&["start", "60"]);
        assert_eq!(code(&o).to_string(), rc);
        assert_eq!(last_line(&o.stderr), say);
        assert!(!fx.awdl0_up());
        assert_eq!(fx.supervisor(), None);
        assert_eq!(status(&fx)["visible"], false);
        assert_eq!(code(&fx.helper(&["stop"])), 0);
    }
}

#[test]
fn a_supervisor_that_died_leaves_a_window_start_can_reopen() {
    let fx = Fx::new();
    assert_eq!(code(&fx.helper(&["start", "120"])), 0);
    let first = fx.lease().unwrap();
    let supervisor = fx.supervisor().unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(supervisor),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while !gone(supervisor) {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(status(&fx)["visible"], false);
    let o = fx.helper(&["start", "120"]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert_ne!(fx.lease(), Some(first));
    assert_eq!(status(&fx)["visible"], true);
    assert_eq!(code(&fx.helper(&["stop"])), 0);
    assert_eq!(fx.calls(), ["up", "down", "up", "down"]);
}

#[test]
fn arguments_are_checked() {
    let fx = Fx::new();
    let bad: [&[&str]; 10] = [
        &[],
        &["start"],
        &["start", "-1"],
        &["start", "+5"],
        &["start", "99999999999999999999"],
        &["start", "1", "2"],
        &["stop", "now"],
        &["status", "--yaml"],
        &["probe"],
        &["__supervisor"],
    ];
    for args in bad {
        assert_eq!(code(&fx.helper(args)), 2, "{args:?}");
    }
    assert_eq!(fx.calls(), Vec::<String>::new());
}

#[test]
fn the_seam_needs_its_variable() {
    // Without the seam the helper drives the real radio, which needs root.
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let fx = Fx::new();
    let o = std::process::Command::new(fx.root.join("omdrop/omdrop-discoverable"))
        .args(["start", "60"])
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(code(&o), 2);
    assert_eq!(fx.lease(), None);
}

#[test]
fn the_sender_beside_the_helper_sends_links() {
    // Omdrop's bash version sends links only when `send-to-peer --help` offers `--url`.
    let o = std::process::Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/omdrop-awdl/send-to-peer"
    ))
    .arg("--help")
    .env_clear()
    .env("PATH", "/usr/bin:/bin")
    .output()
    .unwrap();
    assert_eq!(code(&o), 0);
    assert!(String::from_utf8_lossy(&o.stdout).contains("--url"));
}
