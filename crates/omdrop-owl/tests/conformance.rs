//! The hooks against omdrop-core's backend contract (version 1,
//! "Conformance"), the way omdrop-radio runs them: through the test seam
//! (`OMDROP_RADIO_TEST_ROOT`, no root), with a cleared environment,
//! `/dev/null` on stdin and a process group of their own, as clients of a
//! fake owlyd: owlyd's service on the fake radio, on a private bus.
//!
//! 1. `probe --json` answers within 5 s without root.
//! 2. `up` exits 0 only with `awdl0` up and a link-local address; 3 or 4
//!    otherwise, the last stderr line a sentence.
//! 3. Every hook exits within its timeout, never reads stdin, and needs
//!    nothing from the environment beyond the contract's variables.
//! 4. `up` survives SIGTERM mid-run without leaving the radio worse than a
//!    later `up` can repair.
//! 5. `down` is idempotent and safe with no window open.
//! 6. No hook writes core's run-directory files.
//! 7. (`peer-watch` isn't provided.)

mod fx;

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::Child;
use std::time::{Duration, Instant};

use fx::{Fx, PHONE, code, last_line};

#[test]
fn probe_answers_without_root() {
    let fx = Fx::new();
    let start = Instant::now();
    let o = fx.run_within("probe", &["--json"], Duration::from_secs(5));
    assert!(start.elapsed() < Duration::from_secs(5));
    assert_eq!(code(&o), 0);
    let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(json["backend"], "owl");
    // omdrop-awdl's helper contract, which Omdrop's doctor wants from
    // every backend.
    assert_eq!(json["contract"], "0.10.0");
    assert_eq!(json["hooks"], 1);
    assert_eq!(json["hardware"], true);
    assert_eq!(json["missing"], serde_json::json!([]));
    assert_eq!(fx.calls(), Vec::<String>::new(), "probe changes nothing");
}

#[test]
fn a_window_from_up_to_down() {
    let fx = Fx::new();
    let start = Instant::now();
    let o = fx.run("up", &[]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    // The pipes closed with `up`, and the lease outlived it.
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(fx.awdl0_up());
    assert_ne!(fx.lease(), None);

    // The announcement burst for core's announcer (MDNS-7).
    let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"announce": {"count": 3, "interval_us": 50000, "period_s": 3, "plain": true}})
    );

    assert_eq!(code(&fx.run("tick", &["1"])), 0);
    let o = fx.run("peers", &[]);
    assert_eq!(code(&o), 0);
    let line =
        regex_lite::Regex::new(r"([0-9a-f]{2}(:[0-9a-f]{2}){5})\s+rssi=\s*(-?\d+|\?)").unwrap();
    let peers = String::from_utf8(o.stdout).unwrap();
    let found: Vec<_> = line
        .captures_iter(&peers)
        .map(|c| c[1].to_string())
        .collect();
    assert_eq!(found, [PHONE]);

    let o = fx.run("down", &["stopped"]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(!fx.awdl0_up());
    assert_eq!(fx.lease(), None);
    assert_eq!(fx.calls(), ["up", "down"]);
    assert_eq!(code(&fx.run("tick", &["2"])), 4);
    assert_eq!(code(&fx.run("peers", &[])), 4);
    assert_eq!(fx.cores_files(), Vec::<PathBuf>::new());
}

#[test]
fn up_fails_with_a_sentence() {
    for (rc, say) in [("3", "Wi-Fi isn't connected."), ("4", "No radio here.")] {
        let fx = Fx::new();
        fx.fake("up.fail", &format!("{rc} {say}"));
        let o = fx.run("up", &[]);
        assert_eq!(code(&o).to_string(), rc);
        assert_eq!(last_line(&o.stderr), say);
        assert!(o.stdout.is_empty());
        assert!(!fx.awdl0_up());
        assert_eq!(fx.lease(), None);
        assert_eq!(code(&fx.run("down", &["start-failed"])), 0);
    }
}

#[test]
fn up_survives_sigterm() {
    let fx = Fx::new();
    fx.fake("up.sleep", "2");
    let mut up: Child = fx.command("up", &[]).spawn().unwrap();
    std::thread::sleep(Duration::from_millis(500));
    // As omdrop-radio cancels a hook: TERM to its process group.
    nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(up.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    let status = up.wait().unwrap();
    assert_ne!(status.code(), Some(0));
    let mut stderr = String::new();
    up.stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();

    // core then calls `down start-failed`, which waits for owlyd to finish
    // the setup and gives the radio back.
    assert_eq!(code(&fx.run("down", &["start-failed"])), 0);
    assert!(!fx.awdl0_up());
    assert_eq!(fx.calls(), ["up", "down"]);

    // And a later `up` works.
    fs::remove_file(fx.root.join("owly-fake/up.sleep")).unwrap();
    assert_eq!(code(&fx.run("up", &[])), 0);
    assert!(fx.awdl0_up());
    assert_eq!(code(&fx.run("down", &["stopped"])), 0);
}

#[test]
fn down_is_idempotent_with_no_window() {
    let fx = Fx::new();
    for why in ["stopped", "stopped", "expired", "radio-lost"] {
        let o = fx.run("down", &[why]);
        assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    }
    assert!(!fx.calls().contains(&"up".to_string()));
    assert_eq!(fx.cores_files(), Vec::<PathBuf>::new());
}

#[test]
fn owlyd_stopping_ends_the_window() {
    let mut fx = Fx::new();
    assert_eq!(code(&fx.run("up", &[])), 0);
    // owlyd gives the radio back as it stops.
    fx.stop_owlyd();
    assert!(!fx.awdl0_up());
    let o = fx.run("tick", &["7"]);
    assert_eq!(code(&o), 4);
    assert!(last_line(&o.stderr).contains("stopped"), "{o:?}");
    assert_eq!(code(&fx.run("down", &["radio-lost"])), 0);
    assert_eq!(fx.lease(), None);
}

#[test]
fn up_gives_back_a_lease_core_lost_track_of() {
    let fx = Fx::new();
    assert_eq!(code(&fx.run("up", &[])), 0);
    let first = fx.lease().unwrap();
    // core's supervisor died with the window open, and core starts afresh.
    let o = fx.run("up", &[]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert_ne!(fx.lease(), Some(first));
    assert_eq!(fx.calls(), ["up", "down", "up"]);
    assert_eq!(code(&fx.run("down", &["stopped"])), 0);
    assert!(!fx.awdl0_up());
}

#[test]
fn a_lost_link_ends_the_window() {
    let fx = Fx::new();
    assert_eq!(code(&fx.run("up", &[])), 0);
    fx.fake("lose", "");
    let end = Instant::now() + Duration::from_secs(5);
    let o = loop {
        let o = fx.run("tick", &["1"]);
        if code(&o) != 0 || Instant::now() > end {
            break o;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(code(&o), 4);
    assert!(
        last_line(&o.stderr).contains("the fake radio was lost"),
        "{o:?}"
    );
    // owlyd gave the radio back on its own.
    assert!(!fx.awdl0_up());
    assert_eq!(code(&fx.run("down", &["radio-lost"])), 0);
}

#[test]
fn arguments_are_checked() {
    let fx = Fx::new();
    let bad: [(&str, &[&str]); 9] = [
        ("probe", &[]),
        ("probe", &["--json", "x"]),
        ("up", &["now"]),
        ("tick", &[]),
        ("tick", &["01"]),
        ("tick", &["-1"]),
        ("tick", &["9223372036854775808"]),
        ("down", &["bogus"]),
        ("peers", &["--json"]),
    ];
    for (hook, args) in bad {
        assert_eq!(code(&fx.run(hook, args)), 2, "{hook} {args:?}");
    }
    assert_eq!(fx.calls(), Vec::<String>::new());
    assert_eq!(fx.cores_files(), Vec::<PathBuf>::new());
}

#[test]
fn the_seam_needs_its_variable() {
    // Without the seam the hooks drive the real radio, which needs root.
    let fx = Fx::new();
    let o = fx
        .command("up", &[])
        .env_remove("OMDROP_RADIO_TEST_ROOT")
        .output()
        .unwrap();
    if nix::unistd::geteuid().is_root() {
        return;
    }
    assert_eq!(code(&o), 2);
    assert_eq!(fx.lease(), None);
}

#[test]
fn without_owlyd_the_hooks_say_so() {
    let mut fx = Fx::new();
    fx.stop_owlyd();
    let o = fx.run_within("probe", &["--json"], Duration::from_secs(5));
    assert_eq!(code(&o), 0);
    let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(json["hooks"], 1);
    assert_eq!(json["missing"][0]["id"], "backend");
    assert!(
        json["missing"][0]["say"]
            .as_str()
            .unwrap()
            .contains("owlyd"),
        "{json}"
    );
    let o = fx.run("up", &[]);
    assert_eq!(code(&o), 4);
    assert!(last_line(&o.stderr).contains("owlyd"), "{o:?}");
    assert_eq!(code(&fx.run("down", &["start-failed"])), 0);
}

#[test]
fn a_busy_radio_is_retryable() {
    let fx = Fx::new();
    // Someone else's lease.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let address = fs::read_to_string(fx.root.join("owly-fake/bus")).unwrap();
    let (_conn, lease) = rt.block_on(async {
        let conn = owlyd::api::connect(Some(&address)).await.unwrap();
        let radio = owlyd::api::radio(&conn).await.unwrap();
        let (lease, _) = radio.acquire(0).await.unwrap();
        (conn, lease)
    });
    assert_ne!(lease, 0);
    let o = fx.run("up", &[]);
    assert_eq!(code(&o), 3, "{o:?}");
    assert!(last_line(&o.stderr).contains("in use"), "{o:?}");
}
