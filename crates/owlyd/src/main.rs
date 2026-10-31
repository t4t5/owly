//! owlyd, the Owly system service: it owns the Wi-Fi radio and leases it
//! out over the system D-Bus API (`io.github.t4t5.Owly.Radio1`, see
//! [`owlyd::api`]).
//!
//! ```text
//! owlyd [--bus ADDRESS] [--run-dir DIR] [--fake ROOT]
//! ```
//!
//! It runs as a systemd service with `CAP_NET_ADMIN` and `CAP_NET_RAW`
//! only. On start, before it takes any lease, it undoes whatever a previous
//! owlyd left from the recovery journal in its run directory (`/run/owly`,
//! or `--run-dir`).
//!
//! It serves the injection backend ([`owly_radio::injection`]), set up as
//! `/etc/owly/radio.toml` says. `--fake ROOT` serves [`owly_radio::fake`]
//! instead, with its fake `awdl0` under ROOT, trusting every caller: for
//! testing what runs on top. `--bus` serves on a bus other than the system
//! bus.

use std::process::ExitCode;

use owly_radio::fake::{self, Fake};
use owly_radio::injection::Injection;
use owly_radio::rundir::{RUN_DIR, RunDir};
use owlyd::service::{self, Options};

const USAGE: &str = "usage: owlyd [--bus ADDRESS] [--run-dir DIR] [--fake ROOT]";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let mut bus = None;
    let mut run_dir = None;
    let mut fake = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let value = match a.as_str() {
            "--bus" => &mut bus,
            "--run-dir" => &mut run_dir,
            "--fake" => &mut fake,
            "-h" | "--help" => {
                println!("{USAGE}\n{}", env!("OWLY_BUILD_ID"));
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        };
        match args.next() {
            Some(v) => *value = Some(v),
            None => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a tokio runtime");
    let served = match fake {
        Some(root) => {
            let options = Options { bus, polkit: false };
            rt.block_on(service::serve(
                Fake::new(root),
                fake::probe,
                options,
                shutdown(),
            ))
        }
        None => {
            let run = RunDir::new(run_dir.unwrap_or_else(|| RUN_DIR.into()));
            let backend = match Injection::from_config(run.clone()) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("{e}");
                    return ExitCode::from(1);
                }
            };
            // radio.toml read afresh for each probe, as the backend reads it
            // each time the radio comes up: edits to it need no restart.
            let probe = move || owly_radio::probe::from_config(run.clone());
            let options = Options { bus, polkit: true };
            rt.block_on(service::serve(backend, probe, options, shutdown()))
        }
    };
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::from(1)
        }
    }
}

/// SIGTERM or SIGINT.
async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("a SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("a SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
