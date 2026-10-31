//! The owly command-line client: of owlyd, Owly's radio service, and of
//! owly-airdrop, for AirDrop without omdrop.
//!
//! - `owly doctor [--json]`: what the card can do, what stands in the way,
//!   and what's known to go wrong on it. From owlyd, or from here when it
//!   isn't running. No root needed.
//! - `owly radio up [--for SECONDS]`: takes the radio from owlyd and holds
//!   it until Ctrl-C, for interop tests; polkit decides who may.
//! - `owly radio peers`: the AWDL peers of the session that's up.
//! - `owly receive`, `owly send` and `owly browse`: AirDrop on one
//!   interface, `awdl0` by default, as yourself. Take the radio with
//!   `owly radio up` first.
//! - `owly test-card`: walks a tester through a photo each way, watches
//!   Wi-Fi after teardown, and writes a JSON report.
//! - `owly capture`: records an AWDL session for the capture corpus, on
//!   the monitor interface of the session that's up. Takes root.

mod airdrop;
mod bluez;
mod capture;
mod doctor;
mod radio;
mod test_card;
mod wifi;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "owly", version, about, after_help = env!("OWLY_BUILD_ID"))]
struct Cli {
    /// The bus owlyd is on, when it isn't the system bus.
    #[arg(long, global = true, hide = true)]
    bus: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// What the Wi-Fi card can do here, and what stands in the way.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// The radio, through owlyd.
    #[command(subcommand)]
    Radio(Radio),
    /// Receive files and links in Everyone mode.
    Receive(airdrop::ReceiveArgs),
    /// Send files, or links with --url.
    Send(airdrop::SendArgs),
    /// List the receivers that answer /Discover.
    Browse(airdrop::BrowseArgs),
    /// Test this computer's Wi-Fi card with an iPhone, and write a report.
    TestCard(test_card::Args),
    /// Record an AWDL session with a phone for tests/captures (root).
    Capture(capture::Args),
}

#[derive(Subcommand)]
enum Radio {
    /// The same as `owly doctor`.
    Probe {
        #[arg(long)]
        json: bool,
    },
    /// Bring awdl0 up and hold it until Ctrl-C.
    Up {
        /// Give it back after this many seconds.
        #[arg(long = "for", value_name = "SECONDS", default_value_t = 0)]
        duration: u32,
    },
    /// The AWDL peers of the session that's up.
    Peers,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("a tokio runtime");
    let bus = cli.bus.as_deref();
    let result = rt.block_on(async {
        match cli.command {
            Command::Doctor { json } | Command::Radio(Radio::Probe { json }) => {
                doctor::run(bus, json).await
            }
            Command::Radio(Radio::Up { duration }) => radio::up(bus, duration).await,
            Command::Radio(Radio::Peers) => radio::peers(bus).await,
            Command::Receive(args) => airdrop::receive(bus, args).await,
            Command::Send(args) => airdrop::send(bus, args).await,
            Command::Browse(args) => airdrop::browse(args).await,
            Command::TestCard(args) => test_card::run(bus, args).await,
            Command::Capture(args) => capture::run(args).await,
        }
    });
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("owly: {e}");
            ExitCode::from(2)
        }
    }
}
