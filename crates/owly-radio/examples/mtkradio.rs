//! Bridge `owly-awdl` directly to a user-space `mtkradio` UNIX socket.
//!
//! Usage:
//!   sudo ./mtkradio /tmp/mtkradio.sock [channel]

use std::env;
use std::fmt;
use std::time::{Duration, Instant};

use owly_awdl::{Channel, Config, MacAddr, Presence, RadioConstraints, TxRate};
use owly_radio::native::Native;
use tokio::sync::watch;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber};
use tracing::span::{Attributes, Id, Record};

/// Minimal stderr subscriber so `owly-awdl`'s periodic `STATS` and peer/overlap
/// diagnostics are visible without adding extra crate dependencies.
struct StderrLogger {
    start: Instant,
}

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = fmt::write(&mut self.0, format_args!("{value:?}"));
        } else {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            let _ = fmt::write(&mut self.0, format_args!("{}={value:?}", field.name()));
        }
    }
}

impl Subscriber for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= Level::INFO
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        let mut v = MessageVisitor(String::new());
        event.record(&mut v);
        let secs = self.start.elapsed().as_secs_f64();
        eprintln!(
            "[{secs:8.2}s {:5}] {}",
            event.metadata().level(),
            v.0
        );
    }

    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

fn main() {
    let _ = tracing::subscriber::set_global_default(StderrLogger {
        start: Instant::now(),
    });

    let args: Vec<String> = env::args().collect();
    let sock = args.get(1).map(|s| s.as_str()).unwrap_or("/tmp/mtkradio.sock");
    let ch_num: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(149);
    let freq_mhz = if ch_num <= 13 {
        2407 + ch_num * 5
    } else {
        5000 + ch_num * 5
    };
    let channel = Channel::from_freq_mhz(freq_mhz).expect("valid AWDL channel (6, 44, or 149)");

    let mut cfg = Config::new(
        MacAddr([0x02, 0x79, 0x22, 0x55, 0x6d, 0x0d]),
        "owly-MT7922",
        RadioConstraints {
            channel,
            presence: Presence::Fixed,
        },
    );
    cfg.rate = TxRate::Ht { mcs: 7, sgi: false };
    cfg.no_ack = true;
    cfg.accept_addba = true;
    cfg.amsdu = true;
    cfg.max_frame = 4000;

    let (peers_tx, mut peers_rx) = watch::channel(Vec::new());
    let native = Native::start_socket(sock, "awdl0", cfg, peers_tx)
        .expect("failed to start owly-awdl over mtkradio socket");
    eprintln!(
        "[owly-mtkradio] awdl0 up (ifindex={}, ch={}, Fixed+ADDBA+AMSDU+HT-MCS15-SGI+VHT80-2x2+no_ack)",
        native.index, ch_num
    );

    let failed = native.failed();
    loop {
        std::thread::sleep(Duration::from_secs(2));
        if let Some(err) = failed.borrow().as_ref() {
            eprintln!("[owly-mtkradio] node failed: {err}");
            break;
        }
        if peers_rx.has_changed().unwrap_or(false) {
            let peers = peers_rx.borrow_and_update();
            eprintln!("[owly-mtkradio] peers ({}):", peers.len());
            for p in peers.iter() {
                eprintln!("  - {} name={:?} rssi={:?}", p.mac, p.name, p.rssi);
            }
        }
    }
    native.stop();
}
