//! The injection backend: AWDL in userspace, on a monitor interface that
//! injects beside or in place of the card's station, in the mode the card
//! needs (`setup`):
//!
//! - **Shared**: the station stays associated and AWDL runs on its AP's
//!   channel, which must be one of AWDL's social channels (AWDL-11). The
//!   monitor interface carries the station's MAC and AWDL runs on it
//!   advertising only the slots in which the phone is on our channel. The
//!   station ACKs the phone's unicast.
//! - **Exclusive**: the station is taken off the air, and an ad-hoc cell on
//!   AWDL's BSSID (or, on cards with no ad-hoc mode, a hidden AP) takes its
//!   place and MAC, to ACK the phone. AWDL runs fixed to one channel the
//!   card may transmit on, electing its master by metric (AWDL-9, AWDL-12).
//! - **Active monitor**: exclusive, but the monitor is an active one that
//!   ACKs for itself, for cards with neither.
//! - **Firmware monitor**: exclusive, with capture and injection supplied by
//!   patched FullMAC firmware, on a fixed channel without a separate cell.
//!
//! AWDL itself is owly-awdl's ([`crate::native`]), which makes `awdl0` on
//! the AWDL address, the station's (AWDL-2), with its link-local address
//! and no DAD (NET-1). Every change is written to
//! the recovery [`Journal`] before it's made, and teardown replays it.

mod setup;

use std::io;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::radio::{Backend, Capabilities, Error, Link, LinkState, PeerInfo};

use crate::config::{CONFIG, Config};
use crate::journal::Journal;
use crate::native::Native;
use crate::quirks::Quirks;
use crate::rundir::RunDir;
use crate::sys::{Ops, System};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// The interface AWDL's data path runs on.
pub const AWDL_IFACE: &str = "awdl0";
/// The monitor interface the backend adds.
pub const MONITOR: &str = "owlymon0";
/// Exclusive mode's ad-hoc cell.
pub const IBSS: &str = "owlyibss0";
/// Exclusive mode's hidden AP, on cards with no ad-hoc mode.
pub const AP: &str = "owlyap0";

/// Where hostapd is, when a package says at build time (`OWLY_HOSTAPD`).
const HOSTAPD: Option<&str> = option_env!("OWLY_HOSTAPD");

/// Where distributions put hostapd: Arch in `/usr/bin`, Debian, Ubuntu and
/// Fedora in `/usr/sbin`.
const HOSTAPD_DIRS: [&str; 3] = ["/usr/bin", "/usr/sbin", "/sbin"];

/// hostapd: where the package put it, else the first on `PATH` or in the
/// usual places. Where there's none, the first usual place, to say where
/// it was looked for. `/etc/owly/radio.toml` can name another.
pub fn hostapd() -> PathBuf {
    if let Some(path) = HOSTAPD {
        return PathBuf::from(path);
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(HOSTAPD_DIRS.iter().map(PathBuf::from))
        .map(|dir| dir.join("hostapd"))
        .find(|p| p.is_file())
        .unwrap_or_else(|| Path::new(HOSTAPD_DIRS[0]).join("hostapd"))
}

/// How the backend is set up on this machine (`/etc/owly/radio.toml`).
#[derive(Debug, Clone)]
pub struct Settings {
    /// The Wi-Fi interface to use; else the first station.
    pub station: Option<String>,
    /// Run on a card the quirks table doesn't mark tested.
    pub allow_untested: bool,
    /// Overrides the quirk's `reconnect_after_monitor`.
    pub reconnect_after: Option<bool>,
    /// Exclusive modes: the regulatory domain to ask for.
    pub country: Option<String>,
    /// Exclusive modes: overrides the quirk's channel order.
    pub channels: Option<Vec<u8>>,
    /// Overrides the quirk's `rx_ampdu`.
    pub aggregation: Option<bool>,
    /// The data frame rate.
    pub tx_rate: Option<owly_awdl::TxRate>,
    /// Unicast as A-MSDUs, where the peer takes them.
    pub tx_amsdu: bool,
    pub hostapd: PathBuf,
    pub quirks: Quirks,
    pub run_dir: RunDir,
}

/// AWDL running on the interfaces a setup made.
pub trait Awdl: Send {
    /// `awdl0`'s index. AWDL makes it before it starts: up, on the AWDL
    /// address, with that address's link-local one and no DAD (NET-1).
    fn index(&self) -> u32;
    /// Why it stopped by itself, once it has.
    fn failed(&self) -> watch::Receiver<Option<String>>;
    /// Stops it, taking `awdl0` with it.
    fn stop(self: Box<Self>);
}

impl Awdl for Native {
    fn index(&self) -> u32 {
        self.index
    }
    fn failed(&self) -> watch::Receiver<Option<String>> {
        Native::failed(self)
    }
    fn stop(self: Box<Self>) {
        Native::stop(*self);
    }
}

/// Starts AWDL on the monitor interface (the first argument), making the
/// second, `awdl0`, and publishing its valid peers on the last. Blocking.
/// owly-awdl's [`Native`] outside tests.
pub type StartAwdl = Arc<
    dyn Fn(&str, &str, owly_awdl::Config, watch::Sender<Vec<PeerInfo>>) -> io::Result<Box<dyn Awdl>>
        + Send
        + Sync,
>;

pub struct Injection {
    ops: Arc<dyn Ops>,
    settings: Settings,
    start_awdl: StartAwdl,
    journal: Option<Arc<Mutex<Journal>>>,
    live: Option<Live>,
    /// Whether the settings come from `/etc/owly/radio.toml`, which is then
    /// read again each time the radio comes up.
    reads_config: bool,
}

struct Live {
    node: Box<dyn Awdl>,
    stop: watch::Sender<bool>,
    supervisor: JoinHandle<Option<Child>>,
}

impl Injection {
    pub fn new(ops: Arc<dyn Ops>, settings: Settings) -> Self {
        let start: StartAwdl = Arc::new(|monitor, tap, cfg, peers| {
            Ok(Box::new(Native::start(monitor, tap, cfg, peers)?))
        });
        Injection::with_awdl(ops, settings, start)
    }

    /// The backend as `/etc/owly/radio.toml` sets it up, with its run
    /// directory at `run`.
    pub fn from_config(run: RunDir) -> Result<Self, String> {
        let mut backend = Injection::new(Arc::new(System), load(run)?);
        backend.reads_config = true;
        Ok(backend)
    }

    /// With AWDL started by `start_awdl`, for testing the setup around it.
    pub fn with_awdl(ops: Arc<dyn Ops>, settings: Settings, start_awdl: StartAwdl) -> Self {
        Injection {
            ops,
            settings,
            start_awdl,
            journal: None,
            live: None,
            reads_config: false,
        }
    }

    /// The journal, locked from first use for as long as the backend lives.
    fn journal(&mut self) -> Result<Arc<Mutex<Journal>>, Error> {
        if let Some(j) = &self.journal {
            return Ok(j.clone());
        }
        let j = Journal::open(&self.settings.run_dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                Error::not_now(format!("The radio is busy: {e}."))
            } else {
                Error::no_radio(format!("Owly can't open its recovery journal: {e}"))
            }
        })?;
        let j = Arc::new(Mutex::new(j));
        self.journal = Some(j.clone());
        Ok(j)
    }

    /// Replays the journal, undoing whatever it holds.
    async fn undo(&mut self) -> Result<(), Error> {
        let journal = self.journal()?;
        let ops = self.ops.clone();
        tokio::task::spawn_blocking(move || journal.lock().unwrap().undo(&*ops))
            .await
            .map_err(|e| Error::no_radio(e.to_string()))?
            .map_err(Error::no_radio)
    }

    async fn start(&mut self) -> Result<Link, Error> {
        if self.live.is_some() {
            return Err(Error::not_now("The radio is already up."));
        }
        // The file as it is now, not as it was when owlyd started.
        if self.reads_config {
            self.settings = load(self.settings.run_dir.clone()).map_err(|e| {
                Error::no_radio(format!("Owly's radio settings can't be read: {e}"))
            })?;
        }
        let run = self.settings.run_dir.clone();
        run.create()
            .map_err(|e| Error::no_radio(format!("{}: {e}", run.path().display())))?;
        // Whatever a session before this one left has to go first, or its
        // steps would be taken for this one's.
        self.undo().await?;

        let ops = self.ops.clone();
        let journal = self.journal()?;
        let prepared = {
            let settings = self.settings.clone();
            let ops = ops.clone();
            let journal = journal.clone();
            tokio::task::spawn_blocking(move || {
                setup::prepare(&*ops, &settings, &mut journal.lock().unwrap())
            })
            .await
            .map_err(|e| Error::no_radio(e.to_string()))??
        };

        let (state_tx, state) = watch::channel(LinkState::Up);
        let (peers_tx, peers) = watch::channel(Vec::new());
        let (stop, stopped) = watch::channel(false);
        let announce = prepared.announce;
        let cfg = prepared.awdl;
        let mac = cfg.addr;
        let start = self.start_awdl.clone();
        let started =
            tokio::task::spawn_blocking(move || start(MONITOR, AWDL_IFACE, cfg, peers_tx))
                .await
                .map_err(|e| Error::no_radio(e.to_string()))?;
        let node = match started {
            Ok(n) => n,
            Err(e) => {
                self.undo().await?;
                return Err(Error::no_radio(format!("Couldn't start AWDL: {e}")));
            }
        };
        // owly-awdl made awdl0 and set it up before returning. Only
        // NetworkManager is told to leave it alone, for installs without
        // the package's device section.
        let unmanage = ops.clone();
        let _ = tokio::task::spawn_blocking(move || unmanage.set_managed(AWDL_IFACE, false)).await;
        let index = node.index();
        let supervisor = tokio::spawn(supervise(
            ops.clone(),
            prepared.hostapd,
            node.failed(),
            stopped,
            state_tx,
        ));
        self.live = Some(Live {
            node,
            stop,
            supervisor,
        });

        // AWDL-2: peers address us by the AWDL address. Something that
        // rewrote awdl0's (udev's MACAddressPolicy) breaks that.
        if let Some(now) = ops.mac(AWDL_IFACE)
            && now != mac
        {
            tracing::warn!("{AWDL_IFACE} has MAC {now}, not the AWDL address {mac} (AWDL-2)");
        }
        tracing::info!("{} mode up", prepared.mode);
        Ok(Link {
            name: AWDL_IFACE.into(),
            index,
            mac,
            addr: mac.link_local(),
            announce: Some(announce),
            peers,
            state,
        })
    }

    async fn stop(&mut self) -> Result<(), Error> {
        let mut hostapd = None;
        if let Some(live) = self.live.take() {
            let _ = live.stop.send(true);
            let node = live.node;
            let _ = tokio::task::spawn_blocking(move || node.stop()).await;
            hostapd = live.supervisor.await.ok().flatten();
        }
        let result = self.undo().await;
        if let Some(mut child) = hostapd {
            // Stopped by the journal; reaped here.
            let _ = tokio::task::spawn_blocking(move || child.wait()).await;
        }
        result
    }
}

impl Injection {
    /// What the radio can do here and what stands in the way. Needs no root
    /// and changes nothing.
    pub fn probe(&self) -> Capabilities {
        crate::probe::capabilities(&*self.ops, &self.settings)
    }
}

/// The settings `/etc/owly/radio.toml` gives, with the run directory at
/// `run`.
fn load(run: RunDir) -> Result<Settings, String> {
    Config::load(Path::new(CONFIG))?.settings(run)
}

impl Backend for Injection {
    async fn up(&mut self) -> Result<Link, Error> {
        self.start().await
    }

    async fn down(&mut self) -> Result<(), Error> {
        self.stop().await
    }

    async fn recover(&mut self) -> Result<(), Error> {
        if self.live.is_some() {
            return Ok(());
        }
        let journal = self.journal()?;
        if journal.lock().unwrap().is_empty() {
            return Ok(());
        }
        tracing::info!("undoing the radio session a previous process left");
        self.undo().await
    }
}

/// Watches AWDL, the monitor interface and hostapd until told to stop, and
/// reports the first of them to fail as the link lost; `awdl0` lasts as
/// long as AWDL does. Hands hostapd back, for reaping once the journal has
/// stopped it.
async fn supervise(
    ops: Arc<dyn Ops>,
    mut hostapd: Option<Child>,
    mut failed: watch::Receiver<Option<String>>,
    mut stopped: watch::Receiver<bool>,
    state: watch::Sender<LinkState>,
) -> Option<Child> {
    let mut check = tokio::time::interval(Duration::from_secs(1));
    let lost = |why: String| {
        tracing::warn!("link lost: {why}");
        state.send_if_modified(|s| {
            let first = *s == LinkState::Up;
            if first {
                *s = LinkState::Lost(why);
            }
            first
        });
    };
    loop {
        tokio::select! {
            _ = stopped.changed() => break,
            Ok(()) = failed.changed() => {
                if let Some(why) = failed.borrow_and_update().clone() {
                    lost(why);
                }
            }
            _ = check.tick() => {
                // A driver that reloads (iwlwifi after a firmware crash)
                // takes the monitor interface with it (legacy #23).
                if !ops.exists(MONITOR) {
                    lost(format!("{MONITOR} is gone; the driver may have reloaded"));
                }
                // The hidden AP is only up while hostapd is: without it
                // nothing ACKs the phone.
                if let Some(child) = &mut hostapd
                    && let Ok(Some(status)) = child.try_wait()
                {
                    lost(format!("hostapd exited ({status})"));
                }
            }
        }
    }
    hostapd
}
