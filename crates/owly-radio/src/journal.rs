//! The recovery journal: each change a radio session makes to the kernel
//! and NetworkManager, recorded before it's made, in a file locked by the
//! process that owns the radio. Undoing a session replays it backwards, so
//! a session that died halfway, or a process killed outright, is undone
//! the same way as an orderly teardown: by whoever opens the journal next.
//!
//! The file is JSON, replaced whole on every change, and lives in the run
//! directory (`/run/owly/journal.json`), which outlives the process but not
//! a reboot, as the changes themselves don't.

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};

use crate::rundir::{Process, RunDir};
use crate::sys::Ops;

const FILE: &str = "journal.json";
const LOCK: &str = "journal.lock";

/// How long NetworkManager gets to reconnect a station by itself before
/// the recorded connection is brought up. Autoconnect took 3 s on an AX211.
const AUTOCONNECT_WAIT: Duration = Duration::from_secs(10);

/// One change, by what undoes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "kebab-case")]
pub enum Step {
    /// A process the session started (hostapd): stop it.
    Process { what: String, process: Process },
    /// An interface the session added: delete it.
    Interface { name: String },
    /// Shared mode, on drivers whose station stops receiving after a monitor
    /// interface goes: reconnect it once one has been deleted.
    Reconnect { station: String },
    /// The station, taken from NetworkManager and down: give it back, and
    /// see that it reconnects to `connection`, the one it had.
    Station {
        station: String,
        connection: Option<String>,
    },
    /// The station made into the cell or a monitor: make it a station.
    StationType { station: String },
    /// An interface's `disable_ipv6` before the session set it.
    Ipv6 { iface: String, disable_ipv6: String },
    /// mt76's power management settings before the session.
    Mt76 {
        dir: PathBuf,
        runtime_pm: String,
        deep_sleep: String,
    },
    /// The regulatory domain before the session asked for another.
    Regdom { alpha2: String },
    /// rtw88's data rate fixed for the session, and its retry limit
    /// register as it was before the session changed it.
    Rtw88 {
        dir: PathBuf,
        retry_limit: Option<String>,
    },
}

/// The journal, locked for as long as this value lives.
pub struct Journal {
    run: RunDir,
    steps: Vec<Step>,
    _lock: Flock<File>,
}

/// What undoing carries from one step to the steps before it.
#[derive(Default)]
struct Undo {
    /// An interface was deleted, or had already gone, as one does when
    /// the radio is lost (for [`Step::Reconnect`]).
    deleted: bool,
    /// The station's type was changed back (for [`Step::Station`]).
    converted: bool,
}

impl Journal {
    /// Locks the journal and reads what a previous owner left. Fails if
    /// another process holds it.
    pub fn open(run: &RunDir) -> io::Result<Journal> {
        run.create()?;
        let file = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(run.file(LOCK))?;
        let lock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| {
            if e == nix::errno::Errno::EWOULDBLOCK {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "another process holds the radio ({} is locked)",
                        run.file(LOCK).display()
                    ),
                )
            } else {
                e.into()
            }
        })?;
        let steps = match run.read(FILE) {
            None => Vec::new(),
            Some(text) => serde_json::from_str(&text).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", run.file(FILE).display()),
                )
            })?,
        };
        Ok(Journal {
            run: run.clone(),
            steps,
            _lock: lock,
        })
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Records a change about to be made.
    pub fn record(&mut self, step: Step) -> io::Result<()> {
        self.steps.push(step);
        self.save()
    }

    /// Drops the newest step, for a change that was recorded but not made.
    pub fn discard_last(&mut self) -> io::Result<()> {
        self.steps.pop();
        self.save()
    }

    fn save(&self) -> io::Result<()> {
        if self.steps.is_empty() {
            self.run.remove(FILE);
            return Ok(());
        }
        self.run.write_json(FILE, &self.steps)
    }

    /// Undoes every change, newest first, dropping each from the journal as
    /// it's undone. Stops, keeping the rest for the next try, only where a
    /// step that later ones depend on fails: a station that can't be made a
    /// station again.
    pub fn undo(&mut self, ops: &dyn Ops) -> Result<(), String> {
        let mut state = Undo::default();
        while let Some(step) = self.steps.last().cloned() {
            if let Err(e) = undo(ops, &step, &mut state) {
                let _ = self.save();
                return Err(e);
            }
            self.steps.pop();
            let _ = self.save();
        }
        Ok(())
    }
}

fn undo(ops: &dyn Ops, step: &Step, state: &mut Undo) -> Result<(), String> {
    tracing::debug!(?step, "undo");
    match step {
        Step::Process { what, process } => {
            if !process.stop(Duration::from_secs(2)) {
                tracing::warn!("{what} (process {}) won't exit", process.pid);
            }
        }
        Step::Interface { name } => {
            if ops.exists(name) {
                if ops.iface_type(name).as_deref() == Some("IBSS") {
                    let _ = ops.leave_ibss(name);
                }
                let _ = ops.set_up(name, false);
                match ops.del_iface(name) {
                    Ok(()) => state.deleted = true,
                    Err(e) => tracing::warn!("deleting {name}: {e}"),
                }
            } else {
                state.deleted = true;
            }
        }
        Step::Reconnect { station } => {
            // Some drivers' stations stop receiving after a monitor
            // interface is deleted (the MT7925), and reloading the driver
            // isn't ours to do. A fresh association right after the delete
            // has kept it healthy in every teardown tested.
            if state.deleted {
                ops.sleep(Duration::from_secs(1));
                ops.reconnect(station);
            }
        }
        Step::StationType { station } => {
            let kind = ops.iface_type(station);
            if kind.is_some() && kind.as_deref() != Some("managed") {
                if kind.as_deref() == Some("IBSS") {
                    let _ = ops.leave_ibss(station);
                }
                let _ = ops.set_up(station, false);
                ops.set_kind(station, crate::nl80211::Kind::Station)
                    .map_err(|e| {
                        format!(
                            "Wi-Fi ({station}) is still set up for the last session and couldn't be made a station again ({e}). Restarting the computer fixes it."
                        )
                    })?;
            }
            state.converted = true;
        }
        Step::Ipv6 {
            iface,
            disable_ipv6,
        } => {
            let _ = ops.sysctl(&format!("net/ipv6/conf/{iface}/disable_ipv6"), disable_ipv6);
        }
        Step::Mt76 {
            dir,
            runtime_pm,
            deep_sleep,
        } => {
            let _ = ops.write(&dir.join("runtime-pm"), runtime_pm);
            let _ = ops.write(&dir.join("deep-sleep"), deep_sleep);
        }
        Step::Rtw88 { dir, retry_limit } => {
            let _ = ops.write(&dir.join("fix_rate"), crate::rtw88::FIX_RATE_OFF);
            if let Some(was) = retry_limit {
                crate::rtw88::set_retry_limit(ops, dir, was);
            }
        }
        Step::Regdom { alpha2 } => {
            if let Err(e) = ops.set_regdom(alpha2) {
                tracing::warn!("restoring the regulatory domain {alpha2}: {e}");
            }
        }
        Step::Station {
            station,
            connection,
        } => {
            let _ = ops.set_up(station, true);
            ops.set_managed(station, true);
            give_back(ops, station, connection.as_deref(), state.converted);
        }
    }
    Ok(())
}

/// NetworkManager reconnects a station by itself once it has it back, if
/// the connection has autoconnect on. Otherwise nothing would, so a station
/// it hasn't reconnected in [`AUTOCONNECT_WAIT`] gets the connection it had
/// brought up. One whose type was changed gets it at once: NetworkManager
/// can find it unavailable for a moment, and then leaves it. Three tries
/// either way.
fn give_back(ops: &dyn Ops, station: &str, connection: Option<&str>, converted: bool) {
    let Some(uuid) = connection.filter(|u| is_uuid(u)) else {
        // It wasn't connected: nothing to reconnect to.
        return;
    };
    if !converted {
        let mut waited = Duration::ZERO;
        while waited < AUTOCONNECT_WAIT {
            if ops.nm_connection(station).is_some() {
                return;
            }
            ops.sleep(Duration::from_secs(1));
            waited += Duration::from_secs(1);
        }
    }
    for _ in 0..3 {
        match ops.connection_up(uuid, station) {
            Ok(()) => return,
            Err(e) => tracing::debug!("bringing {uuid} up on {station}: {e}"),
        }
        ops.sleep(Duration::from_secs(1));
    }
    tracing::warn!("{station} is a station again, but didn't reconnect to {uuid}");
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_owner_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let run = RunDir::new(dir.path());
        let mut first = Journal::open(&run).unwrap();
        first
            .record(Step::Regdom {
                alpha2: "DE".into(),
            })
            .unwrap();
        let e = Journal::open(&run).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        drop(first);
        // The next owner finds what the last one left.
        let second = Journal::open(&run).unwrap();
        assert_eq!(
            second.steps(),
            [Step::Regdom {
                alpha2: "DE".into()
            }]
        );
    }

    #[test]
    fn steps_read_as_they_were_written() {
        let step = Step::Station {
            station: "wlan0".into(),
            connection: Some("8d2c9f8e-1b4f-4d47-9a45-3b0c2a6f1e10".into()),
        };
        let json = serde_json::to_string(&step).unwrap();
        assert_eq!(
            json,
            r#"{"step":"station","station":"wlan0","connection":"8d2c9f8e-1b4f-4d47-9a45-3b0c2a6f1e10"}"#
        );
        assert_eq!(serde_json::from_str::<Step>(&json).unwrap(), step);
        assert!(is_uuid("8d2c9f8e-1b4f-4d47-9a45-3b0c2a6f1e10"));
        assert!(!is_uuid("--"));
    }
}
