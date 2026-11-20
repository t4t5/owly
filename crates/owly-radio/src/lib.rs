//! The radio on Linux: the Backend trait and its injection backend, capability probing and quirks, and owly-awdl over nl80211.
//!
//! [`radio`] is the [`Backend`](radio::Backend) trait owlyd runs, and the
//! link a backend brings up. [`injection`] implements it with owly-awdl ([`native`]), on interfaces it sets up through [`nl80211`] and [`rtnl`], in the mode each
//! card needs: shared, exclusive (an ad-hoc cell or hidden AP) or active
//! monitor. It picks the mode from what [`probe`] finds and what [`quirks`]
//! records, and writes each change to a recovery [`journal`] before making
//! it, with the settings [`config`] reads from `/etc/owly/radio.toml`.
//! [`fake`] is a backend for testing what runs on top.

pub mod capture;
pub mod config;
pub mod fake;
pub mod injection;
pub mod journal;
pub mod native;
pub mod netlink;
pub mod nl80211;
pub mod pcap;
pub mod probe;
pub mod quirks;
pub mod radio;
pub mod radiotap;
pub mod rtnl;
mod rtw88;
pub mod rundir;
pub mod sys;
