//! AWDL TLVs (docs/SPEC.md §3.2, AWDL-4–6): splitting an action frame's body
//! into TLVs, decoding the ones a node needs, and writing its own.
//!
//! The layouts are those of docs/SPEC.md §3.2. Offsets below are into a
//! TLV's value, after its 3-byte header.

use alloc::string::String;
use alloc::vec::Vec;

use crate::channel::{Channel, Sequence};
use crate::wire::{Bytes, Put};
use crate::{Error, MacAddr};

/// AWDL-6: TLV types.
pub mod kind {
    pub const SERVICE_RESPONSE: u8 = 2;
    pub const SYNC_PARAMS: u8 = 4;
    pub const ELECTION_PARAMS: u8 = 5;
    pub const SERVICE_PARAMS: u8 = 6;
    pub const HT_CAPABILITIES: u8 = 7;
    pub const DATA_PATH_STATE: u8 = 12;
    pub const ARPA: u8 = 16;
    pub const IEEE80211_CONTAINER: u8 = 17;
    pub const CHANNEL_SEQUENCE: u8 = 18;
    pub const SYNC_TREE: u8 = 20;
    pub const VERSION: u8 = 21;
    pub const BLOOM_FILTER: u8 = 22;
    pub const ELECTION_PARAMS_V2: u8 = 24;
}

/// Device classes in the Version TLV (AWDL-6).
pub mod devclass {
    pub const MACOS: u8 = 1;
    pub const IOS: u8 = 2;
    pub const TVOS: u8 = 8;
}

/// The AWDL version a node announces: 3.4, as legacy did.
pub const VERSION: u8 = 0x34;

/// The longest host name kept from, or written to, an ARPA TLV.
pub const NAME_MAX: usize = 64;

/// One TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub kind: u8,
    pub value: &'a [u8],
}

/// The TLVs in an action frame's body, in order (AWDL-4). A TLV whose
/// length runs past the end is an error, and so is a tail of fewer than 3
/// bytes unless it's all zeros: iPhones pad some MIFs that way (AWDL-5).
/// Zeros of 3 bytes or more read as empty TLVs of type 0, which is
/// deprecated and ignored, as legacy read them.
pub fn tlvs(body: &[u8]) -> Tlvs<'_> {
    Tlvs { rest: body }
}

pub struct Tlvs<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Tlvs<'a> {
    type Item = Result<Tlv<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.rest;
        if rest.len() < 3 {
            self.rest = &[];
            return if rest.iter().all(|&b| b == 0) {
                None
            } else {
                Some(Err(Error::Truncated))
            };
        }
        let len = u16::from_le_bytes([rest[1], rest[2]]) as usize;
        let Some(value) = rest.get(3..3 + len) else {
            self.rest = &[];
            return Some(Err(Error::Truncated));
        };
        self.rest = &rest[3 + len..];
        Some(Ok(Tlv {
            kind: rest[0],
            value,
        }))
    }
}

/// The Synchronization Parameters TLV (4), as far as a node reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncParams {
    /// The channel of the sender's next AW.
    pub next_aw_channel: u8,
    /// TU to the sender's next slot boundary (its TX down-counter).
    pub next_tu: u16,
    pub master_channel: u8,
    pub aw_period: u16,
    /// How often the sender sends PSFs, in TU.
    pub af_period: u16,
    pub master: MacAddr,
    pub presence_mode: u8,
    /// The sender's AW count (its next AW sequence number).
    pub aw_counter: u16,
}

impl SyncParams {
    /// Offsets 0–30, all a reader needs (§3.2).
    pub fn parse(value: &[u8]) -> Result<SyncParams, Error> {
        let b = Bytes(value);
        Ok(SyncParams {
            next_aw_channel: b.u8(0)?,
            next_tu: b.le16(1)?,
            master_channel: b.u8(3)?,
            aw_period: b.le16(5)?,
            af_period: b.le16(7)?,
            master: b.mac(21)?,
            presence_mode: b.u8(27)?,
            aw_counter: b.le16(29)?,
        })
    }
}

/// What the Election Parameters TLVs (5 and 24) say about the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectionParams {
    pub master: MacAddr,
    /// Only version 2 carries it; version 1's sender syncs to itself.
    pub sync: Option<MacAddr>,
    pub height: u32,
    pub master_metric: u32,
    pub self_metric: u32,
    /// Only version 2 carries the counters.
    pub master_counter: u32,
    pub self_counter: u32,
}

impl ElectionParams {
    /// Version 1 (5): flags, ID, distance to the top master, then its
    /// address and metric and the sender's metric.
    pub fn parse_v1(value: &[u8]) -> Result<ElectionParams, Error> {
        let b = Bytes(value);
        Ok(ElectionParams {
            height: b.u8(3)? as u32,
            master: b.mac(5)?,
            master_metric: b.le32(11)?,
            self_metric: b.le32(15)?,
            sync: None,
            master_counter: 0,
            self_counter: 0,
        })
    }

    /// Version 2 (24): master and sync addresses, the master's counter,
    /// the distance, both metrics, then the sender's counter.
    pub fn parse_v2(value: &[u8]) -> Result<ElectionParams, Error> {
        let b = Bytes(value);
        Ok(ElectionParams {
            master: b.mac(0)?,
            sync: Some(b.mac(6)?),
            master_counter: b.le32(12)?,
            height: b.le32(16)?,
            master_metric: b.le32(20)?,
            self_metric: b.le32(24)?,
            self_counter: b.le32(36)?,
        })
    }
}

/// The HT Capabilities TLV (7): two reserved bytes, the HT capability
/// word, the A-MPDU parameters, the RX MCS mask, two reserved bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtCapabilities {
    pub capabilities: u16,
    pub ampdu_params: u8,
    /// MCS 0–31, a bit each.
    pub rx_mcs: u32,
}

impl HtCapabilities {
    /// One spatial stream, all its MCS: what a node here announces.
    pub const ONE_STREAM: HtCapabilities = HtCapabilities {
        capabilities: 0x11ce,
        ampdu_params: 0x1b,
        rx_mcs: 0xff,
    };

    /// Two spatial streams (MCS 0..15) with Short Guard Interval (20 MHz)
    /// for optimized PHY throughput.
    pub const TWO_STREAM_SGI: HtCapabilities = HtCapabilities {
        capabilities: 0x11ee,
        ampdu_params: 0x1b,
        rx_mcs: 0xffff,
    };

    /// The mask may be longer than one byte; bits past MCS 31 are
    /// dropped.
    pub fn parse(value: &[u8]) -> Result<HtCapabilities, Error> {
        let b = Bytes(value);
        let end = if value.len() >= 8 {
            value.len() - 2
        } else {
            value.len()
        };
        let mask = b.slice(5, end.saturating_sub(5).max(1))?;
        let mut rx_mcs = [0u8; 4];
        for (to, from) in rx_mcs.iter_mut().zip(mask) {
            *to = *from;
        }
        Ok(HtCapabilities {
            capabilities: b.le16(2)?,
            ampdu_params: b.u8(4)?,
            rx_mcs: u32::from_le_bytes(rx_mcs),
        })
    }

    /// The largest A-MSDU the sender receives: 7935 bytes with the HT
    /// capability's max A-MSDU bit, else 3839.
    pub fn max_amsdu(&self) -> usize {
        if self.capabilities & 0x0800 != 0 {
            7935
        } else {
            3839
        }
    }

    /// Short guard interval at 20 MHz.
    pub fn sgi20(&self) -> bool {
        self.capabilities & 0x0020 != 0
    }
}

/// What a node reads from the Data Path State TLV (12).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataPathState {
    pub country: Option<[u8; 3]>,
    /// The sender's station address on its infrastructure network.
    pub infra: Option<MacAddr>,
}

mod data_path {
    pub const INFRA_INFO: u16 = 0x0001;
    pub const INFRA_ADDRESS: u16 = 0x0002;
    pub const AWDL_ADDRESS: u16 = 0x0004;
    pub const COUNTRY_CODE: u16 = 0x0100;
    pub const SOCIAL_CHANNEL_MAP: u16 = 0x0200;
}

impl DataPathState {
    /// Flags, then each optional field the flags announce, as far as legacy
    /// read them.
    pub fn parse(value: &[u8]) -> Result<DataPathState, Error> {
        use data_path::*;
        let b = Bytes(value);
        let flags = b.le16(0)?;
        let mut at = 2;
        let mut out = DataPathState::default();
        if flags & COUNTRY_CODE != 0 {
            let c = b.slice(at, 3)?;
            out.country = Some([c[0], c[1], c[2]]);
            at += 3;
        }
        if flags & SOCIAL_CHANNEL_MAP != 0 {
            b.slice(at, 2)?;
            at += 2;
        }
        if flags & INFRA_INFO != 0 {
            b.slice(at, 8)?;
            at += 8;
        }
        if flags & INFRA_ADDRESS != 0 {
            out.infra = Some(b.mac(at)?);
            at += 6;
        }
        if flags & AWDL_ADDRESS != 0 {
            b.slice(at, 6)?;
        }
        Ok(out)
    }
}

/// The host name in an ARPA TLV (16): flags, then a length-prefixed label.
/// Longer names are cut at [`NAME_MAX`] bytes.
pub fn parse_arpa(value: &[u8]) -> Result<String, Error> {
    let b = Bytes(value);
    let len = b.u8(1)? as usize;
    let name = b.slice(2, len)?;
    Ok(String::from_utf8_lossy(&name[..len.min(NAME_MAX)]).into_owned())
}

/// The Version TLV (21): version, device class.
pub fn parse_version(value: &[u8]) -> Result<(u8, u8), Error> {
    let b = Bytes(value);
    Ok((b.u8(0)?, b.u8(1)?))
}

/// What one action frame's TLVs say, decoded whole before anything acts on
/// them, so a malformed TLV late in the frame can't half-update a peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Advert {
    pub sync: Option<SyncParams>,
    /// Version 2 when the frame has it, else version 1.
    pub election: Option<ElectionParams>,
    pub election_v2: bool,
    pub sequence: Option<Sequence>,
    pub name: Option<String>,
    /// Version, device class.
    pub version: Option<(u8, u8)>,
    pub ht: Option<HtCapabilities>,
    pub data_path: Option<DataPathState>,
}

impl Advert {
    /// Decodes an action frame's TLVs. Unknown TLVs are skipped by their
    /// length (AWDL-6), and so are those a node has no use for.
    pub fn parse(body: &[u8]) -> Result<Advert, Error> {
        let mut a = Advert::default();
        for tlv in tlvs(body) {
            let Tlv { kind, value } = tlv?;
            match kind {
                kind::SYNC_PARAMS => a.sync = Some(SyncParams::parse(value)?),
                kind::ELECTION_PARAMS => {
                    let e = ElectionParams::parse_v1(value)?;
                    if !a.election_v2 {
                        a.election = Some(e);
                    }
                }
                kind::ELECTION_PARAMS_V2 => {
                    a.election = Some(ElectionParams::parse_v2(value)?);
                    a.election_v2 = true;
                }
                kind::CHANNEL_SEQUENCE => a.sequence = Some(Sequence::parse(value)?),
                kind::ARPA => a.name = Some(parse_arpa(value)?),
                kind::VERSION => a.version = Some(parse_version(value)?),
                kind::HT_CAPABILITIES => a.ht = Some(HtCapabilities::parse(value)?),
                kind::DATA_PATH_STATE => a.data_path = Some(DataPathState::parse(value)?),
                // The sync tree's layout isn't known (docs/open-questions.md,
                // item 11) and the election doesn't need it; the rest carry
                // nothing a node acts on.
                _ => {}
            }
        }
        Ok(a)
    }
}

/// What a node announces about itself, for writing its TLVs.
pub struct Own<'a> {
    pub addr: MacAddr,
    pub name: &'a str,
    pub devclass: u8,
    /// The channel the radio is on now, 0 for none.
    pub channel: u8,
    /// The channel the node calls its own: the one it serves in every slot
    /// it can.
    pub master_channel: Channel,
    pub next_tu: u16,
    pub aw_counter: u16,
    pub psf_interval_tu: u16,
    pub sequence: &'a Sequence,
    pub election: &'a crate::election::Election,
    pub ht: Option<HtCapabilities>,
    pub tuned: bool,
}

fn tlv(out: &mut Vec<u8>, kind: u8, value: impl FnOnce(&mut Vec<u8>)) {
    out.u8(kind);
    let len_at = out.len();
    out.le16(0);
    value(out);
    let len = (out.len() - len_at - 2) as u16;
    out[len_at..len_at + 2].copy_from_slice(&len.to_le_bytes());
}

/// The Synchronization Parameters TLV (§3.2): the fixed fields, the AW
/// count and phase, then the channel sequence and 2 bytes of padding.
pub fn put_sync_params(out: &mut Vec<u8>, own: &Own) {
    use crate::sync::{AW_PERIOD_TU, PRESENCE_MODE};
    tlv(out, kind::SYNC_PARAMS, |v| {
        let ext = PRESENCE_MODE - 1;
        v.u8(own.channel);
        v.le16(own.next_tu);
        v.u8(own.master_channel.0);
        v.u8(0); // guard time
        v.le16(AW_PERIOD_TU);
        v.le16(own.psf_interval_tu);
        v.le16(0x1800); // flags: reserved
        v.le16(AW_PERIOD_TU); // extended AW length
        v.le16(AW_PERIOD_TU); // common AW length
        let elapsed = AW_PERIOD_TU * PRESENCE_MODE as u16 - own.next_tu.min(64);
        v.le16(AW_PERIOD_TU.saturating_sub(elapsed)); // remaining AW length
        v.extend_from_slice(&[ext, ext, ext, ext]); // min ext, max ext multicast, unicast, AF
        v.mac(own.election.master);
        v.u8(PRESENCE_MODE);
        v.u8(0);
        v.le16(own.aw_counter); // next AW sequence number
        v.le16(own.aw_counter); // AP alignment
        own.sequence.put(v);
        v.extend_from_slice(&[0, 0]);
    });
}

/// Election Parameters, version 1.
pub fn put_election_v1(out: &mut Vec<u8>, own: &Own) {
    let e = own.election;
    tlv(out, kind::ELECTION_PARAMS, |v| {
        v.u8(0); // flags
        v.le16(0); // ID
        v.u8(e.height.min(255) as u8);
        v.u8(0);
        v.mac(e.master);
        v.le32(e.master_metric);
        v.le32(e.self_metric);
        v.extend_from_slice(&[0, 0]);
    });
}

/// The Channel Sequence TLV, with its 3 bytes of padding (§3.2).
pub fn put_channel_sequence(out: &mut Vec<u8>, own: &Own) {
    tlv(out, kind::CHANNEL_SEQUENCE, |v| {
        own.sequence.put(v);
        v.extend_from_slice(&[0, 0, 0]);
    });
}

/// Election Parameters, version 2.
pub fn put_election_v2(out: &mut Vec<u8>, own: &Own) {
    let e = own.election;
    tlv(out, kind::ELECTION_PARAMS_V2, |v| {
        v.mac(e.master);
        v.mac(e.sync);
        v.le32(e.master_counter);
        v.le32(e.height);
        v.le32(e.master_metric);
        v.le32(e.self_metric);
        v.le32(0);
        v.le32(0);
        v.le32(e.self_counter);
    });
}

/// Service Parameters, all zero: a changed SUI makes peers flush their
/// mDNS caches, and the TLV seems otherwise unused since AWDL 2.
pub fn put_service_params(out: &mut Vec<u8>) {
    tlv(out, kind::SERVICE_PARAMS, |v| {
        v.extend_from_slice(&[0; 3]);
        v.le16(0);
        v.le32(0);
    });
}

pub fn put_ht_capabilities(out: &mut Vec<u8>, ht: &HtCapabilities) {
    tlv(out, kind::HT_CAPABILITIES, |v| {
        v.le16(0);
        v.le16(ht.capabilities);
        v.u8(ht.ampdu_params);
        v.u8(ht.rx_mcs as u8);
        v.le16((ht.rx_mcs >> 8) as u16);
    });
}

/// Data Path State with legacy's flags (`0x8f24`), country `X0`, the master
/// channel in the social channel map, and our AWDL address.
pub fn put_data_path_state(out: &mut Vec<u8>, own: &Own) {
    tlv(out, kind::DATA_PATH_STATE, |v| {
        let (flags, ext_flags) = if own.tuned {
            let mut f = 0xaf84;
            let mut ext = 0x0000;
            if own.master_channel.0 == 6 {
                ext |= 0x0008;
            } else {
                f |= 0x0020;
            }
            (f, ext)
        } else {
            (0x8f24, 0x0000)
        };
        v.le16(flags);
        v.extend_from_slice(b"X0\0");
        v.le16(match own.master_channel.0 {
            6 => 0x0001,
            44 => 0x0002,
            _ => 0x0004,
        });
        v.mac(own.addr);
        v.le16(ext_flags);
    });
}

/// The ARPA TLV: our host name, then `.local` as a DNS pointer.
pub fn put_arpa(out: &mut Vec<u8>, name: &str) {
    let mut end = name.len().min(NAME_MAX);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let name = &name.as_bytes()[..end];
    tlv(out, kind::ARPA, |v| {
        v.u8(3); // the one flag value IO80211Family accepts
        v.u8(name.len() as u8);
        v.extend_from_slice(name);
        v.be16(0xc00c);
    });
}

pub fn put_version(out: &mut Vec<u8>, devclass: u8) {
    tlv(out, kind::VERSION, |v| {
        v.u8(VERSION);
        v.u8(devclass);
    });
}

/// A PSF's or MIF's TLVs, in legacy's order. Both carry the HT
/// capabilities, as an iPhone's do; only MIFs carry the host name.
pub fn put_all(out: &mut Vec<u8>, own: &Own, mif: bool) {
    put_sync_params(out, own);
    put_election_v1(out, own);
    put_channel_sequence(out, own);
    put_election_v2(out, own);
    put_service_params(out);
    if let Some(ht) = &own.ht {
        put_ht_capabilities(out, ht);
    }
    if mif {
        put_arpa(out, own.name);
    }
    put_data_path_state(out, own);
    put_version(out, own.devclass);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::election::Election;
    use alloc::vec;

    fn own_frame(mif: bool) -> Vec<u8> {
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let seq = Sequence::fixed(Channel(44));
        let mut e = Election::own(mac);
        e.master = MacAddr([2, 0, 0, 0, 0, 9]);
        e.sync = MacAddr([2, 0, 0, 0, 0, 9]);
        e.height = 1;
        e.master_metric = 522;
        e.master_counter = 393;
        let own = Own {
            addr: mac,
            name: "owly",
            devclass: devclass::MACOS,
            channel: 44,
            master_channel: Channel(44),
            next_tu: 20,
            aw_counter: 401,
            psf_interval_tu: 110,
            sequence: &seq,
            election: &e,
            ht: Some(HtCapabilities::ONE_STREAM),
            tuned: false,
        };
        let mut out = Vec::new();
        put_all(&mut out, &own, mif);
        out
    }

    // spec: AWDL-4
    #[test]
    fn our_tlvs_parse_back() {
        let body = own_frame(true);
        let kinds: Vec<u8> = tlvs(&body).map(|t| t.unwrap().kind).collect();
        assert_eq!(kinds, vec![4, 5, 18, 24, 6, 7, 16, 12, 21]);
        let a = Advert::parse(&body).unwrap();
        let sync = a.sync.unwrap();
        assert_eq!(
            (sync.next_tu, sync.aw_counter, sync.master_channel),
            (20, 401, 44)
        );
        assert_eq!(sync.master, MacAddr([2, 0, 0, 0, 0, 9]));
        let e = a.election.unwrap();
        assert!(a.election_v2);
        assert_eq!(e.sync, Some(MacAddr([2, 0, 0, 0, 0, 9])));
        assert_eq!((e.height, e.master_metric, e.master_counter), (1, 522, 393));
        assert_eq!(a.sequence, Some(Sequence::fixed(Channel(44))));
        assert_eq!(a.name.as_deref(), Some("owly"));
        assert_eq!(a.version, Some((VERSION, devclass::MACOS)));
        assert_eq!(a.ht, Some(HtCapabilities::ONE_STREAM));
        assert_eq!(a.data_path.unwrap().country, Some(*b"X0\0"));
        // PSFs leave out only the name.
        let psf = own_frame(false);
        let kinds: Vec<u8> = tlvs(&psf).map(|t| t.unwrap().kind).collect();
        assert_eq!(kinds, vec![4, 5, 18, 24, 6, 7, 12, 21]);
        let psf = Advert::parse(&psf).unwrap();
        assert_eq!((psf.name, psf.ht), (None, Some(HtCapabilities::ONE_STREAM)));
    }

    #[test]
    fn owls_tlv_lengths() {
        let body = own_frame(true);
        let lens: Vec<usize> = tlvs(&body).map(|t| t.unwrap().value.len()).collect();
        // sync 33 + sequence 38 + 2, election 21, sequence 38 + 3,
        // election v2 40, service 9, HT 8, ARPA 4 + name, data path 15,
        // version 2.
        assert_eq!(lens, vec![73, 21, 41, 40, 9, 8, 8, 15, 2]);
    }

    // spec: AWDL-5
    #[test]
    fn zero_padding_is_accepted_and_anything_else_refused() {
        let version = [kind::VERSION, 2, 0, VERSION, devclass::IOS];
        for pad in [0, 1, 2, 3, 8] {
            let mut body = version.to_vec();
            body.extend(core::iter::repeat_n(0, pad));
            let a = Advert::parse(&body).unwrap_or_else(|e| panic!("{pad} zeros: {e}"));
            assert_eq!(a.version, Some((VERSION, devclass::IOS)));
        }
        let mut nonzero = version.to_vec();
        nonzero.extend([0, 1]);
        assert_eq!(Advert::parse(&nonzero), Err(Error::Truncated));
        let mut half = version.to_vec();
        half.extend([kind::VERSION, 2]);
        assert_eq!(Advert::parse(&half), Err(Error::Truncated));
        let mut long = version.to_vec();
        long.extend([kind::VERSION, 9, 0, 1]);
        assert_eq!(Advert::parse(&long), Err(Error::Truncated));
    }

    // spec: AWDL-6
    #[test]
    fn unknown_tlvs_are_skipped_by_length() {
        let mut body = vec![99, 4, 0, 1, 2, 3, 4, kind::BLOOM_FILTER, 1, 0, 7];
        body.extend([kind::VERSION, 2, 0, VERSION, devclass::IOS]);
        assert_eq!(
            Advert::parse(&body).unwrap().version,
            Some((VERSION, devclass::IOS))
        );
    }

    #[test]
    fn version_1_election_gives_way_to_version_2() {
        let body = own_frame(false);
        // Only the v1 TLV: its sender syncs to itself.
        let v1: Vec<u8> = tlvs(&body)
            .map(Result::unwrap)
            .filter(|t| t.kind == kind::ELECTION_PARAMS)
            .flat_map(|t| {
                let mut b = vec![t.kind];
                b.extend((t.value.len() as u16).to_le_bytes());
                b.extend(t.value);
                b
            })
            .collect();
        let a = Advert::parse(&v1).unwrap();
        assert!(!a.election_v2);
        let e = a.election.unwrap();
        assert_eq!((e.sync, e.height, e.master_metric), (None, 1, 522));
    }

    #[test]
    fn ht_masks_of_any_length() {
        let mut v = vec![0, 0, 0xce, 0x11, 0x1b, 0xff, 0xff, 0, 0];
        let ht = HtCapabilities::parse(&v).unwrap();
        assert_eq!(ht.rx_mcs, 0xffff);
        v.truncate(6);
        assert_eq!(HtCapabilities::parse(&v).unwrap().rx_mcs, 0xff);
        assert_eq!(HtCapabilities::ONE_STREAM.max_amsdu(), 3839);
        v.truncate(5);
        assert!(HtCapabilities::parse(&v).is_err());
    }

    #[test]
    fn names_are_bounded() {
        let long = "x".repeat(100);
        let mut out = Vec::new();
        put_arpa(&mut out, &long);
        let t = tlvs(&out).next().unwrap().unwrap();
        assert_eq!(parse_arpa(t.value).unwrap().len(), NAME_MAX);
        assert_eq!(parse_arpa(&[3, 10, b'a']), Err(Error::Truncated));
    }

    #[test]
    fn tuned_tlvs() {
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        let seq = Sequence::fixed(Channel(6));
        let e = Election::own(mac);
        let own = Own {
            addr: mac,
            name: "owly",
            devclass: devclass::MACOS,
            channel: 6,
            master_channel: Channel(6),
            next_tu: 20,
            aw_counter: 401,
            psf_interval_tu: 110,
            sequence: &seq,
            election: &e,
            ht: Some(HtCapabilities::TWO_STREAM_SGI),
            tuned: true,
        };
        let mut out = Vec::new();
        put_data_path_state(&mut out, &own);
        let tlv = tlvs(&out).next().unwrap().unwrap();
        assert_eq!(tlv.kind, kind::DATA_PATH_STATE);
        let b = Bytes(tlv.value);
        assert_eq!(b.le16(0).unwrap(), 0xaf84);
        assert_eq!(b.le16(13).unwrap(), 0x0008);

        let mut ht_out = Vec::new();
        put_ht_capabilities(&mut ht_out, &HtCapabilities::TWO_STREAM_SGI);
        let ht_tlv = tlvs(&ht_out).next().unwrap().unwrap();
        assert_eq!(ht_tlv.kind, kind::HT_CAPABILITIES);
        let hb = Bytes(ht_tlv.value);
        assert_eq!(hb.le16(2).unwrap(), 0x11ee);
        assert_eq!(hb.u8(4).unwrap(), 0x1b);
        assert_eq!(hb.u8(5).unwrap(), 0xff);
        assert_eq!(hb.le16(6).unwrap(), 0x00ff);
        assert!(HtCapabilities::TWO_STREAM_SGI.sgi20());
    }
}
