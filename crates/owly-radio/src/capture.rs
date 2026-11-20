//! What `owly capture` keeps of what a monitor hears, for the capture
//! corpus (`tests/captures/`), and how it takes everything personal out
//! before anything is written: the corpus is committed.
//!
//! [`Filter`] keeps AWDL's frames between the nodes it's told to keep, and
//! nothing of the router's or of bystanders'. Of what it keeps it blanks,
//! leaving every length as it was so that frames still parse the same:
//!
//! - host names (ARPA TLVs) and the country code (Data Path State);
//! - TLVs whose contents aren't known (service records, which carry mDNS
//!   names, the bloom filter, deprecated and unknown types);
//! - every packet's contents past its IPv6 and TCP, UDP or ICMPv6 header,
//!   which takes mDNS names and whatever was sent with them.
//!
//! [`Pseudonyms`] then replaces every MAC address, wherever it is: in frame
//! headers, in TLVs (masters, sync trees, the infrastructure BSSID and
//! address a phone announces, which would place it), and as the interface
//! ID of IPv6 addresses. Stand-ins are given in the order of the real
//! addresses, so that elections, which break ties by address, replay the
//! same.

use std::collections::{BTreeMap, BTreeSet};

use owly_awdl::frame::{self, Received, fc};
use owly_awdl::tlv::{self, kind};
use owly_awdl::{BSSID, MacAddr};

/// Which nodes' frames to keep.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// The AWDL addresses to keep frames from and to: the phone, and this
    /// computer's. Empty keeps every AWDL node's action and data frames,
    /// bystanders' too, and no control frames.
    pub keep: Vec<MacAddr>,
}

impl Filter {
    fn kept(&self, mac: MacAddr) -> bool {
        self.keep.is_empty() || self.keep.contains(&mac)
    }

    fn listed(&self, mac: MacAddr) -> bool {
        self.keep.contains(&mac)
    }

    /// The frame to keep, blanked, if it's kept: an 802.11 frame, without
    /// radiotap or FCS. Its addresses are still the real ones.
    pub fn apply(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.len() < 10 {
            return None;
        }
        let control = u16::from_le_bytes([bytes[0], bytes[1]]);
        // Control frames carry no BSSID: Block Acks and their requests
        // (AWDL-15), and ACKs, only to and from listed nodes. Their bodies
        // are sequence numbers and bitmaps.
        if control & 0x000c == 0x0004 {
            let ra = MacAddr(bytes[4..10].try_into().ok()?);
            let ta = bytes
                .get(10..16)
                .and_then(|b| b.try_into().ok())
                .map(MacAddr);
            return (self.listed(ra) || ta.is_some_and(|t| self.listed(t))).then(|| bytes.to_vec());
        }
        let mut out = bytes.to_vec();
        match frame::parse(bytes).ok()? {
            Received::Action { header, .. } if self.kept(header.src) => {
                blank_tlvs(&mut out);
                Some(out)
            }
            Received::AddBaRequest { header, .. }
                if self.listed(header.src) || self.listed(header.dst) =>
            {
                Some(out)
            }
            Received::Data {
                header,
                amsdu,
                body,
            } if self.kept(header.src) => {
                let msdus = frame::msdus(&header, amsdu, body).ok()?;
                for m in msdus {
                    let at = m.payload.as_ptr() as usize - bytes.as_ptr() as usize;
                    blank_packet(&mut out[at..at + m.payload.len()]);
                }
                Some(out)
            }
            Received::Other => {
                // The rest of Block Ack's action frames: responses, DELBA.
                let h = frame::parse_header(bytes)?;
                let body = bytes.get(frame::HEADER_LEN..)?;
                let ba = h.fc & fc::TYPE_SUBTYPE == fc::ACTION && body.first() == Some(&3);
                (ba && h.bssid == BSSID && (self.listed(h.src) || self.listed(h.dst)))
                    .then_some(out)
            }
            _ => None,
        }
    }
}

/// Where each TLV of an AWDL action frame starts, and its type and length.
fn tlv_spans(f: &[u8]) -> Vec<(usize, u8, usize)> {
    let start = frame::HEADER_LEN + frame::ACTION_HEADER_LEN;
    let mut at = start;
    tlv::tlvs(f.get(start..).unwrap_or_default())
        .map_while(Result::ok)
        .map(|t| {
            let here = at;
            at += 3 + t.value.len();
            (here, t.kind, t.value.len())
        })
        .collect()
}

/// The TLVs a node reads for timing, election, schedule and capabilities
/// stay; names, the country and anything unknown are blanked.
fn blank_tlvs(f: &mut [u8]) {
    for (here, k, len) in tlv_spans(f) {
        let value = here + 3..here + 3 + len;
        match k {
            kind::SYNC_PARAMS
            | kind::ELECTION_PARAMS
            | kind::ELECTION_PARAMS_V2
            | kind::SERVICE_PARAMS
            | kind::HT_CAPABILITIES
            | kind::IEEE80211_CONTAINER
            | kind::CHANNEL_SEQUENCE
            | kind::SYNC_TREE
            | kind::VERSION => {}
            kind::ARPA => {
                let n = f.get(here + 4).copied().unwrap_or(0) as usize;
                if let Some(name) = f.get_mut(here + 5..(here + 5 + n).min(value.end)) {
                    name.fill(b'x');
                }
            }
            kind::DATA_PATH_STATE => {
                let flags =
                    u16::from_le_bytes([f[here + 3], f.get(here + 4).copied().unwrap_or(0)]);
                if flags & 0x0100 != 0
                    && let Some(cc) = f.get_mut(here + 5..(here + 8).min(value.end))
                {
                    cc.fill(b'X');
                }
            }
            _ => f[value].fill(0),
        }
    }
}

/// Zeroes an IPv6 packet's contents past its header and its TCP, UDP or
/// ICMPv6 header; or all of it, if it's anything else.
fn blank_packet(p: &mut [u8]) {
    let keep = if p.len() >= 40 && p[0] >> 4 == 6 {
        40 + match p[6] {
            6 => p.get(52).map_or(0, |b| ((b >> 4) as usize * 4).max(20)),
            17 => 8,
            58 => 8,
            _ => 0,
        }
    } else {
        0
    };
    if let Some(rest) = p.get_mut(keep.min(p.len())..) {
        rest.fill(0);
    }
}

/// Every unicast MAC address in a frame (as [`Filter::apply`] leaves it):
/// its header's, and those in its TLVs. Data frames' IPv6 addresses carry
/// the same MACs as their headers.
pub fn addresses(f: &[u8]) -> Vec<MacAddr> {
    let mut out = Vec::new();
    let mac = |at: usize| f.get(at..at + 6).map(|b| MacAddr(b.try_into().unwrap()));
    out.extend(mac(4));
    if let Some(h) = frame::parse_header(f) {
        out.extend([h.src, h.bssid]);
    }
    if let Ok(Received::Action { .. }) = frame::parse(f) {
        for (here, k, len) in tlv_spans(f) {
            let v = here + 3;
            match k {
                kind::SYNC_PARAMS => out.extend(mac(v + 21)),
                kind::ELECTION_PARAMS => out.extend(mac(v + 5)),
                kind::ELECTION_PARAMS_V2 => out.extend(mac(v).into_iter().chain(mac(v + 6))),
                kind::SYNC_TREE => out.extend((0..len / 6).filter_map(|i| mac(v + 6 * i))),
                kind::DATA_PATH_STATE => {
                    let flags = u16::from_le_bytes([f[v], f.get(v + 1).copied().unwrap_or(0)]);
                    let mut at = v + 2;
                    for (bit, size, macs) in [
                        (0x0100, 3, &[][..]),
                        (0x0200, 2, &[][..]),
                        (0x0001, 8, &[0][..]),
                        (0x0002, 6, &[0][..]),
                        (0x0004, 6, &[0][..]),
                    ] {
                        if flags & bit != 0 {
                            out.extend(macs.iter().filter_map(|o| mac(at + o)));
                            at += size;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out.retain(|m| !m.is_multicast() && *m != BSSID && *m != MacAddr([0; 6]));
    out
}

/// Stand-ins for real MAC addresses: `02:00:00:00:00:01` and on, given in
/// the real addresses' order.
#[derive(Debug, Clone, Default)]
pub struct Pseudonyms {
    map: BTreeMap<MacAddr, MacAddr>,
}

impl Pseudonyms {
    pub fn new(real: impl IntoIterator<Item = MacAddr>) -> Pseudonyms {
        let all: BTreeSet<MacAddr> = real.into_iter().collect();
        let map = all
            .into_iter()
            .enumerate()
            .map(|(i, m)| (m, Pseudonyms::nth(i + 1)))
            .collect();
        Pseudonyms { map }
    }

    /// The `n`th stand-in.
    pub fn nth(n: usize) -> MacAddr {
        let n = n as u32;
        MacAddr([0x02, 0, 0, (n >> 16) as u8, (n >> 8) as u8, n as u8])
    }

    /// Whether an address is one of the stand-ins.
    pub fn is_pseudonym(m: MacAddr) -> bool {
        m.0[..3] == [0x02, 0, 0]
    }

    pub fn get(&self, real: MacAddr) -> Option<MacAddr> {
        self.map.get(&real).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (MacAddr, MacAddr)> + '_ {
        self.map.iter().map(|(a, b)| (*a, *b))
    }

    /// Replaces every real address in `bytes`, as six bytes and as an
    /// IPv6 interface ID (modified EUI-64).
    pub fn apply(&self, bytes: &mut [u8]) {
        for (real, fake) in &self.map {
            replace(bytes, &real.0, &fake.0);
            replace(bytes, &eui64(*real), &eui64(*fake));
        }
    }
}

fn eui64(m: MacAddr) -> [u8; 8] {
    let o = m.link_local().octets();
    o[8..].try_into().unwrap()
}

fn replace(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    let n = from.len();
    let mut i = 0;
    while i + n <= bytes.len() {
        if bytes[i..i + n] == *from {
            bytes[i..i + n].copy_from_slice(to);
            i += n;
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use owly_awdl::channel::{Channel, Sequence};
    use owly_awdl::election::Election;
    use owly_awdl::tlv::{Own, put_all};

    const PHONE: MacAddr = MacAddr([0x86, 8, 4, 0x8a, 0x2b, 0xf4]);
    const US: MacAddr = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1]);
    const BYSTANDER: MacAddr = MacAddr([0x4e, 1, 2, 3, 4, 5]);
    const ROUTER: MacAddr = MacAddr([0x9c, 0x53, 0x22, 0x10, 0x20, 0x30]);
    const IPAD: MacAddr = MacAddr([0x5a, 0x11, 0x22, 0x33, 0x44, 0x55]);

    /// A phone's MIF as an iPhone's would be: its master an iPad, a sync
    /// tree, its router in the Data Path State, a bloom filter and a
    /// service record with a name in it.
    fn mif(from: MacAddr) -> Vec<u8> {
        let seq = Sequence::fixed(Channel(6));
        let mut e = Election::own(from);
        e.master = IPAD;
        e.sync = IPAD;
        let own = Own {
            addr: from,
            name: "Charlies-iPhone",
            devclass: 2,
            channel: 6,
            master_channel: Channel(6),
            next_tu: 64,
            aw_counter: 0,
            psf_interval_tu: 110,
            sequence: &seq,
            election: &e,
            ht: None,
            tuned: false,
        };
        frame::action_frame(from, 0, frame::subtype::MIF, 0, |o| {
            put_all(o, &own, true);
            // Data Path State: country, infrastructure BSSID and channel,
            // infrastructure address, AWDL address.
            let mut dp = vec![0x07, 0x01];
            dp.extend_from_slice(b"DE\0");
            dp.extend_from_slice(&ROUTER.0);
            dp.extend_from_slice(&[44, 0]);
            dp.extend_from_slice(&[0x5e, 1, 1, 1, 1, 1]);
            dp.extend_from_slice(&from.0);
            o.extend_from_slice(&[kind::DATA_PATH_STATE, dp.len() as u8, 0]);
            o.extend_from_slice(&dp);
            o.extend_from_slice(&[kind::SYNC_TREE, 12, 0]);
            o.extend_from_slice(&IPAD.0);
            o.extend_from_slice(&from.0);
            o.extend_from_slice(&[kind::BLOOM_FILTER, 4, 0, 0xde, 0xad, 0xbe, 0xef]);
            o.extend_from_slice(&[kind::SERVICE_RESPONSE, 9, 0]);
            o.extend_from_slice(b"\x08Charlies");
        })
    }

    /// An mDNS packet from the phone, naming it.
    fn mdns_from_phone() -> Vec<u8> {
        let payload = b"\x0fCharlies-iPhone\x05local\x00";
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[17, 255]);
        p.extend_from_slice(&PHONE.link_local().octets());
        p.extend_from_slice(&"ff02::fb".parse::<std::net::Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&[0x14, 0xe9, 0x14, 0xe9, 0, 0, 0, 0]);
        p.extend_from_slice(payload);
        let group = MacAddr([0x33, 0x33, 0, 0, 0, 0xfb]);
        frame::data_frame(PHONE, group, 1, 1, &p)
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn nothing_personal_is_left() {
        let f = Filter {
            keep: vec![PHONE, US],
        };
        let frames = [
            f.apply(&mif(PHONE)).expect("the phone's MIF"),
            f.apply(&mdns_from_phone()).expect("its mDNS"),
            f.apply(&frame::data_frame(
                US,
                PHONE,
                2,
                2,
                &mdns_from_phone()[40..],
            ))
            .expect("ours"),
            f.apply(&frame::addba_response(US, PHONE, 1, 1, 0, 0))
                .expect("ADDBA"),
        ];
        let p = Pseudonyms::new(frames.iter().flat_map(|f| addresses(f)));
        for real in [PHONE, US, ROUTER, IPAD, MacAddr([0x5e, 1, 1, 1, 1, 1])] {
            assert!(p.get(real).is_some(), "{real} found");
        }
        for (i, mut frame) in frames.into_iter().enumerate() {
            let len = frame.len();
            p.apply(&mut frame);
            assert_eq!(frame.len(), len);
            for real in [PHONE, US, ROUTER, IPAD] {
                assert!(!contains(&frame, &real.0), "frame {i} has {real}");
                assert!(
                    !contains(&frame, &eui64(real)),
                    "frame {i} has {real} in IPv6"
                );
            }
            for word in [&b"Charlies"[..], b"DE", b"\xde\xad\xbe\xef"] {
                assert!(!contains(&frame, word), "frame {i} has {word:?}");
            }
            // Every address left is a stand-in or a group.
            for m in addresses(&frame) {
                assert!(Pseudonyms::is_pseudonym(m), "frame {i}: {m}");
            }
            // And it still parses whole.
            if let Ok(Received::Action { tlvs, .. }) = frame::parse(&frame) {
                let a = tlv::Advert::parse(tlvs).unwrap();
                assert_eq!(a.name.as_deref(), Some("xxxxxxxxxxxxxxx"));
                assert_eq!(a.election.unwrap().master, p.get(IPAD).unwrap());
            }
        }
    }

    #[test]
    fn stand_ins_keep_the_order_of_addresses() {
        let p = Pseudonyms::new([PHONE, US, IPAD, BYSTANDER]);
        let mut real: Vec<_> = p.iter().collect();
        real.sort();
        assert!(real.windows(2).all(|w| w[0].1 < w[1].1));
        assert_eq!(p.get(BYSTANDER), Some(Pseudonyms::nth(1)));
    }

    #[test]
    fn packets_keep_their_headers_only() {
        let mut tcp = vec![0x60, 0, 0, 0, 0, 30, 6, 64];
        tcp.extend_from_slice(&[0xab; 32]);
        let mut seg = vec![0u8; 20];
        seg[12] = 6 << 4; // 24 bytes with options
        seg.extend_from_slice(&[0xcd; 4]);
        seg.extend_from_slice(b"secret");
        tcp.extend_from_slice(&seg);
        blank_packet(&mut tcp);
        assert_eq!(&tcp[40 + 20..40 + 24], &[0xcd; 4], "options stay");
        assert!(tcp[64..].iter().all(|&b| b == 0), "data goes");
        assert_eq!(&tcp[8..40], &[0xab; 32]);
        let mut other = vec![0x45; 30];
        blank_packet(&mut other);
        assert!(other.iter().all(|&b| b == 0));
    }

    #[test]
    fn keeps_the_listed_nodes_only() {
        let f = Filter {
            keep: vec![PHONE, US],
        };
        assert_eq!(f.apply(&mif(BYSTANDER)), None);
        let mut ap = frame::data_frame(PHONE, US, 1, 1, &[0x60]);
        ap[16] = 0x10;
        assert_eq!(f.apply(&ap), None, "an AP's frame");
        let mut ack = vec![0xd4, 0, 0, 0];
        ack.extend_from_slice(&US.0);
        assert!(f.apply(&ack).is_some());
        ack[4] = 0x02;
        assert_eq!(f.apply(&ack), None);
        // With nobody listed, every AWDL node, but no control frames.
        let all = Filter::default();
        assert!(all.apply(&mif(BYSTANDER)).is_some());
        ack[4] = US.0[0];
        assert_eq!(all.apply(&ack), None);
    }
}
