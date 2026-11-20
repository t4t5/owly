//! A receiver's DNS-SD records in action frames (MDNS-2): the Service
//! Response TLV, and the values of the Service Parameters TLV (§3.2).
//!
//! A peer that hears a node's action frames has its records, on whatever
//! channel it hears them. One that waits for the node's multicast mDNS has
//! to share a multicast slot with it, which a radio that can't hop seldom
//! does. A node has no say in what its host announces, so it reads the
//! records from the host's own mDNS responses on their way out.

use alloc::vec::Vec;

use crate::wire::Put;

/// DNS record types.
const PTR: u16 = 12;
const TXT: u16 = 16;
const SRV: u16 = 33;

/// AirDrop's service, and the name codes for it and for `.local`.
const AIRDROP: [&[u8]; 3] = [b"_airdrop", b"_tcp", b"local"];
const CODE_OWN_NAME: u16 = 0xc000;
const CODE_AIRDROP: u16 = 0xc007;
const CODE_LOCAL: u16 = 0xc00c;

/// TXT data longer than this isn't carried: action frames have to stay
/// small. A receiver's is its flags.
const MAX_TXT: usize = 255;

/// A DNS name as its labels, without the root.
pub type Name = Vec<Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// The instance: one label before the record's own name.
    Ptr(Vec<u8>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        /// The host's label, under `.local`.
        host: Vec<u8>,
    },
    Txt(Vec<u8>),
}

/// One record a node carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub data: Data,
}

impl Record {
    fn kind(&self) -> u16 {
        match self.data {
            Data::Ptr(_) => PTR,
            Data::Srv { .. } => SRV,
            Data::Txt(_) => TXT,
        }
    }

    /// Whether `other` is this record anew: the same name and type.
    pub fn replaces(&self, other: &Record) -> bool {
        self.kind() == other.kind() && self.name == other.name
    }
}

fn ends_with(name: &[Vec<u8>], suffix: &[&[u8]]) -> bool {
    name.len() >= suffix.len()
        && name[name.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// CRC-8 with polynomial `0x07`, from 0.
fn crc8(bytes: impl Iterator<Item = u8>) -> u8 {
    bytes.fold(0, |mut c, b| {
        c ^= b;
        for _ in 0..8 {
            c = if c & 0x80 != 0 {
                (c << 1) ^ 0x07
            } else {
                c << 1
            };
        }
        c
    })
}

/// The Service Parameters value for a record name: the CRC-8 of the name as
/// DNS writes it, in lower case.
pub fn value(name: &[Vec<u8>]) -> u8 {
    let wire = name
        .iter()
        .flat_map(|l| {
            core::iter::once(l.len() as u8).chain(l.iter().map(|b| b.to_ascii_lowercase()))
        })
        .chain(core::iter::once(0));
    crc8(wire)
}

/// Writes the Service Parameters TLV's value: the SUI, and `values` as a
/// mask and a byte for each of its bits.
pub fn put_params(out: &mut Vec<u8>, sui: u16, values: impl Iterator<Item = u8>) {
    let mut mask = 0u32;
    let mut bytes = [0u8; 32];
    for v in values {
        mask |= 1 << (v / 8);
        bytes[(v / 8) as usize] |= 1 << (v % 8);
    }
    out.extend_from_slice(&[0; 3]);
    out.le16(sui);
    out.le32(mask);
    out.extend(bytes.into_iter().filter(|b| *b != 0));
}

fn put_label(out: &mut Vec<u8>, label: &[u8]) {
    let label = &label[..label.len().min(63)];
    out.u8(label.len() as u8);
    out.extend_from_slice(label);
}

/// Writes the Service Response TLV's value for one of AirDrop's records.
pub fn put_response(out: &mut Vec<u8>, record: &Record) {
    // The labels before the service's name, then its code.
    let mut name = Vec::new();
    let own = record.name.len().saturating_sub(AIRDROP.len());
    for label in &record.name[..own] {
        put_label(&mut name, label);
    }
    name.be16(CODE_AIRDROP);
    let mut data = Vec::new();
    match &record.data {
        Data::Ptr(instance) => {
            put_label(&mut data, instance);
            data.be16(CODE_OWN_NAME);
        }
        Data::Srv {
            priority,
            weight,
            port,
            host,
        } => {
            data.be16(*priority);
            data.be16(*weight);
            data.be16(*port);
            put_label(&mut data, host);
            data.be16(CODE_LOCAL);
        }
        Data::Txt(txt) => data.extend_from_slice(txt),
    }
    out.le16(name.len() as u16 + 1);
    out.extend_from_slice(&name);
    out.u8(record.kind() as u8);
    out.le16(data.len() as u16);
    out.le16(0);
    out.extend_from_slice(&data);
}

/// Reads the DNS name at `at`, following compression pointers.
fn read_name(msg: &[u8], mut at: usize) -> Option<Name> {
    let mut labels = Vec::new();
    // A name has at most 127 labels; more hops than that is a loop.
    for _ in 0..128 {
        let len = *msg.get(at)? as usize;
        match len {
            0 => return Some(labels),
            1..=63 => {
                labels.push(msg.get(at + 1..at + 1 + len)?.to_vec());
                at += 1 + len;
            }
            _ if len & 0xc0 == 0xc0 => at = (len & 0x3f) << 8 | *msg.get(at + 1)? as usize,
            _ => return None,
        }
    }
    None
}

/// The offset just past the DNS name at `at`.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        match *msg.get(at)? as usize {
            0 => return Some(at + 1),
            len if len & 0xc0 == 0xc0 => return Some(at + 2),
            len => at += 1 + len,
        }
    }
}

/// The AirDrop records an IPv6 packet of the host's announces, each with
/// whether it still stands (a TTL of 0 withdraws it): none unless the packet
/// is an mDNS response. Only what the TLV has a way to write is taken: the
/// service's PTR to an instance, and the instance's TXT and its SRV to a
/// host under `.local`.
pub fn announced(packet: &[u8]) -> Vec<(Record, bool)> {
    let mut out = Vec::new();
    // No extension headers, UDP, to port 5353, and a response.
    let Some(msg) = packet
        .get(48..)
        .filter(|_| packet[6] == 17 && packet[42..44] == 5353u16.to_be_bytes())
        .filter(|m| m.len() >= 12 && m[2] & 0x80 != 0)
    else {
        return out;
    };
    let count = |at: usize| u16::from_be_bytes([msg[at], msg[at + 1]]) as usize;
    let mut at = 12;
    for _ in 0..count(4) {
        match skip_name(msg, at) {
            Some(next) => at = next + 4,
            None => return out,
        }
    }
    for _ in 0..count(6) + count(8) + count(10) {
        let Some((name, fixed)) = read_name(msg, at).zip(skip_name(msg, at)) else {
            break;
        };
        let Some(header) = msg.get(fixed..fixed + 10) else {
            break;
        };
        let alive = header[4..8] != [0; 4];
        let start = fixed + 10;
        let Some(rdata) =
            msg.get(start..start + u16::from_be_bytes([header[8], header[9]]) as usize)
        else {
            break;
        };
        at = start + rdata.len();
        if !ends_with(&name, &AIRDROP) {
            continue;
        }
        let instance = name.len() == AIRDROP.len() + 1;
        let data = match (u16::from_be_bytes([header[0], header[1]]), instance) {
            (PTR, false) if name.len() == AIRDROP.len() => match read_name(msg, start) {
                Some(mut target) if target.len() == name.len() + 1 && target[1..] == name[..] => {
                    Data::Ptr(target.swap_remove(0))
                }
                _ => continue,
            },
            (SRV, true) if rdata.len() > 6 => match read_name(msg, start + 6) {
                Some(mut target) if target.len() == 2 && ends_with(&target, &[b"local"]) => {
                    Data::Srv {
                        priority: u16::from_be_bytes([rdata[0], rdata[1]]),
                        weight: u16::from_be_bytes([rdata[2], rdata[3]]),
                        port: u16::from_be_bytes([rdata[4], rdata[5]]),
                        host: target.swap_remove(0),
                    }
                }
                _ => continue,
            },
            (TXT, true) if rdata.len() <= MAX_TXT => Data::Txt(rdata.to_vec()),
            _ => continue,
        };
        out.push((Record { name, data }, alive));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn name(labels: &[&str]) -> Name {
        labels.iter().map(|l| l.as_bytes().to_vec()).collect()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn airdrop() -> Vec<Record> {
        let instance = name(&["0123456789ab", "_airdrop", "_tcp", "local"]);
        vec![
            Record {
                name: name(&["_airdrop", "_tcp", "local"]),
                data: Data::Ptr(b"0123456789ab".to_vec()),
            },
            Record {
                name: instance.clone(),
                data: Data::Srv {
                    priority: 0,
                    weight: 0,
                    port: 8770,
                    host: b"host".to_vec(),
                },
            },
            Record {
                name: instance,
                data: Data::Txt(vec![0]),
            },
        ]
    }

    // spec: MDNS-2, T-AWDL-4
    #[test]
    fn records_are_written_with_their_name_codes() {
        let r = airdrop();
        let mut out = Vec::new();
        put_response(&mut out, &r[0]);
        // The service's code alone, PTR, then the instance before c000.
        assert_eq!(out, hex("0300c0070c0f0000000c303132333435363738396162c000"));
        out.clear();
        put_response(&mut out, &r[1]);
        assert_eq!(
            out,
            hex("10000c303132333435363738396162c007210d00000000000000224204686f7374c00c")
        );
        out.clear();
        put_response(&mut out, &r[2]);
        assert_eq!(out, hex("10000c303132333435363738396162c007100100000000"));
    }

    // spec: MDNS-2
    #[test]
    fn a_name_has_one_value_whatever_its_case() {
        // The check value of this CRC.
        assert_eq!(crc8(b"123456789".iter().copied()), 0xf4);
        assert_eq!(value(&name(&["_airdrop", "_tcp", "local"])), 158);
        assert_eq!(
            value(&name(&["_appSvcPrePair", "_tcp", "local"])),
            value(&name(&["_appsvcprepair", "_tcp", "local"]))
        );
        assert_eq!(value(&name(&["_appsvcprepair", "_tcp", "local"])), 45);
    }

    // spec: MDNS-2
    #[test]
    fn values_are_a_mask_and_a_byte_per_bit() {
        // As an iPhone with four names announced them.
        let mut out = Vec::new();
        put_params(&mut out, 0x15, [4, 32, 45, 102].into_iter());
        assert_eq!(out, hex("00000015003110000010012040"));
        // The service's name, and the instance's once for its two records.
        out.clear();
        put_params(&mut out, 0x54, airdrop().iter().map(|r| value(&r.name)));
        assert_eq!(value(&airdrop()[1].name), 246);
        // 158 and 246: bit 6 of bytes 19 and 30.
        assert_eq!(out, hex("0000005400000008404040"));
        // None: as a node without records sends it.
        out.clear();
        put_params(&mut out, 0, core::iter::empty());
        assert_eq!(out, [0; 9]);
    }

    /// The host's packet announcing a receiver: PTR, SRV, TXT and AAAA, with
    /// names compressed.
    fn announcement(ttl: u32) -> Vec<u8> {
        let mut m = hex("000084000000000400000000");
        let service = m.len();
        m.extend_from_slice(b"\x08_airdrop\x04_tcp\x05local\x00");
        m.extend_from_slice(&[0, 12, 0, 1]);
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&[0, 15]);
        let instance = m.len();
        m.extend_from_slice(b"\x0c0123456789ab");
        m.extend_from_slice(&[0xc0, service as u8]);
        // SRV
        m.extend_from_slice(&[0xc0, instance as u8, 0, 33, 0x80, 1]);
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&[0, 13, 0, 0, 0, 0, 0x22, 0x43]);
        let host = m.len();
        m.extend_from_slice(b"\x04host");
        m.extend_from_slice(&[0xc0, (service + 14) as u8]);
        // TXT
        m.extend_from_slice(&[0xc0, instance as u8, 0, 16, 0x80, 1]);
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&[0, 10]);
        m.extend_from_slice(b"\x09flags=137");
        // AAAA
        m.extend_from_slice(&[0xc0, host as u8, 0, 28, 0x80, 1]);
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&[0, 16]);
        m.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // IPv6 and UDP headers, of which the next header and the port count.
        let mut packet = vec![0u8; 48];
        packet[6] = 17;
        packet[42..44].copy_from_slice(&5353u16.to_be_bytes());
        packet.extend_from_slice(&m);
        packet
    }

    // spec: MDNS-2
    #[test]
    fn an_announcement_gives_the_receivers_records() {
        let records = announced(&announcement(120));
        assert!(records.iter().all(|(_, alive)| *alive));
        let records: Vec<Record> = records.into_iter().map(|(r, _)| r).collect();
        let mut expect = airdrop();
        expect[1].data = Data::Srv {
            priority: 0,
            weight: 0,
            port: 8771,
            host: b"host".to_vec(),
        };
        expect[2].data = Data::Txt(b"\x09flags=137".to_vec());
        assert_eq!(records, expect);
        // A goodbye withdraws them.
        assert!(announced(&announcement(0)).iter().all(|(_, alive)| !alive));
        // A query, and TCP to the same port, say nothing.
        let mut query = announcement(120);
        query[48 + 2] = 0;
        assert_eq!(announced(&query), []);
        let mut tcp = announcement(120);
        tcp[6] = 6;
        assert_eq!(announced(&tcp), []);
    }

    #[test]
    fn a_packet_cut_short_or_looping_is_read_as_far_as_it_goes() {
        let whole = announcement(120);
        for len in 0..whole.len() {
            assert!(announced(&whole[..len]).len() <= 3);
        }
        // A name that points at itself.
        let mut looping = whole.clone();
        looping[48 + 12] = 0xc0;
        looping[48 + 13] = 12;
        assert_eq!(announced(&looping), []);
    }
}
