//! DNS-SD over mDNS for `_airdrop._tcp` (§5): a strict DNS message codec,
//! the records a receiver publishes, and sans-IO responder and browser
//! logic. Time is passed in, never read.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// RFC 6762 §17: the largest message, on any link.
pub const MAX_MESSAGE: usize = 9000;

const SERVICE: [&str; 3] = ["_airdrop", "_tcp", "local"];

/// MDNS-5: URL | MIXED_TYPES | DISCOVER_MAYBE. Without URL, iOS 26.7.1
/// offers a link as a `.webloc` it never uploads. No DVZip (0x002) receive
/// is claimed until it's proven against Apple senders.
pub const RECEIVER_FLAGS: u32 = 0x089;
pub const SUPPORTS_URL: u32 = 0x001;
pub const SUPPORTS_DVZIP: u32 = 0x002;
pub const SUPPORTS_PIPELINING: u32 = 0x004;
pub const SUPPORTS_MIXED_TYPES: u32 = 0x008;

pub mod rtype {
    pub const A: u16 = 1;
    pub const PTR: u16 = 12;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const ANY: u16 = 255;
}

const CLASS_IN: u16 = 1;
/// The class's top bit: cache-flush on a record, unicast-response (QU) on a
/// question.
const CLASS_TOP: u16 = 0x8000;

/// RFC 6762 §10: host records live 120 s, others 75 minutes.
const HOST_TTL: u32 = 120;
const OTHER_TTL: u32 = 4500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad DNS message: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// A domain name as labels. Comparison ignores ASCII case (RFC 6762 §16).
#[derive(Debug, Clone, Default)]
pub struct Name(pub Vec<String>);

impl Name {
    pub fn new(labels: &[&str]) -> Self {
        Name(labels.iter().map(|l| l.to_string()).collect())
    }

    pub fn service() -> Self {
        Name::new(&SERVICE)
    }

    pub fn instance(instance: &str) -> Self {
        let mut labels = vec![instance];
        labels.extend_from_slice(&SERVICE);
        Name::new(&labels)
    }

    pub fn host(host: &str) -> Self {
        Name::new(&[host, "local"])
    }

    /// The instance label, if this is `<instance>._airdrop._tcp.local`.
    pub fn instance_label(&self) -> Option<&str> {
        (self.0.len() == 4 && Name(self.0[1..].to_vec()) == Name::service())
            .then(|| self.0[0].as_str())
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self
                .0
                .iter()
                .zip(&other.0)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl Eq for Name {}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.", self.0.join("."))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    Ptr(Name),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    Txt(Vec<Vec<u8>>),
    Aaaa(Ipv6Addr),
    Other(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: u16,
    pub cache_flush: bool,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: Name,
    pub qtype: u16,
    /// QU: the asker would like a unicast reply.
    pub unicast: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Message {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MESSAGE {
            return Err(Error("too long"));
        }
        let mut r = Reader { bytes, pos: 12 };
        if bytes.len() < 12 {
            return Err(Error("too short"));
        }
        let u16_at = |i: usize| u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        let flags = u16_at(2);
        // Opcode 0 only, and nothing truncated.
        if flags & 0x7800 != 0 {
            return Err(Error("not a standard query or response"));
        }
        let counts = [u16_at(4), u16_at(6), u16_at(8), u16_at(10)];
        // Every question takes at least 5 bytes, every record 11.
        if counts[0] as usize * 5
            + (counts[1] as usize + counts[2] as usize + counts[3] as usize) * 11
            > bytes.len()
        {
            return Err(Error("counts exceed the message"));
        }
        let mut message = Message {
            id: u16_at(0),
            response: flags & 0x8000 != 0,
            ..Message::default()
        };
        for _ in 0..counts[0] {
            let name = r.name()?;
            let qtype = r.u16()?;
            let class = r.u16()?;
            message.questions.push(Question {
                name,
                qtype,
                unicast: class & CLASS_TOP != 0,
            });
        }
        for (count, section) in [
            (counts[1], &mut message.answers),
            (counts[2], &mut message.authority),
            (counts[3], &mut message.additional),
        ] {
            for _ in 0..count {
                section.push(r.record()?);
            }
        }
        Ok(message)
    }

    /// Encodes without name compression, which is always valid.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&self.id.to_be_bytes());
        // A response is authoritative (RFC 6762 §18.4).
        let flags: u16 = if self.response { 0x8400 } else { 0 };
        out.extend_from_slice(&flags.to_be_bytes());
        for n in [
            self.questions.len(),
            self.answers.len(),
            self.authority.len(),
            self.additional.len(),
        ] {
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        for q in &self.questions {
            encode_name(&q.name, &mut out);
            out.extend_from_slice(&q.qtype.to_be_bytes());
            let class = CLASS_IN | if q.unicast { CLASS_TOP } else { 0 };
            out.extend_from_slice(&class.to_be_bytes());
        }
        for r in self
            .answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            encode_name(&r.name, &mut out);
            out.extend_from_slice(&r.rtype.to_be_bytes());
            let class = CLASS_IN | if r.cache_flush { CLASS_TOP } else { 0 };
            out.extend_from_slice(&class.to_be_bytes());
            out.extend_from_slice(&r.ttl.to_be_bytes());
            let start = out.len();
            out.extend_from_slice(&[0, 0]);
            match &r.data {
                RData::Ptr(name) => encode_name(name, &mut out),
                RData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } => {
                    out.extend_from_slice(&priority.to_be_bytes());
                    out.extend_from_slice(&weight.to_be_bytes());
                    out.extend_from_slice(&port.to_be_bytes());
                    encode_name(target, &mut out);
                }
                RData::Txt(strings) => {
                    for s in strings {
                        out.push(s.len() as u8);
                        out.extend_from_slice(s);
                    }
                    if strings.is_empty() {
                        out.push(0);
                    }
                }
                RData::Aaaa(addr) => out.extend_from_slice(&addr.octets()),
                RData::Other(data) => out.extend_from_slice(data),
            }
            let len = (out.len() - start - 2) as u16;
            out[start..start + 2].copy_from_slice(&len.to_be_bytes());
        }
        out
    }

    fn records(&self) -> impl Iterator<Item = &Record> {
        self.answers.iter().chain(&self.additional)
    }
}

fn encode_name(name: &Name, out: &mut Vec<u8>) {
    for label in &name.0 {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.bytes.len())
            .ok_or(Error("truncated"))?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A name, following compression pointers. Pointers must point strictly
    /// backwards, so they can't loop, and the name is capped at 255 bytes.
    fn name(&mut self) -> Result<Name, Error> {
        let (name, end) = read_name(self.bytes, self.pos)?;
        self.pos = end;
        Ok(name)
    }

    fn record(&mut self) -> Result<Record, Error> {
        let name = self.name()?;
        let rtype = self.u16()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let len = self.u16()? as usize;
        let start = self.pos;
        let rdata = self.take(len)?;
        let data = match rtype {
            rtype::PTR => {
                let (target, end) = read_name(self.bytes, start)?;
                if end != start + len {
                    return Err(Error("bad PTR length"));
                }
                RData::Ptr(target)
            }
            rtype::SRV => {
                if len < 7 {
                    return Err(Error("short SRV"));
                }
                let (target, end) = read_name(self.bytes, start + 6)?;
                if end != start + len {
                    return Err(Error("bad SRV length"));
                }
                let at = |i| u16::from_be_bytes([rdata[i], rdata[i + 1]]);
                RData::Srv {
                    priority: at(0),
                    weight: at(2),
                    port: at(4),
                    target,
                }
            }
            rtype::TXT => {
                let mut strings = Vec::new();
                let mut rest = rdata;
                while let Some((&n, tail)) = rest.split_first() {
                    let s = tail.get(..n as usize).ok_or(Error("bad TXT string"))?;
                    if n > 0 {
                        strings.push(s.to_vec());
                    }
                    rest = &tail[n as usize..];
                }
                RData::Txt(strings)
            }
            rtype::AAAA => {
                let octets: [u8; 16] = rdata.try_into().map_err(|_| Error("bad AAAA length"))?;
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            _ => RData::Other(rdata.to_vec()),
        };
        Ok(Record {
            name,
            rtype,
            cache_flush: class & CLASS_TOP != 0,
            ttl,
            data,
        })
    }
}

fn read_name(bytes: &[u8], mut pos: usize) -> Result<(Name, usize), Error> {
    let mut labels = Vec::new();
    let mut total = 0;
    let mut end = None;
    // Where the current run of labels started: pointers must go before it.
    let mut floor = pos;
    loop {
        let len = *bytes.get(pos).ok_or(Error("truncated name"))? as usize;
        match len {
            0 => {
                return Ok((Name(labels), end.unwrap_or(pos + 1)));
            }
            1..=63 => {
                let label = bytes
                    .get(pos + 1..pos + 1 + len)
                    .ok_or(Error("truncated label"))?;
                total += len + 1;
                if total > 255 {
                    return Err(Error("name too long"));
                }
                labels.push(
                    String::from_utf8(label.to_vec()).map_err(|_| Error("label is not UTF-8"))?,
                );
                pos += 1 + len;
            }
            0xc0..=0xff => {
                let low = *bytes.get(pos + 1).ok_or(Error("truncated pointer"))? as usize;
                let target = (len & 0x3f) << 8 | low;
                if target >= floor {
                    return Err(Error("forward compression pointer"));
                }
                end.get_or_insert(pos + 2);
                pos = target;
                floor = target;
            }
            _ => return Err(Error("bad label type")),
        }
    }
}

/// 12 lowercase hex digits from 6 random bytes (MDNS-1).
pub fn service_id(random: [u8; 6]) -> String {
    random.iter().map(|b| format!("{b:02x}")).collect()
}

/// A receiver's `_airdrop._tcp` service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The service ID, the instance name (MDNS-1, MDNS-3).
    pub instance: String,
    /// The host label; the SRV target is `<host>.local.`.
    pub host: String,
    pub port: u16,
    /// The interface's link-local address.
    pub addr: Ipv6Addr,
    pub flags: u32,
}

impl Service {
    /// PTR, SRV, TXT and AAAA: what the responder publishes and what goes in
    /// the radio's Service Response TLV (MDNS-2).
    pub fn records(&self) -> Vec<Record> {
        let instance = Name::instance(&self.instance);
        let host = Name::host(&self.host);
        vec![
            Record {
                name: Name::service(),
                rtype: rtype::PTR,
                cache_flush: false,
                ttl: OTHER_TTL,
                data: RData::Ptr(instance.clone()),
            },
            Record {
                name: instance.clone(),
                rtype: rtype::SRV,
                cache_flush: true,
                ttl: HOST_TTL,
                data: RData::Srv {
                    priority: 0,
                    weight: 0,
                    port: self.port,
                    target: host.clone(),
                },
            },
            Record {
                name: instance,
                rtype: rtype::TXT,
                cache_flush: true,
                ttl: OTHER_TTL,
                data: RData::Txt(vec![format!("flags={}", self.flags).into_bytes()]),
            },
            Record {
                name: host,
                rtype: rtype::AAAA,
                cache_flush: true,
                ttl: HOST_TTL,
                data: RData::Aaaa(self.addr),
            },
        ]
    }

    /// An unsolicited response with every record (RFC 6762 §8.3).
    pub fn announcement(&self) -> Vec<u8> {
        Message {
            response: true,
            answers: self.records(),
            ..Message::default()
        }
        .encode()
    }

    /// The same records with TTL 0, withdrawing them (RFC 6762 §10.1).
    pub fn goodbye(&self) -> Vec<u8> {
        let mut answers = self.records();
        for r in &mut answers {
            r.ttl = 0;
        }
        Message {
            response: true,
            answers,
            ..Message::default()
        }
        .encode()
    }

    /// The reply to a query, if it asks about this service. `legacy` is a
    /// query from a port other than 5353, which gets a unicast reply that
    /// echoes its ID and questions (RFC 6762 §6.7).
    pub fn answer(&self, query: &Message, legacy: bool) -> Option<Reply> {
        if query.response {
            return None;
        }
        let records = self.records();
        let [ptr, srv, txt, aaaa] = [0, 1, 2, 3].map(|i| &records[i]);
        let mut answers: Vec<&Record> = Vec::new();
        let mut additional: Vec<&Record> = Vec::new();
        let wants = |q: &Question, t: u16| q.qtype == t || q.qtype == rtype::ANY;
        for q in &query.questions {
            if q.name == ptr.name && wants(q, rtype::PTR) {
                // RFC 6762 §7.1: skip what the asker already knows, with at
                // least half its TTL left.
                let known = query
                    .answers
                    .iter()
                    .any(|k| k.name == ptr.name && k.data == ptr.data && k.ttl >= ptr.ttl / 2);
                if !known {
                    answers.push(ptr);
                    additional.extend([srv, txt, aaaa]);
                }
            }
            if q.name == srv.name {
                if wants(q, rtype::SRV) {
                    answers.push(srv);
                    additional.push(aaaa);
                }
                if wants(q, rtype::TXT) {
                    answers.push(txt);
                }
            }
            if q.name == aaaa.name && wants(q, rtype::AAAA) {
                answers.push(aaaa);
            }
        }
        if answers.is_empty() {
            return None;
        }
        let dedup = |list: Vec<&Record>, exclude: &[Record]| -> Vec<Record> {
            let mut out: Vec<Record> = Vec::new();
            for r in list {
                if !out.contains(r) && !exclude.contains(r) {
                    out.push(r.clone());
                }
            }
            out
        };
        let mut answers = dedup(answers, &[]);
        let mut additional = dedup(additional, &answers);
        let unicast = legacy || query.questions.iter().all(|q| q.unicast);
        if legacy {
            // RFC 6762 §6.7: no cache-flush bits, TTLs of at most 10 s.
            for r in answers.iter_mut().chain(&mut additional) {
                r.cache_flush = false;
                r.ttl = r.ttl.min(10);
            }
        }
        Some(Reply {
            message: Message {
                id: if legacy { query.id } else { 0 },
                response: true,
                questions: if legacy {
                    query.questions.clone()
                } else {
                    Vec::new()
                },
                answers,
                authority: Vec::new(),
                additional,
            }
            .encode(),
            unicast,
        })
    }
}

/// Repeated unsolicited announcements, for a radio that doesn't carry the
/// records in its Service Response TLV (MDNS-7). The radio layer picks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Burst {
    /// Copies per burst.
    pub count: u32,
    /// Between copies.
    pub interval: Duration,
    /// From the end of one burst to the start of the next.
    pub pause: Duration,
}

/// When a responder sends its unsolicited announcement: twice, a second
/// apart (RFC 6762 §8.3), or in a [`Burst`] for as long as it runs.
#[derive(Debug, Clone)]
pub struct Announcer {
    burst: Option<Burst>,
    next: Option<Instant>,
    sent: u32,
}

impl Announcer {
    pub fn new(burst: Option<Burst>, now: Instant) -> Self {
        Announcer {
            // A burst of nothing announces once a pause, not never.
            burst: burst.map(|b| Burst {
                count: b.count.max(1),
                ..b
            }),
            next: Some(now),
            sent: 0,
        }
    }

    /// When [`Announcer::on_timer`] next needs calling, if ever.
    pub fn next_timer(&self) -> Option<Instant> {
        self.next
    }

    /// Whether to send the announcement now.
    pub fn on_timer(&mut self, now: Instant) -> bool {
        match self.next {
            Some(at) if now >= at => {}
            _ => return false,
        }
        self.sent += 1;
        self.next = match self.burst {
            None if self.sent < 2 => Some(now + Duration::from_secs(1)),
            None => None,
            Some(b) if self.sent.is_multiple_of(b.count) => Some(now + b.pause),
            Some(b) => Some(now + b.interval),
        };
        true
    }
}

/// A responder's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub message: Vec<u8>,
    /// Send it back to the asker rather than to the group.
    pub unicast: bool,
}

/// A receiver a browser found: its SRV and AAAA resolved (MDNS-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub instance: String,
    pub host: String,
    pub port: u16,
    pub addr: Ipv6Addr,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowseEvent {
    /// A receiver resolved, or its address, port or flags changed.
    Found(Found),
    /// Its announcement was withdrawn or expired.
    Lost(String),
}

#[derive(Debug, Clone)]
struct Cached<T> {
    value: T,
    expires: Instant,
}

#[derive(Debug, Default)]
struct Instance {
    ptr: Option<Instant>,
    srv: Option<Cached<(Name, u16)>>,
    txt: Option<Cached<u32>>,
    reported: Option<Found>,
}

/// Most instances and hosts tracked, so a flood of announcements can't grow
/// the cache without bound.
const MAX_CACHE: usize = 256;
/// Longest a record is cached, whatever TTL it claims: RFC 6762's TTL for
/// host records. The browser queries at least every `MAX_QUERY_INTERVAL`, so
/// a peer that's still there refreshes its records long before this, and a
/// flood of announcements can't hold the cache for long (SEC-11).
const MAX_TTL: Duration = Duration::from_secs(120);

const FIRST_QUERY: Duration = Duration::from_millis(20);
const MAX_QUERY_INTERVAL: Duration = Duration::from_secs(10);

/// Browses `_airdrop._tcp` (MDNS-6).
#[derive(Debug)]
pub struct Browser {
    instances: BTreeMap<String, Instance>,
    hosts: Vec<(Name, Cached<Ipv6Addr>)>,
    events: VecDeque<BrowseEvent>,
    next_query: Instant,
    interval: Duration,
}

impl Browser {
    pub fn new(now: Instant) -> Self {
        Browser {
            instances: BTreeMap::new(),
            hosts: Vec::new(),
            events: VecDeque::new(),
            next_query: now + FIRST_QUERY,
            interval: Duration::from_secs(1),
        }
    }

    pub fn poll_event(&mut self) -> Option<BrowseEvent> {
        self.events.pop_front()
    }

    /// When [`Browser::on_timer`] next needs calling.
    pub fn next_timer(&self) -> Instant {
        let expiries = self.instances.values().flat_map(|i| {
            [
                i.ptr,
                i.srv.as_ref().map(|c| c.expires),
                i.txt.as_ref().map(|c| c.expires),
            ]
            .into_iter()
            .flatten()
        });
        let hosts = self.hosts.iter().map(|(_, c)| c.expires);
        expiries.chain(hosts).fold(self.next_query, Instant::min)
    }

    /// Expires stale records, and returns a query to multicast if one is due.
    pub fn on_timer(&mut self, now: Instant) -> Option<Vec<u8>> {
        self.expire(now);
        if now < self.next_query {
            return None;
        }
        self.next_query = now + self.interval;
        self.interval = (self.interval * 2).min(MAX_QUERY_INTERVAL);
        Some(self.query())
    }

    fn query(&self) -> Vec<u8> {
        let mut questions = vec![Question {
            name: Name::service(),
            qtype: rtype::PTR,
            unicast: false,
        }];
        for (label, i) in &self.instances {
            if i.srv.is_none() || i.txt.is_none() {
                questions.push(Question {
                    name: Name::instance(label),
                    qtype: rtype::ANY,
                    unicast: false,
                });
            }
            if let Some(srv) = &i.srv
                && !self.hosts.iter().any(|(h, _)| *h == srv.value.0)
            {
                questions.push(Question {
                    name: srv.value.0.clone(),
                    qtype: rtype::AAAA,
                    unicast: false,
                });
            }
        }
        Message {
            questions,
            ..Message::default()
        }
        .encode()
    }

    /// Takes in the records of a received response.
    pub fn handle(&mut self, message: &Message, now: Instant) {
        if !message.response {
            return;
        }
        let expires = |ttl: u32| {
            // RFC 6762 §10.1: a goodbye means gone in one second.
            now + if ttl == 0 {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(ttl as u64).min(MAX_TTL)
            }
        };
        for r in message.records() {
            match &r.data {
                RData::Ptr(target) if r.name == Name::service() => {
                    let Some(label) = target.instance_label() else {
                        continue;
                    };
                    if let Some(i) = self.instance(label) {
                        i.ptr = Some(expires(r.ttl));
                    }
                }
                RData::Srv { port, target, .. } => {
                    let Some(label) = r.name.instance_label() else {
                        continue;
                    };
                    if let Some(i) = self.instance(label) {
                        i.srv = Some(Cached {
                            value: (target.clone(), *port),
                            expires: expires(r.ttl),
                        });
                    }
                }
                RData::Txt(strings) => {
                    let Some(label) = r.name.instance_label() else {
                        continue;
                    };
                    let flags = strings
                        .iter()
                        .find_map(|s| {
                            std::str::from_utf8(s)
                                .ok()?
                                .strip_prefix("flags=")?
                                .parse()
                                .ok()
                        })
                        .unwrap_or(0);
                    if let Some(i) = self.instance(label) {
                        i.txt = Some(Cached {
                            value: flags,
                            expires: expires(r.ttl),
                        });
                    }
                }
                // AirDrop peers are reached on a link-local address (NET-2),
                // so no other address is ever connected to.
                RData::Aaaa(addr) if is_link_local(addr) => {
                    let cached = Cached {
                        value: *addr,
                        expires: expires(r.ttl),
                    };
                    match self.hosts.iter().position(|(h, _)| *h == r.name) {
                        Some(i) => self.hosts[i].1 = cached,
                        None if self.hosts.len() < MAX_CACHE => {
                            self.hosts.push((r.name.clone(), cached))
                        }
                        None => {}
                    }
                }
                _ => {}
            }
        }
        self.expire(now);
    }

    /// The cache entry for an instance, if there's room for it.
    fn instance(&mut self, label: &str) -> Option<&mut Instance> {
        if !self.instances.contains_key(label) && self.instances.len() >= MAX_CACHE {
            return None;
        }
        Some(self.instances.entry(label.to_string()).or_default())
    }

    fn expire(&mut self, now: Instant) {
        self.hosts.retain(|(_, c)| c.expires > now);
        let hosts = &self.hosts;
        let events = &mut self.events;
        self.instances.retain(|label, i| {
            if i.srv.as_ref().is_some_and(|c| c.expires <= now) {
                i.srv = None;
            }
            if i.txt.as_ref().is_some_and(|c| c.expires <= now) {
                i.txt = None;
            }
            let alive = i.ptr.is_some_and(|t| t > now);
            let resolved = alive
                .then(|| {
                    let srv = i.srv.as_ref()?;
                    let (target, port) = &srv.value;
                    let (_, addr) = hosts.iter().find(|(h, _)| h == target)?;
                    Some(Found {
                        instance: label.clone(),
                        host: target.0.first().cloned().unwrap_or_default(),
                        port: *port,
                        addr: addr.value,
                        flags: i.txt.as_ref().map_or(0, |c| c.value),
                    })
                })
                .flatten();
            match (&resolved, &i.reported) {
                (Some(found), reported) if reported.as_ref() != Some(found) => {
                    events.push_back(BrowseEvent::Found(found.clone()));
                    i.reported = resolved;
                }
                (None, Some(_)) if !alive => {
                    events.push_back(BrowseEvent::Lost(label.clone()));
                    i.reported = None;
                }
                _ => {}
            }
            alive || i.srv.is_some() || i.txt.is_some()
        });
    }
}

fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bursts owly-radio asks for: sharing the AP's channel, and fixed
    /// to one.
    const SHARED: Burst = Burst {
        count: 3,
        interval: Duration::from_millis(50),
        pause: Duration::from_secs(3),
    };
    const FIXED: Burst = Burst {
        count: 64,
        interval: Duration::from_micros(16_400),
        pause: Duration::from_secs(3),
    };

    /// When an announcer sends, over `limit`, stepping to each timer.
    fn announcements(burst: Option<Burst>, limit: Duration) -> Vec<Duration> {
        let start = Instant::now();
        let mut a = Announcer::new(burst, start);
        let mut sent = Vec::new();
        while let Some(at) = a.next_timer() {
            if at - start > limit {
                break;
            }
            assert!(a.on_timer(at));
            assert!(!a.on_timer(at), "one announcement per timer");
            sent.push(at - start);
        }
        sent
    }

    #[test]
    fn announces_twice_without_a_burst() {
        let sent = announcements(None, Duration::from_secs(60));
        assert_eq!(sent, [Duration::ZERO, Duration::from_secs(1)]);
    }

    // spec: MDNS-7
    #[test]
    fn bursts_repeat_for_the_whole_session() {
        let ms = Duration::from_millis;
        let sent = announcements(Some(SHARED), Duration::from_secs(7));
        assert_eq!(
            sent,
            [0, 50, 100, 3100, 3150, 3200, 6200, 6250, 6300].map(ms)
        );
        let sent = announcements(Some(FIXED), Duration::from_secs(60));
        let bursts = sent.windows(2).filter(|w| w[1] - w[0] >= ms(3000)).count() + 1;
        assert_eq!(sent.len(), 64 * bursts);
        // Each burst takes 63 intervals, about 1 s, before its pause.
        assert_eq!(bursts, 15);
        assert_eq!(sent[1] - sent[0], Duration::from_micros(16_400));
    }

    #[test]
    fn an_empty_burst_still_announces() {
        let burst = Burst { count: 0, ..SHARED };
        assert_eq!(announcements(Some(burst), Duration::from_secs(4)).len(), 2);
    }

    fn service() -> Service {
        Service {
            instance: "3fa9c01b22de".into(),
            host: "owly-3fa9c01b22de".into(),
            port: 8770,
            addr: "fe80::1".parse().unwrap(),
            flags: RECEIVER_FLAGS,
        }
    }

    #[test]
    fn messages_round_trip() {
        let message = Message::decode(&service().announcement()).unwrap();
        assert_eq!(message.answers, service().records());
        assert_eq!(Message::decode(&message.encode()).unwrap(), message);
    }

    #[test]
    fn decodes_compressed_names() {
        // A PTR answer whose target points back at the question's name.
        let mut m = vec![0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        encode_name(&Name::service(), &mut m);
        m.extend_from_slice(&[0, 12, 0, 1]);
        m.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 10, 0, 7]);
        m.extend_from_slice(&[4, b'i', b'n', b's', b't', 0xc0, 12]);
        let message = Message::decode(&m).unwrap();
        assert_eq!(message.answers[0].name, Name::service());
        assert_eq!(message.answers[0].data, RData::Ptr(Name::instance("inst")));
    }

    #[test]
    fn rejects_pointer_loops_and_truncation() {
        let mut m = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1]);
        assert_eq!(
            Message::decode(&m),
            Err(Error("forward compression pointer"))
        );
        let good = service().announcement();
        for len in 0..good.len() {
            assert!(Message::decode(&good[..len]).is_err());
        }
    }

    // spec: MDNS-1, MDNS-5
    #[test]
    fn publishes_the_airdrop_records() {
        let records = service().records();
        assert_eq!(records[0].name.to_string(), "_airdrop._tcp.local.");
        assert_eq!(records[0].data, RData::Ptr(Name::instance("3fa9c01b22de")));
        assert!(
            matches!(&records[1].data, RData::Srv { port: 8770, target, .. } if target.to_string() == "owly-3fa9c01b22de.local.")
        );
        assert_eq!(records[2].data, RData::Txt(vec![b"flags=137".to_vec()]));
        assert_eq!(records[3].data, RData::Aaaa("fe80::1".parse().unwrap()));
        assert_ne!(
            RECEIVER_FLAGS & (SUPPORTS_PIPELINING | SUPPORTS_MIXED_TYPES),
            0
        );
        assert_eq!(RECEIVER_FLAGS & SUPPORTS_DVZIP, 0);
        assert_ne!(RECEIVER_FLAGS & SUPPORTS_URL, 0);
    }

    #[test]
    fn goodbye_withdraws_every_record() {
        let bye = Message::decode(&service().goodbye()).unwrap();
        assert!(bye.response);
        assert_eq!(bye.answers.len(), 4);
        assert!(
            bye.answers.iter().all(|r| r.ttl == 0),
            "RFC 6762 10.1: a goodbye carries TTL 0"
        );
    }

    #[test]
    fn answers_queries() {
        let query = |name: Name, qtype| Message {
            questions: vec![Question {
                name,
                qtype,
                unicast: false,
            }],
            ..Message::default()
        };
        let s = service();
        let reply = s
            .answer(&query(Name::service(), rtype::PTR), false)
            .unwrap();
        let m = Message::decode(&reply.message).unwrap();
        assert_eq!(m.answers.len(), 1);
        assert_eq!(m.additional.len(), 3);
        assert!(!reply.unicast);
        assert!(
            s.answer(
                &query(Name::new(&["_other", "_tcp", "local"]), rtype::PTR),
                false
            )
            .is_none()
        );
        let legacy = s
            .answer(&query(Name::host(&s.host), rtype::AAAA), true)
            .unwrap();
        let m = Message::decode(&legacy.message).unwrap();
        assert!(legacy.unicast && m.questions.len() == 1 && m.answers[0].ttl == 10);
    }

    // spec: MDNS-6
    #[test]
    fn browser_reports_only_resolved_instances() {
        let start = Instant::now();
        let mut b = Browser::new(start);
        let s = service();
        let records = s.records();
        let response = |answers: Vec<Record>| Message {
            response: true,
            answers,
            ..Message::default()
        };
        // PTR and SRV alone aren't enough.
        b.handle(&response(records[..3].to_vec()), start);
        assert_eq!(b.poll_event(), None);
        let q = Message::decode(&b.on_timer(start + Duration::from_secs(1)).unwrap()).unwrap();
        assert!(q.questions.iter().any(|q| q.qtype == rtype::AAAA));
        b.handle(&response(records[3..].to_vec()), start);
        assert_eq!(
            b.poll_event(),
            Some(BrowseEvent::Found(Found {
                instance: s.instance.clone(),
                host: s.host.clone(),
                port: 8770,
                addr: s.addr,
                flags: RECEIVER_FLAGS,
            }))
        );
        // A goodbye removes it a second later.
        let bye = Message::decode(&s.goodbye()).unwrap();
        b.handle(&bye, start);
        assert_eq!(b.poll_event(), None);
        b.on_timer(start + Duration::from_secs(2));
        assert_eq!(b.poll_event(), Some(BrowseEvent::Lost(s.instance)));
    }

    // spec: NET-2, SEC-11
    #[test]
    fn browser_caps_ttls_and_ignores_routable_addresses() {
        let start = Instant::now();
        let mut b = Browser::new(start);
        let s = service();
        let mut records = s.records();
        for r in &mut records {
            r.ttl = u32::MAX;
            if let RData::Aaaa(addr) = &mut r.data {
                *addr = "2001:db8::1".parse().unwrap();
            }
        }
        let response = Message {
            response: true,
            answers: records.clone(),
            ..Message::default()
        };
        b.handle(&response, start);
        assert_eq!(b.poll_event(), None);

        for r in &mut records {
            if let RData::Aaaa(addr) = &mut r.data {
                *addr = s.addr;
            }
        }
        b.handle(
            &Message {
                response: true,
                answers: records,
                ..Message::default()
            },
            start,
        );
        assert!(matches!(b.poll_event(), Some(BrowseEvent::Found(f)) if f.addr == s.addr));
        b.on_timer(start + MAX_TTL + Duration::from_secs(1));
        assert_eq!(b.poll_event(), Some(BrowseEvent::Lost(s.instance)));
    }
}
