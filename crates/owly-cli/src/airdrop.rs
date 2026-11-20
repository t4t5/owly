//! AirDrop on its own, without omdrop: `owly receive`, `owly send` and
//! `owly browse`, owly-airdrop's receiver and sender on one interface.
//!
//! The interface is any one with an IPv6 link-local address: the `awdl0`
//! of an owlyd lease (`owly radio up`) with an iPhone, or the veth harness
//! between two of these. On the `awdl0` of an owlyd lease, the receiver
//! announces in the bursts the radio asks for (MDNS-7), and the sender
//! tries the radio's AWDL peers beside mDNS (DISC-5), both as owlyd's D-Bus
//! API says.

use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use owly_airdrop::driver::mdns::Mdns;
use owly_airdrop::driver::receiver::{Options, Receiver, ReceiverEvent};
use owly_airdrop::driver::sender::{Event, Payload, Sender};
use owly_airdrop::driver::tls::Identity;
use owly_airdrop::proto::ble::Advert;
use owly_airdrop::proto::mdns::{self, BrowseEvent, RECEIVER_FLAGS, SUPPORTS_DVZIP, Service};
use owly_airdrop::proto::messages::Offer;
use owly_airdrop::proto::receiver::Config;
use owly_airdrop::proto::sender::{self, Outcome};
use owly_awdl::MacAddr;
use owly_radio::radio::Announce;
use owlyd::api::{self, LinkInfo, RadioProxy};
use tokio::io::AsyncBufReadExt;

use crate::bluez::BluezAdvertiser;
use crate::hci::HciAdvertiser;

/// Apple's receivers listen here (MDNS-1), and an AWDL peer with no mDNS
/// is tried here (DISC-5).
const AIRDROP_PORT: u16 = 8770;

/// Where we receive: the port omdrop's firewall rule opens on `awdl0`
/// (docs/implementation.md, NET-4). A host firewall that blocks the
/// port is the first reason a phone never lists us.
const RECEIVE_PORT: u16 = 8771;

/// Where and as whom: the flags every AirDrop command takes.
#[derive(clap::Args)]
pub struct On {
    /// The interface to use, such as awdl0.
    #[arg(long, short, default_value = "awdl0")]
    iface: String,
    /// The name others see (default: the host name).
    #[arg(long)]
    name: Option<String>,
}

#[derive(clap::Args)]
pub struct ReceiveArgs {
    #[command(flatten)]
    on: On,
    /// Where received files go.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    /// The firewall has to let it in on the interface (NET-4).
    #[arg(long, default_value_t = RECEIVE_PORT)]
    port: u16,
    /// Accept every request without asking (ASK-3).
    #[arg(long)]
    accept: bool,
    /// Don't announce over mDNS, for when another responder does.
    #[arg(long)]
    no_mdns: bool,
    /// The TXT flags to announce (MDNS-4), decimal or 0x-prefixed hex,
    /// to compare what Apple senders do with each (MDNS-5).
    #[arg(long, default_value = "0x089", value_parser = parse_flags)]
    flags: u32,
}

#[derive(clap::Args)]
pub struct BrowseArgs {
    #[command(flatten)]
    on: On,
    /// How long to browse.
    #[arg(long, default_value_t = 10)]
    seconds: u64,
    /// Don't send the BLE advert that wakes Apple receivers (BLE-1).
    #[arg(long)]
    no_ble: bool,
}

#[derive(clap::Args)]
pub struct SendArgs {
    #[command(flatten)]
    on: On,
    /// The receiver: its name, service ID or AWDL address. The first one
    /// found if left out. A straight and a curly apostrophe in a name match
    /// alike.
    #[arg(long)]
    to: Option<String>,
    /// Skip mDNS: try the receiver at this AWDL address on port 8770
    /// (DISC-5).
    #[arg(long, conflicts_with = "to")]
    mac: Option<String>,
    /// Send a link instead of files.
    #[arg(long)]
    url: Vec<String>,
    /// How long to look for the receiver.
    #[arg(long, default_value_t = 30)]
    seconds: u64,
    /// Don't send the BLE advert that wakes Apple receivers (BLE-1).
    #[arg(long)]
    no_ble: bool,
    files: Vec<PathBuf>,
}

impl On {
    fn resolve(&self) -> io::Result<(Interface, String)> {
        // rustls needs a crypto provider chosen; ring is owly-cli's.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let iface = Interface::lookup(&self.iface)?;
        let name = match &self.name {
            Some(name) => name.clone(),
            None => nix::unistd::gethostname()?.to_string_lossy().into_owned(),
        };
        Ok((iface, name))
    }
}

/// `owly receive`.
pub async fn receive(bus: Option<&str>, args: ReceiveArgs) -> Result<ExitCode, String> {
    let (iface, name) = args.on.resolve().map_err(|e| e.to_string())?;
    let announce = match Lease::find(bus, &iface.name).await {
        Ok(lease) => lease.link.announce,
        Err(e) => {
            eprintln!("not announcing as the radio asks: {e}");
            None
        }
    };
    run_receiver(&iface, name, burst(announce), args)
        .await
        .map_err(|e| e.to_string())
}

/// `owly browse`: by mDNS and, on an owlyd lease, by `/Discover` at the
/// radio's AWDL peers (DISC-5), as `owly send` finds them.
pub async fn browse(bus: Option<&str>, args: BrowseArgs) -> Result<ExitCode, String> {
    async {
        let (iface, name) = args.on.resolve()?;
        let _advert = advertise(args.no_ble).await;
        let sender = Sender::new(sender::Config::new(name, random_service_id()?))?;
        let limit = Duration::from_secs(args.seconds);
        let deadline = tokio::time::Instant::now() + limit;
        let lease = Lease::find(bus, &iface.name)
            .await
            .inspect_err(|e| eprintln!("not trying the radio's AWDL peers: {e}"))
            .ok();
        let seen = std::cell::RefCell::new(std::collections::HashSet::new());
        let show = |r: &Listed| {
            if seen.borrow_mut().insert(r.addr) {
                println!("{:<14} {:?} ({})", r.instance, r.name, r.addr);
            }
        };
        let by_peers = async {
            if let Some(lease) = &lease {
                discover_peers(&iface, &sender, lease, deadline, |r| {
                    show(&r);
                    false
                })
                .await;
            }
        };
        let (by_mdns, ()) = tokio::join!(
            browse_receivers(&iface, &sender, limit, |r| {
                show(r);
                false
            }),
            by_peers
        );
        // Without a lease, mDNS was the only way to find anyone.
        match by_mdns {
            Err(e) if lease.is_none() => return Err(e),
            Err(e) => eprintln!("not browsing mDNS: {e}"),
            Ok(()) => {}
        }
        Ok(ExitCode::SUCCESS)
    }
    .await
    .map_err(|e: io::Error| e.to_string())
}

/// `owly send`.
pub async fn send(bus: Option<&str>, args: SendArgs) -> Result<ExitCode, String> {
    send_inner(bus, args).await.map_err(|e| e.to_string())
}

async fn send_inner(bus: Option<&str>, args: SendArgs) -> io::Result<ExitCode> {
    let SendArgs {
        on,
        to,
        mac,
        url,
        seconds,
        no_ble,
        files,
    } = args;
    let (iface, name) = on.resolve()?;
    let payload = match (url.is_empty(), files.is_empty()) {
        (false, true) => Payload::Urls(url),
        (true, false) => Payload::Files(
            files
                .iter()
                .map(std::path::absolute)
                .collect::<Result<_, _>>()?,
        ),
        _ => return Err(io::Error::other("give either files or --url, not both")),
    };
    let _advert = advertise(no_ble).await;
    let sender = Sender::new(sender::Config::new(name, random_service_id()?))?;
    let target = match mac {
        Some(mac) => {
            let addr =
                SocketAddrV6::new(parse_mac(&mac)?.link_local(), AIRDROP_PORT, 0, iface.index);
            let receiver = knock(&sender, addr, Duration::from_secs(seconds))
                .await?
                .ok_or_else(|| io::Error::other("the receiver at that address doesn't list us"))?;
            Listed {
                instance: mac,
                name: receiver.computer_name,
                addr,
                // UP-1b: no TXT to say, and Apple receivers take DVZip.
                flags: RECEIVER_FLAGS | SUPPORTS_DVZIP,
            }
        }
        None => {
            let lease = Lease::find(bus, &iface.name)
                .await
                .inspect_err(|e| eprintln!("not trying the radio's AWDL peers: {e}"))
                .ok();
            match &to {
                Some(to) => eprintln!("looking for {to:?} for {seconds} s..."),
                None => eprintln!("looking for a receiver for {seconds} s..."),
            }
            find_receiver(
                &iface,
                &sender,
                lease.as_ref(),
                to.as_deref(),
                Duration::from_secs(seconds),
            )
            .await?
        }
    };
    eprintln!("sending to {:?} at {}", target.name, target.addr);
    let (events, mut updates) = tokio::sync::mpsc::unbounded_channel();
    let printer = tokio::spawn(async move {
        while let Some(event) = updates.recv().await {
            match event {
                Event::Accepted => eprintln!("accepted"),
                Event::Progress(p) => eprint!("\r{} / {} bytes", p.sent, p.total),
            }
        }
        eprintln!();
    });
    let outcome = sender
        .send(target.addr, &payload, target.flags, Some(events))
        .await?;
    let _ = printer.await;
    Ok(match outcome {
        Outcome::Delivered => {
            println!("delivered");
            ExitCode::SUCCESS
        }
        Outcome::Declined => {
            println!("declined");
            ExitCode::from(1)
        }
        Outcome::Failed(reason) => {
            println!("failed: {reason}");
            ExitCode::from(2)
        }
    })
}

struct Interface {
    name: String,
    index: u32,
    addr: Ipv6Addr,
}

impl Interface {
    /// The interface's index and IPv6 link-local address (NET-1, NET-2).
    fn lookup(name: &str) -> io::Result<Self> {
        let index = nix::net::if_::if_nametoindex(name)
            .map_err(|e| io::Error::other(format!("{name}: {e}")))?;
        let addr = nix::ifaddrs::getifaddrs()?
            .filter(|a| a.interface_name == name)
            .filter_map(|a| a.address?.as_sockaddr_in6().map(|s| s.ip()))
            .find(|ip| ip.segments()[0] & 0xffc0 == 0xfe80)
            .ok_or_else(|| io::Error::other(format!("{name} has no IPv6 link-local address")))?;
        Ok(Interface {
            name: name.into(),
            index,
            addr,
        })
    }
}

/// owlyd's lease on the interface we're on, when there's one.
struct Lease {
    radio: RadioProxy<'static>,
    link: LinkInfo,
}

impl Lease {
    /// Why there's none when owlyd can't be reached, holds no lease, or
    /// leases another interface: on a link no Owly radio set up, such as
    /// the veth harness, or from an owlyd older than this owly.
    async fn find(bus: Option<&str>, iface: &str) -> Result<Lease, String> {
        let conn = api::connect(bus)
            .await
            .map_err(|e| format!("owlyd can't be reached ({e})"))?;
        let radio = api::radio(&conn).await.map_err(|e| e.to_string())?;
        let link = radio.link().await.map_err(|e| {
            format!("owlyd doesn't say which link is up ({e}); is it older than this owly?")
        })?;
        let link = LinkInfo::from_dict(&link).ok_or("the radio isn't up")?;
        if link.interface != iface {
            return Err(format!(
                "the radio is up on {}, not {iface}",
                link.interface
            ));
        }
        Ok(Lease { radio, link })
    }

    /// The AWDL peers the radio hears now.
    async fn peers(&self) -> Vec<MacAddr> {
        let peers = self.radio.peers().await.unwrap_or_default();
        peers
            .iter()
            .filter_map(|p| p.get("mac")?.downcast_ref::<String>().ok()?.parse().ok())
            .collect()
    }
}

/// The burst the radio asks receivers to announce in (MDNS-7).
fn burst(announce: Option<Announce>) -> Option<mdns::Burst> {
    let a = announce?;
    eprintln!(
        "announcing {} times {} ms apart, every {} s, as the radio asks",
        a.count,
        a.interval.as_millis(),
        a.pause.as_secs()
    );
    Some(mdns::Burst {
        count: a.count,
        interval: a.interval,
        pause: a.pause,
    })
}

fn parse_flags(text: &str) -> Result<u32, String> {
    match text.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => text.parse(),
    }
    .map_err(|e| format!("{text}: {e}"))
}

fn random_service_id() -> io::Result<String> {
    let mut bytes = [0; 6];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(mdns::service_id(bytes))
}

/// BLE-5: a fresh tag per advert.
fn random_tag() -> io::Result<[u8; 3]> {
    let mut tag = [0; 3];
    getrandom::fill(&mut tag).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(tag)
}

fn parse_mac(text: &str) -> io::Result<MacAddr> {
    text.parse()
        .map_err(|_| io::Error::other(format!("bad MAC address {text}")))
}

/// Keeps the advert going until dropped, whichever backend sent it.
type Advertising = Box<dyn Send>;

/// BLE-1: the advert that makes Apple receivers turn on AirDrop. Without
/// Bluetooth, sending still works to receivers that are already listening.
/// BlueZ is tried first, then a raw HCI socket for machines without it.
async fn advertise(skip: bool) -> Option<Advertising> {
    if skip {
        return None;
    }
    let tag = match random_tag() {
        Ok(tag) => tag,
        Err(e) => {
            eprintln!("not advertising over Bluetooth: {e}");
            return None;
        }
    };
    let bluez = async {
        BluezAdvertiser::new()
            .await?
            .advertise(Advert::anonymous(tag))
            .await
    }
    .await;
    let bluez_error = match bluez {
        Ok(guard) => return Some(Box::new(guard)),
        Err(e) => e,
    };
    let hci = async {
        HciAdvertiser::new()
            .await?
            .advertise(Advert::anonymous(tag))
            .await
    }
    .await;
    match hci {
        Ok(guard) => Some(Box::new(guard)),
        Err(e) => {
            eprintln!("not advertising over Bluetooth: {bluez_error}; over raw HCI: {e}");
            None
        }
    }
}

/// `/Discover` at one address until it answers or `limit` runs out. An
/// iPhone opens its port only once our BLE advert has woken it: in legacy's
/// run that worked, 14.8 s after the advert started. Until then it refuses
/// the connection, or doesn't answer at all.
async fn knock(
    sender: &Sender,
    addr: SocketAddrV6,
    limit: Duration,
) -> io::Result<Option<sender::Receiver>> {
    let deadline = tokio::time::Instant::now() + limit;
    let mut said = false;
    loop {
        let attempt = tokio::time::timeout_at(deadline, sender.discover(addr)).await;
        match attempt {
            Ok(Ok(answer)) => return Ok(answer),
            Ok(Err(e)) if tokio::time::Instant::now() < deadline => {
                if !said {
                    eprintln!("waiting for the receiver to open its port ({e})");
                    said = true;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("the receiver didn't open its port within {limit:?}"),
                ));
            }
        }
    }
}

/// The receiver `to` names, or the first found, by mDNS and, on an owlyd
/// lease, by `/Discover` at the radio's AWDL peers (DISC-5): an iPhone's
/// mDNS doesn't reach `awdl0`, and a peer can turn up at any time before
/// the deadline. Whichever finds it first wins.
async fn find_receiver(
    iface: &Interface,
    sender: &Sender,
    lease: Option<&Lease>,
    to: Option<&str>,
    limit: Duration,
) -> io::Result<Listed> {
    let deadline = tokio::time::Instant::now() + limit;
    let by_mdns = async {
        let mut chosen = None;
        let mut others = BTreeSet::new();
        browse_receivers(iface, sender, limit, |r| {
            let wanted = to.is_none_or(|t| same_name(t, &r.name) || t == r.instance);
            if wanted {
                chosen = Some(r.clone());
            } else {
                say_other(&mut others, to, &r.name);
            }
            wanted
        })
        .await?;
        chosen.ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "no such receiver found"))
    };
    let Some(lease) = lease else {
        return by_mdns.await;
    };
    let by_peers = knock_peers(iface, sender, lease, to, deadline);
    tokio::pin!(by_mdns, by_peers);
    let (mut mdns_done, mut peers_failed) = (false, None);
    loop {
        tokio::select! {
            r = &mut by_mdns, if !mdns_done => match r {
                Ok(found) => return Ok(found),
                Err(e) => {
                    if e.kind() != io::ErrorKind::TimedOut {
                        eprintln!("not browsing mDNS: {e}");
                    }
                    mdns_done = true;
                }
            },
            r = &mut by_peers, if peers_failed.is_none() => match r {
                Ok(found) => return Ok(found),
                Err(e) => peers_failed = Some(e),
            },
        }
        // Both gave up: the AWDL peers' error says more about why a phone
        // wasn't found.
        if mdns_done && let Some(e) = peers_failed {
            return Err(e);
        }
    }
}

/// `/Discover` at each AWDL peer in turn (DISC-5) until one that `to` names
/// answers, or the deadline. The list is read again each round: peers come
/// and go, and an iPhone changes its AWDL address.
async fn knock_peers(
    iface: &Interface,
    sender: &Sender,
    lease: &Lease,
    to: Option<&str>,
    deadline: tokio::time::Instant,
) -> io::Result<Listed> {
    let mut found = None;
    let mut others = BTreeSet::new();
    discover_peers(iface, sender, lease, deadline, |r| {
        if to.is_none_or(|t| same_name(t, &r.name) || t == r.instance) {
            found = Some(r);
            return true;
        }
        say_other(&mut others, to, &r.name);
        false
    })
    .await;
    found.ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, no_peer(to, &others)))
}

/// `/Discover` at each of the lease's AWDL peers until `deadline`, handing
/// each one that answers to `on_listed` once, until it says to stop.
async fn discover_peers(
    iface: &Interface,
    sender: &Sender,
    lease: &Lease,
    deadline: tokio::time::Instant,
    mut on_listed: impl FnMut(Listed) -> bool,
) {
    let mut tried = std::collections::HashSet::new();
    let mut answered = std::collections::HashSet::new();
    while tokio::time::Instant::now() < deadline {
        for mac in lease.peers().await {
            if answered.contains(&mac) {
                continue;
            }
            if tried.insert(mac) {
                eprintln!("trying AWDL peer {mac}");
            }
            let addr = SocketAddrV6::new(mac.link_local(), AIRDROP_PORT, 0, iface.index);
            // A peer that refuses fails at once; one that's silent mustn't
            // hold up the others for long.
            let wait = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(Duration::from_secs(3));
            let Ok(Ok(Some(receiver))) = tokio::time::timeout(wait, sender.discover(addr)).await
            else {
                continue;
            };
            answered.insert(mac);
            let listed = Listed {
                instance: mac.to_string(),
                name: receiver.computer_name,
                addr,
                // UP-1b: no TXT to say, and Apple receivers take DVZip.
                flags: RECEIVER_FLAGS | SUPPORTS_DVZIP,
            };
            if on_listed(listed) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Whether `to` is this name, with a straight and a curly apostrophe alike:
/// an iPhone's name can have either, and whoever types it may use the other.
fn same_name(to: &str, name: &str) -> bool {
    let plain = |c| if matches!(c, '‘' | '’') { '\'' } else { c };
    to.chars().map(plain).eq(name.chars().map(plain))
}

/// Says, once for each name, that a receiver answered as someone other than
/// `to`. A name that's nearly right looks the same as a phone that's asleep.
fn say_other(others: &mut BTreeSet<String>, to: Option<&str>, name: &str) {
    if let Some(to) = to
        && others.insert(name.to_string())
    {
        eprintln!("{name:?} answered, not {to:?}");
    }
}

/// Why no AWDL peer was chosen, given the names that answered as `others`.
fn no_peer(to: Option<&str>, others: &BTreeSet<String>) -> String {
    match to {
        Some(to) if !others.is_empty() => {
            let names: Vec<String> = others.iter().map(|n| format!("{n:?}")).collect();
            format!("no AWDL peer answered as {to:?}; {} did", names.join(", "))
        }
        _ => "no AWDL peer answered /Discover; is the receiver unlocked, with AirDrop on?".into(),
    }
}

#[derive(Debug, Clone)]
struct Listed {
    instance: String,
    name: String,
    addr: SocketAddrV6,
    flags: u32,
}

/// BROWSING and DISCOVERING (§8.1): each resolved instance gets a
/// `/Discover`, and is listed only if it answers with a name (DISC-1).
/// Stops early when `on_listed` returns true.
async fn browse_receivers(
    iface: &Interface,
    sender: &Sender,
    limit: Duration,
    mut on_listed: impl FnMut(&Listed) -> bool,
) -> io::Result<()> {
    let mut browse = Mdns::new(iface.index).browse().await?;
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let event = tokio::select! {
            event = browse.events.recv() => event,
            () = tokio::time::sleep_until(deadline) => return Ok(()),
        };
        let Some(BrowseEvent::Found(found)) = event else {
            continue;
        };
        let addr = SocketAddrV6::new(found.addr, found.port, 0, iface.index);
        match sender.discover(addr).await {
            Ok(Some(receiver)) => {
                let listed = Listed {
                    instance: found.instance,
                    name: receiver.computer_name,
                    addr,
                    flags: found.flags,
                };
                if on_listed(&listed) {
                    return Ok(());
                }
            }
            Ok(None) => eprintln!("{} doesn't list us", found.instance),
            Err(e) => eprintln!("{}: /Discover failed: {e}", found.instance),
        }
    }
}

async fn run_receiver(
    iface: &Interface,
    name: String,
    burst: Option<mdns::Burst>,
    args: ReceiveArgs,
) -> io::Result<ExitCode> {
    let ReceiveArgs {
        dir,
        port,
        accept,
        no_mdns,
        flags,
        ..
    } = args;
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .ok_or_else(|| io::Error::other("no XDG_STATE_HOME or HOME"))?
        .join("owly");
    let identity = Identity::load_or_generate(&state)?;
    let mut config = Config::new(name.clone());
    config.model_name = "Linux".into();
    let addr = SocketAddrV6::new(iface.addr, port, 0, iface.index);
    let (receiver, mut events) = Receiver::bind(addr, &identity, Options::new(config, dir)).await?;
    tokio::spawn(receiver.run());

    let service_id = random_service_id()?;
    let _registration = if no_mdns {
        None
    } else {
        let service = Service {
            instance: service_id.clone(),
            host: format!("owly-{service_id}"),
            port,
            addr: iface.addr,
            flags,
        };
        Some(
            Mdns::new(iface.index)
                .with_burst(burst)
                .register(service)
                .await?,
        )
    };
    eprintln!(
        "receiving as {name:?} ({service_id}) on [{}]:{port}, flags {flags:#x}",
        iface.addr
    );

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        let event = tokio::select! {
            event = events.recv() => event,
            _ = tokio::signal::ctrl_c() => return Ok(ExitCode::SUCCESS),
        };
        let Some(event) = event else {
            return Ok(ExitCode::SUCCESS);
        };
        match event {
            ReceiverEvent::Discovered { peer, .. } => eprintln!("seen by {peer}"),
            ReceiverEvent::Request(request) => {
                // SEC-4: everything here is the sender's; {:?} escapes it.
                eprintln!(
                    "{:?} ({:?}) wants to send:",
                    request.ask.sender_computer_name, request.ask.sender_model_name
                );
                match &request.ask.offer {
                    Offer::Files(files) => {
                        for f in files {
                            eprintln!(
                                "  {:?} {} {}",
                                f.name,
                                f.file_type,
                                f.size.map(|s| format!("{s} bytes")).unwrap_or_default()
                            );
                        }
                    }
                    Offer::Urls(urls) => {
                        for u in urls {
                            eprintln!("  {u:?}");
                        }
                    }
                }
                if accept {
                    request.accept();
                    continue;
                }
                eprint!("accept? [y/N] ");
                // ASK-2: the receiver declines by itself after 15 s.
                let answer = tokio::time::timeout(Duration::from_secs(15), stdin.next_line()).await;
                match answer {
                    Ok(Ok(Some(line))) if line.trim().eq_ignore_ascii_case("y") => request.accept(),
                    Ok(_) => request.decline(),
                    Err(_) => eprintln!("\ntimed out"),
                }
            }
            ReceiverEvent::Withdrawn { .. } => eprintln!("the request was withdrawn"),
            // SEC-4: shown, never opened.
            ReceiverEvent::Urls { urls, .. } => {
                for u in urls {
                    println!("{u:?}");
                }
            }
            ReceiverEvent::Received { paths, .. } => {
                for p in paths {
                    println!("{}", p.display());
                }
            }
            ReceiverEvent::Failed { reason, .. } => eprintln!("transfer failed: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn straight_and_curly_apostrophes_name_the_same_receiver() {
        assert!(same_name("Jane's iPhone", "Jane's iPhone"));
        assert!(same_name("Jane's iPhone", "Jane’s iPhone"));
        assert!(same_name("Jane’s iPhone", "Jane's iPhone"));
        assert!(same_name("Jane‘s iPhone", "Jane’s iPhone"));
        assert!(!same_name("Jane's iPhone", "Janes iPhone"));
        assert!(!same_name("Jane's iPhone", "Jane's iPad"));
    }

    #[test]
    fn the_error_says_who_answered() {
        let silent = "no AWDL peer answered /Discover; is the receiver unlocked, with AirDrop on?";
        assert_eq!(no_peer(None, &BTreeSet::new()), silent);
        assert_eq!(no_peer(Some("Jane"), &BTreeSet::new()), silent);
        let others = BTreeSet::from(["Sam's Mac".to_string(), "Jane's iPhone".to_string()]);
        assert_eq!(
            no_peer(Some("Jane"), &others),
            r#"no AWDL peer answered as "Jane"; "Jane's iPhone", "Sam's Mac" did"#
        );
    }
}
