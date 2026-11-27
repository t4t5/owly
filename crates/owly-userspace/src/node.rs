//! Integrated 7-layer userspace AWDL + `smoltcp` IPv6 + AirDrop node.

use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use owly_airdrop::driver::tls::Identity;
use owly_airdrop::proto::archive::compress::Compressor;
use owly_airdrop::proto::mdns::{
    Announcer, BrowseEvent, Browser, Burst, Found, MDNS_GROUP, MDNS_PORT, Message, SUPPORTS_DVZIP,
    SUPPORTS_MIXED_TYPES, SUPPORTS_PIPELINING, Service,
};
use owly_airdrop::proto::messages::{AskRequest, DiscoverRequest, Offer};
use owly_airdrop::proto::receiver::{
    Answer, Config as ReceiverConfig, Connection as ReceiverConnection, Event as ReceiverProtoEvent,
};
use owly_airdrop::proto::sender::{
    Action as SenderAction, Config as SenderConfig, Outcome, Receiver as DiscoveredPeer,
    ResponseReader, Transfer, discover_request, parse_discover_response,
};
use owly_awdl::channel::Channel;
use owly_awdl::{
    Action as AwdlAction, Config as AwdlConfig, Frame, Input, MacAddr, Node, Presence,
    RadioConstraints, Time,
};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};

use crate::air::SimAirHub;
use crate::archive::build_in_memory_upload;
use crate::phy::AwdlIpDevice;
use crate::tls::UserspaceTls;

/// Default AirDrop TCP port used by `owly`'s receiver (`MDNS-1`).
pub const DEFAULT_RECEIVER_PORT: u16 = 8771;

/// Maximum compressed upload body and total extracted file bytes buffered by the default
/// in-memory receiver (256 MiB).
///
/// Applications that deliberately accept larger in-memory transfers can pass a customized
/// [`ReceiverConfig`] to [`UserspaceNode::enable_receiver_with_config`].
pub const DEFAULT_IN_MEMORY_UPLOAD_LIMIT: u64 = 256 * 1024 * 1024;

const TCP_BUF_BYTES: usize = 65536;
const UDP_SLOTS: usize = 16;
const UDP_SLOT_BYTES: usize = 4096;
const UPLOAD_CHUNK_BYTES: usize = 16384;

/// Builds a default fixed-channel [`owly_awdl::Config`] suitable for simulated or dedicated USB radios.
pub fn default_awdl_config(addr: MacAddr, name: &str, channel: Channel) -> AwdlConfig {
    AwdlConfig::new(
        addr,
        name,
        RadioConstraints {
            channel,
            presence: Presence::Fixed,
        },
    )
}

/// High-level events emitted by a [`UserspaceNode`] acting as an AirDrop receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserspaceReceiveEvent {
    Discovered(DiscoverRequest),
    Ask {
        id: u64,
        request: AskRequest,
    },
    AskWithdrawn {
        id: u64,
    },
    Urls {
        id: u64,
        urls: Vec<String>,
    },
    ReceivedFiles {
        id: u64,
        files: Vec<(String, Vec<u8>)>,
    },
    Failed {
        id: u64,
        reason: String,
    },
}

struct ReceiverState {
    config: Arc<ReceiverConfig>,
    identity: Identity,
    service: Service,
    announcer: Announcer,
    listen_port: u16,
    listen_handle: Option<SocketHandle>,
    next_conn_id: u64,
    conns: BTreeMap<u64, RxTcpConn>,
    events: VecDeque<UserspaceReceiveEvent>,
}

struct RxTcpConn {
    handle: SocketHandle,
    tls: UserspaceTls,
    proto: ReceiverConnection,
    staging_files: Vec<(String, Vec<u8>)>,
    current_file: Option<(String, Vec<u8>)>,
    timer_deadline_us: Option<u64>,
}

struct DiscoverTask {
    handle: SocketHandle,
    tls: UserspaceTls,
    reader: ResponseReader,
    sent_req: bool,
    deadline_us: u64,
    finished: Option<Result<Option<DiscoveredPeer>, String>>,
}

struct TransferTask {
    handle: SocketHandle,
    tls: UserspaceTls,
    transfer: Transfer,
    connected: bool,
    upload_bytes: Vec<u8>,
    upload_offset: usize,
    streaming_upload: bool,
    timer_deadline_us: Option<u64>,
    finished: Option<Outcome>,
}

/// Self-contained 7-layer userspace AWDL + `smoltcp` IPv6 + AirDrop protocol node.
pub struct UserspaceNode {
    mac: MacAddr,
    link_local: Ipv6Addr,
    awdl: Node,
    next_awdl_timer: Time,
    device: AwdlIpDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    draining_sockets: Vec<(SocketHandle, u64)>,
    mdns_handle: SocketHandle,
    base_instant: Instant,
    next_ephemeral_port: u16,
    valid_peers: BTreeMap<MacAddr, ()>,
    receiver: Option<ReceiverState>,
    browser: Option<Browser>,
    browse_events: VecDeque<BrowseEvent>,
    discovered: BTreeMap<String, Found>,
    discover_task: Option<DiscoverTask>,
    discover_result: Option<Result<Option<DiscoveredPeer>, String>>,
    transfer_task: Option<TransferTask>,
    transfer_outcome: Option<Outcome>,
}

impl UserspaceNode {
    /// Creates a new userspace AWDL + `smoltcp` node at explicit initial timestamp `start_us`.
    pub fn new(cfg: AwdlConfig, start_us: u64) -> Self {
        crate::ensure_crypto_provider();
        let mac = cfg.addr;
        let link_local = mac.link_local();
        let start_time = Time(start_us);
        let awdl = Node::new(cfg, start_time);

        let mut device = AwdlIpDevice::new();
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = u64::from_le_bytes([
            mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5], 0x5a, 0xa5,
        ]);
        let smol_now = SmolInstant::from_micros(i64::try_from(start_us).unwrap_or(i64::MAX));
        let mut iface = Interface::new(iface_cfg, &mut device, smol_now);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(link_local), 64));
        });
        let _ = iface.join_multicast_group(IpAddress::Ipv6(MDNS_GROUP));

        let mut sockets = SocketSet::new(Vec::new());
        let mut mdns_sock = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_SLOTS],
                vec![0u8; UDP_SLOTS * UDP_SLOT_BYTES],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_SLOTS],
                vec![0u8; UDP_SLOTS * UDP_SLOT_BYTES],
            ),
        );
        let _ = mdns_sock.bind(IpListenEndpoint::from(MDNS_PORT));
        let mdns_handle = sockets.add(mdns_sock);

        Self {
            mac,
            link_local,
            awdl,
            next_awdl_timer: start_time,
            device,
            iface,
            sockets,
            draining_sockets: Vec::new(),
            mdns_handle,
            base_instant: Instant::now(),
            next_ephemeral_port: 49152,
            valid_peers: BTreeMap::new(),
            receiver: None,
            browser: None,
            browse_events: VecDeque::new(),
            discovered: BTreeMap::new(),
            discover_task: None,
            discover_result: None,
            transfer_task: None,
            transfer_outcome: None,
        }
    }

    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    pub fn link_local(&self) -> Ipv6Addr {
        self.link_local
    }

    /// Valid AWDL peers discovered over 802.11 action frames.
    pub fn valid_peers(&self) -> Vec<MacAddr> {
        self.valid_peers.keys().copied().collect()
    }

    pub fn awdl(&self) -> &Node {
        &self.awdl
    }

    pub fn device_stats(&self) -> (u64, u64) {
        (self.device.rx_packets(), self.device.tx_packets())
    }

    /// Enables `_airdrop._tcp` mDNS announcing and opens the TLS receiver on `port`.
    pub fn enable_receiver(
        &mut self,
        computer_name: &str,
        instance_id: &str,
        host_label: &str,
        port: u16,
        flags: u32,
        now_us: u64,
    ) -> std::io::Result<()> {
        let mut config = ReceiverConfig::new(computer_name);
        config.limits.max_upload_body = DEFAULT_IN_MEMORY_UPLOAD_LIMIT;
        config.limits.extract.max_total = DEFAULT_IN_MEMORY_UPLOAD_LIMIT;
        self.enable_receiver_with_config(config, instance_id, host_label, port, flags, now_us)
    }

    /// Enables the receiver with caller-supplied protocol and resource limits.
    pub fn enable_receiver_with_config(
        &mut self,
        config: ReceiverConfig,
        instance_id: &str,
        host_label: &str,
        port: u16,
        flags: u32,
        now_us: u64,
    ) -> std::io::Result<()> {
        if self.receiver.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "receiver is already enabled",
            ));
        }
        let identity = Identity::generate()?;
        let service = Service {
            instance: instance_id.to_string(),
            host: host_label.to_string(),
            port,
            addr: self.link_local,
            flags,
        };
        let burst = Burst {
            count: 2,
            interval: Duration::from_millis(50),
            pause: Duration::from_secs(2),
        };
        let announcer = Announcer::new(Some(burst), self.std_instant(now_us));
        let mut rx_state = ReceiverState {
            config: Arc::new(config),
            identity,
            service,
            announcer,
            listen_port: port,
            listen_handle: None,
            next_conn_id: 1,
            conns: BTreeMap::new(),
            events: VecDeque::new(),
        };
        rx_state.listen_handle = Some(Self::alloc_listener(&mut self.sockets, port)?);
        self.receiver = Some(rx_state);
        Ok(())
    }

    /// Starts active `_airdrop._tcp` mDNS browsing.
    pub fn enable_browser(&mut self, now_us: u64) {
        self.browser = Some(Browser::new(self.std_instant(now_us)));
    }

    pub fn poll_browse_event(&mut self) -> Option<BrowseEvent> {
        self.browse_events.pop_front()
    }

    pub fn discovered_services(&self) -> Vec<Found> {
        self.discovered.values().cloned().collect()
    }

    pub fn poll_receiver_event(&mut self) -> Option<UserspaceReceiveEvent> {
        self.receiver.as_mut()?.events.pop_front()
    }

    /// Answers an interactive `/Ask` request (`accept = true` or `decline`).
    pub fn answer_ask(&mut self, conn_id: u64, answer: Answer) -> bool {
        let Some(rx_state) = &mut self.receiver else {
            return false;
        };
        let Some(conn) = rx_state.conns.get_mut(&conn_id) else {
            return false;
        };
        conn.proto.answer(answer);
        true
    }

    pub fn accept_ask(&mut self, conn_id: u64) -> bool {
        self.answer_ask(conn_id, Answer::Accept)
    }

    pub fn decline_ask(&mut self, conn_id: u64) -> bool {
        self.answer_ask(conn_id, Answer::Decline)
    }

    /// Opens a TLS connection to `addr:port` and posts `/Discover`.
    pub fn start_discover(&mut self, addr: Ipv6Addr, port: u16, now_us: u64) -> Result<(), String> {
        if self.discover_task.is_some() {
            return Err("discover already in progress".into());
        }
        let tls = UserspaceTls::client().map_err(|e| e.to_string())?;
        let local_port = self.alloc_ephemeral_port();
        let mut sock = Self::new_tcp_socket();
        sock.connect(
            self.iface.context(),
            (IpAddress::Ipv6(addr), port),
            local_port,
        )
        .map_err(|e| format!("tcp connect: {e:?}"))?;
        let handle = self.sockets.add(sock);
        self.discover_result = None;
        self.discover_task = Some(DiscoverTask {
            handle,
            tls,
            reader: ResponseReader::new(),
            sent_req: false,
            deadline_us: now_us.saturating_add(10_000_000),
            finished: None,
        });
        Ok(())
    }

    pub fn take_discover_result(&mut self) -> Option<Result<Option<DiscoveredPeer>, String>> {
        self.discover_result.take()
    }

    /// Opens a TLS connection and sends in-memory files (`Gzip` or `DVZip` per `receiver_flags`).
    pub fn start_send_files(
        &mut self,
        addr: Ipv6Addr,
        port: u16,
        receiver_flags: u32,
        sender_name: &str,
        files: &[(String, Vec<u8>)],
    ) -> Result<(), String> {
        if self.transfer_task.is_some() {
            return Err("transfer already in progress".into());
        }
        let compressor = compressor_for_receiver_flags(receiver_flags);
        let (offer, upload_bytes) = build_in_memory_upload(files, compressor)?;
        let upload_meta = Some((compressor, upload_bytes.len() as u64));
        self.start_transfer(addr, port, sender_name, offer, upload_meta, upload_bytes)
    }

    /// Opens a TLS connection and sends an AirDrop URL offer (`ASK-4`).
    pub fn start_send_urls(
        &mut self,
        addr: Ipv6Addr,
        port: u16,
        sender_name: &str,
        urls: Vec<String>,
    ) -> Result<(), String> {
        if self.transfer_task.is_some() {
            return Err("transfer already in progress".into());
        }
        if urls.is_empty() {
            return Err("at least one URL is required".into());
        }
        self.start_transfer(addr, port, sender_name, Offer::Urls(urls), None, Vec::new())
    }

    pub fn take_transfer_outcome(&mut self) -> Option<Outcome> {
        self.transfer_outcome.take()
    }

    fn start_transfer(
        &mut self,
        addr: Ipv6Addr,
        port: u16,
        sender_name: &str,
        offer: Offer,
        upload_meta: Option<(Compressor, u64)>,
        upload_bytes: Vec<u8>,
    ) -> Result<(), String> {
        let transfer_id = random_uuid_v4()?;
        let sender_id = random_hex_id()?;
        let cfg = SenderConfig::new(sender_name, sender_id);
        let transfer = Transfer::new(&cfg, &transfer_id, &offer, upload_meta);

        let tls = UserspaceTls::client().map_err(|e| e.to_string())?;
        let local_port = self.alloc_ephemeral_port();
        let mut sock = Self::new_tcp_socket();
        sock.connect(
            self.iface.context(),
            (IpAddress::Ipv6(addr), port),
            local_port,
        )
        .map_err(|e| format!("tcp connect: {e:?}"))?;
        let handle = self.sockets.add(sock);
        self.transfer_outcome = None;
        self.transfer_task = Some(TransferTask {
            handle,
            tls,
            transfer,
            connected: false,
            upload_bytes,
            upload_offset: 0,
            streaming_upload: false,
            timer_deadline_us: None,
            finished: None,
        });
        Ok(())
    }

    /// Advances all 7 layers at monotonic microsecond timestamp `now_us`.
    ///
    /// Consumes `rx_frames` off the radio, steps `owly_awdl::Node`, polls `smoltcp`, pumps
    /// mDNS / TLS / AirDrop state machines, and returns outbound 802.11 frames to transmit.
    pub fn step(&mut self, now_us: u64, rx_frames: &[(Option<i8>, Vec<u8>)]) -> Vec<Frame> {
        let now = Time(now_us);
        let mut tx_frames = Vec::new();

        for (rssi, bytes) in rx_frames {
            self.handle_awdl_actions(
                Input::Frame {
                    rx_time: now,
                    rssi: *rssi,
                    bytes,
                },
                &mut tx_frames,
            );
        }

        if now >= self.next_awdl_timer {
            self.handle_awdl_actions(Input::Timer(now), &mut tx_frames);
        }

        let smol_now = SmolInstant::from_micros(i64::try_from(now_us).unwrap_or(i64::MAX));
        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);

        self.pump_mdns(now_us);
        self.pump_receiver(now_us);
        self.pump_discover(now_us);
        self.pump_transfer(now_us);
        self.reap_draining_sockets(now_us);

        self.iface
            .poll(smol_now, &mut self.device, &mut self.sockets);

        while let Some(packet) = self.device.pop_tx() {
            self.handle_awdl_actions(Input::Outbound { now, packet }, &mut tx_frames);
        }

        tx_frames
    }

    fn handle_awdl_actions(&mut self, input: Input<'_>, tx_frames: &mut Vec<Frame>) {
        let actions: Vec<AwdlAction> = self.awdl.handle(input).collect();
        for action in actions {
            match action {
                AwdlAction::Transmit { frame, .. } => tx_frames.push(frame),
                AwdlAction::ArmTimer(at) => self.next_awdl_timer = at,
                AwdlAction::PeerUp(info) => {
                    self.valid_peers.insert(info.mac, ());
                }
                AwdlAction::PeerDown(mac) => {
                    self.valid_peers.remove(&mac);
                }
                AwdlAction::Deliver(pkt) => self.device.push_rx(pkt),
            }
        }
    }

    fn pump_mdns(&mut self, now_us: u64) {
        let std_now = self.std_instant(now_us);
        let local_ll = self.link_local;
        let sock = self.sockets.get_mut::<udp::Socket>(self.mdns_handle);

        let mut incoming = Vec::new();
        while sock.can_recv() {
            if let Ok((bytes, meta)) = sock.recv() {
                incoming.push((meta.endpoint.port, meta.endpoint.addr, bytes.to_vec()));
            } else {
                break;
            }
        }

        let mut outgoing: Vec<(IpEndpoint, Vec<u8>)> = Vec::new();
        for (src_port, src_addr, raw) in incoming {
            let Ok(msg) = Message::decode(&raw) else {
                continue;
            };
            if !msg.response {
                if let Some(rx_state) = &self.receiver
                    && let Some(reply) = rx_state.service.answer(&msg, src_port != MDNS_PORT)
                {
                    let dst = if reply.unicast {
                        IpEndpoint::new(src_addr, src_port)
                    } else {
                        IpEndpoint::new(IpAddress::Ipv6(MDNS_GROUP), MDNS_PORT)
                    };
                    outgoing.push((dst, reply.message));
                }
            } else if let Some(browser) = &mut self.browser {
                browser.handle(&msg, std_now);
                while let Some(ev) = browser.poll_event() {
                    match &ev {
                        BrowseEvent::Found(found) => {
                            self.discovered
                                .insert(found.instance.clone(), found.clone());
                        }
                        BrowseEvent::Lost(id) => {
                            self.discovered.remove(id);
                        }
                    }
                    self.browse_events.push_back(ev);
                }
            }
        }

        if let Some(rx_state) = &mut self.receiver
            && rx_state.announcer.on_timer(std_now)
        {
            outgoing.push((
                IpEndpoint::new(IpAddress::Ipv6(MDNS_GROUP), MDNS_PORT),
                rx_state.service.announcement(),
            ));
        }

        if let Some(browser) = &mut self.browser {
            if let Some(query) = browser.on_timer(std_now) {
                outgoing.push((
                    IpEndpoint::new(IpAddress::Ipv6(MDNS_GROUP), MDNS_PORT),
                    query,
                ));
            }
            while let Some(ev) = browser.poll_event() {
                match &ev {
                    BrowseEvent::Found(found) => {
                        self.discovered
                            .insert(found.instance.clone(), found.clone());
                    }
                    BrowseEvent::Lost(id) => {
                        self.discovered.remove(id);
                    }
                }
                self.browse_events.push_back(ev);
            }
        }

        for (endpoint, payload) in outgoing {
            if sock.can_send() {
                let meta = udp::UdpMetadata {
                    endpoint,
                    local_address: Some(IpAddress::Ipv6(local_ll)),
                    meta: Default::default(),
                };
                let _ = sock.send_slice(&payload, meta);
            }
        }
    }

    fn pump_receiver(&mut self, now_us: u64) {
        let Some(rx_state) = &mut self.receiver else {
            return;
        };

        // Promote accepted listener socket into an active TLS connection and re-arm listener.
        if let Some(listen_handle) = rx_state.listen_handle {
            let state = self.sockets.get::<tcp::Socket>(listen_handle).state();
            if state != tcp::State::Listen {
                match Self::alloc_listener(&mut self.sockets, rx_state.listen_port) {
                    Ok(handle) => rx_state.listen_handle = Some(handle),
                    Err(err) => {
                        rx_state.listen_handle = None;
                        rx_state.events.push_back(UserspaceReceiveEvent::Failed {
                            id: 0,
                            reason: format!("failed to re-arm receiver listener: {err}"),
                        });
                    }
                }
                if let Ok(tls) = UserspaceTls::server(&rx_state.identity) {
                    let conn_id = rx_state.next_conn_id;
                    rx_state.next_conn_id = rx_state.next_conn_id.saturating_add(1);
                    rx_state.conns.insert(
                        conn_id,
                        RxTcpConn {
                            handle: listen_handle,
                            tls,
                            proto: ReceiverConnection::new(Arc::clone(&rx_state.config)),
                            staging_files: Vec::new(),
                            current_file: None,
                            timer_deadline_us: None,
                        },
                    );
                } else {
                    self.sockets.remove(listen_handle);
                }
            }
        }

        let mut finished_ids = Vec::new();
        for (&conn_id, conn) in &mut rx_state.conns {
            let sock = self.sockets.get_mut::<tcp::Socket>(conn.handle);
            if let Err(err) = conn.tls.pump(sock) {
                rx_state.events.push_back(UserspaceReceiveEvent::Failed {
                    id: conn_id,
                    reason: err,
                });
                conn.tls.initiate_close();
                let _ = conn.tls.pump(sock);
                finished_ids.push(conn_id);
                continue;
            }

            let rx_bytes = conn.tls.take_rx();
            if !rx_bytes.is_empty() {
                conn.proto.receive(&rx_bytes);
            }
            if conn.tls.peer_eof() {
                conn.proto.receive_eof();
            }
            if conn.timer_deadline_us.is_some_and(|dl| now_us >= dl) {
                conn.timer_deadline_us = None;
                conn.proto.timeout();
            }

            while let Some(ev) = conn.proto.poll() {
                match ev {
                    ReceiverProtoEvent::Transmit(bytes) => conn.tls.queue_write(&bytes),
                    ReceiverProtoEvent::SetTimer(after) => {
                        conn.timer_deadline_us = after.map(|d| {
                            now_us.saturating_add(u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
                        });
                    }
                    ReceiverProtoEvent::Discovered(req) => {
                        rx_state
                            .events
                            .push_back(UserspaceReceiveEvent::Discovered(req));
                    }
                    ReceiverProtoEvent::Ask(req) => {
                        rx_state.events.push_back(UserspaceReceiveEvent::Ask {
                            id: conn_id,
                            request: req,
                        });
                    }
                    ReceiverProtoEvent::AskWithdrawn => {
                        rx_state
                            .events
                            .push_back(UserspaceReceiveEvent::AskWithdrawn { id: conn_id });
                    }
                    ReceiverProtoEvent::Urls(urls) => {
                        rx_state
                            .events
                            .push_back(UserspaceReceiveEvent::Urls { id: conn_id, urls });
                    }
                    ReceiverProtoEvent::UploadStarted => {
                        conn.staging_files.clear();
                        conn.current_file = None;
                    }
                    ReceiverProtoEvent::CreateDir(_) => {}
                    ReceiverProtoEvent::CreateFile(rel) => {
                        conn.current_file = Some((rel.components().join("/"), Vec::new()));
                    }
                    ReceiverProtoEvent::Data(chunk) => {
                        if let Some((_, buf)) = &mut conn.current_file {
                            buf.extend_from_slice(&chunk);
                        }
                    }
                    ReceiverProtoEvent::EndFile => {
                        if let Some(file) = conn.current_file.take() {
                            conn.staging_files.push(file);
                        }
                    }
                    ReceiverProtoEvent::UploadComplete => {
                        let files = std::mem::take(&mut conn.staging_files);
                        rx_state
                            .events
                            .push_back(UserspaceReceiveEvent::ReceivedFiles { id: conn_id, files });
                        conn.proto.finish_upload(Ok(()));
                    }
                    ReceiverProtoEvent::UploadFailed(reason) => {
                        conn.staging_files.clear();
                        conn.current_file = None;
                        rx_state.events.push_back(UserspaceReceiveEvent::Failed {
                            id: conn_id,
                            reason,
                        });
                    }
                    ReceiverProtoEvent::Close => conn.tls.initiate_close(),
                }
            }

            let _ = conn.tls.pump(sock);
            if conn.proto.is_closed() && conn.tls.is_fully_closed() {
                finished_ids.push(conn_id);
            }
        }

        let mut to_retire = Vec::new();
        for id in finished_ids {
            if let Some(conn) = rx_state.conns.remove(&id) {
                to_retire.push(conn.handle);
            }
        }
        for handle in to_retire {
            self.retire_socket(handle, now_us);
        }
    }

    fn pump_discover(&mut self, now_us: u64) {
        let Some(task) = &mut self.discover_task else {
            return;
        };
        let sock = self.sockets.get_mut::<tcp::Socket>(task.handle);
        if let Err(err) = task.tls.pump(sock) {
            task.finished = Some(Err(err));
        } else {
            if !task.sent_req && sock.state() == tcp::State::Established {
                task.tls.queue_write(&discover_request());
                task.sent_req = true;
            }
            let rx = task.tls.take_rx();
            if !rx.is_empty() {
                match task.reader.receive(&rx) {
                    Ok(Some(resp)) => {
                        task.finished = Some(Ok(parse_discover_response(&resp)));
                        task.tls.initiate_close();
                    }
                    Ok(None) => {}
                    Err(e) => {
                        task.finished = Some(Err(e.to_string()));
                        task.tls.initiate_close();
                    }
                }
            }
            if task.finished.is_none() && task.tls.peer_eof() {
                let res = task
                    .reader
                    .receive_eof()
                    .map(|r| parse_discover_response(&r))
                    .map_err(|e| e.to_string());
                task.finished = Some(res);
                task.tls.initiate_close();
            }
            if task.finished.is_none() && now_us >= task.deadline_us {
                task.finished = Some(Err("discover timed out".into()));
                task.tls.initiate_close();
            }
            let _ = task.tls.pump(sock);
        }

        if let Some(res) = task.finished.take() {
            let done_task = self.discover_task.take().unwrap();
            self.retire_socket(done_task.handle, now_us);
            self.discover_result = Some(res);
        }
    }

    fn pump_transfer(&mut self, now_us: u64) {
        let Some(task) = &mut self.transfer_task else {
            return;
        };
        let sock = self.sockets.get_mut::<tcp::Socket>(task.handle);
        if let Err(err) = task.tls.pump(sock) {
            task.finished = Some(Outcome::Failed(err));
        } else {
            if task.timer_deadline_us.is_some_and(|dl| now_us >= dl) {
                task.timer_deadline_us = None;
                task.transfer.timeout();
            }

            let rx = task.tls.take_rx();
            if !rx.is_empty() {
                task.transfer.receive(&rx);
            }
            if task.tls.peer_eof() {
                task.transfer.receive_eof();
            }

            if sock.state() == tcp::State::Established {
                task.connected = true;
            }
            if task.connected {
                while let Some(action) = task.transfer.poll() {
                    match action {
                        SenderAction::Transmit(bytes) => task.tls.queue_write(&bytes),
                        SenderAction::SetTimer(after) => {
                            task.timer_deadline_us = after.map(|d| {
                                now_us.saturating_add(
                                    u64::try_from(d.as_micros()).unwrap_or(u64::MAX),
                                )
                            });
                        }
                        SenderAction::Accepted => {}
                        SenderAction::SendUpload(head) => {
                            task.tls.queue_write(&head);
                            task.streaming_upload = true;
                        }
                        SenderAction::Done(outcome) => {
                            task.finished = Some(outcome);
                            task.tls.initiate_close();
                            break;
                        }
                    }
                }
            }

            if task.streaming_upload {
                while task.upload_offset < task.upload_bytes.len()
                    && task.tls.tx_queued_len() < 32768
                {
                    let end =
                        (task.upload_offset + UPLOAD_CHUNK_BYTES).min(task.upload_bytes.len());
                    task.tls
                        .queue_write(&task.upload_bytes[task.upload_offset..end]);
                    task.upload_offset = end;
                }
                if task.upload_offset >= task.upload_bytes.len() && task.tls.tx_queued_len() == 0 {
                    task.streaming_upload = false;
                    task.transfer.upload_sent();
                }
            }

            let _ = task.tls.pump(sock);
        }

        if let Some(outcome) = task.finished.take() {
            let done_task = self.transfer_task.take().unwrap();
            self.retire_socket(done_task.handle, now_us);
            self.transfer_outcome = Some(outcome);
        }
    }

    fn retire_socket(&mut self, handle: SocketHandle, now_us: u64) {
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        if !matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait) {
            sock.close();
        }
        // Keep the socket until smoltcp finishes transmitting queued TLS records / FIN.
        self.draining_sockets
            .push((handle, now_us.saturating_add(2_000_000)));
    }

    fn reap_draining_sockets(&mut self, now_us: u64) {
        let mut idx = 0;
        while idx < self.draining_sockets.len() {
            let (handle, deadline) = self.draining_sockets[idx];
            let sock = self.sockets.get::<tcp::Socket>(handle);
            let done = (sock.send_queue() == 0
                && matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait))
                || now_us >= deadline;
            if done {
                self.draining_sockets.swap_remove(idx);
                self.sockets.remove(handle);
            } else {
                idx += 1;
            }
        }
    }

    fn alloc_ephemeral_port(&mut self) -> u16 {
        let port = self.next_ephemeral_port;
        self.next_ephemeral_port = if self.next_ephemeral_port >= 65000 {
            49152
        } else {
            self.next_ephemeral_port + 1
        };
        port
    }

    fn alloc_listener(
        sockets: &mut SocketSet<'static>,
        port: u16,
    ) -> std::io::Result<SocketHandle> {
        let mut sock = Self::new_tcp_socket();
        sock.listen(port)
            .map_err(|e| std::io::Error::other(format!("tcp listen: {e:?}")))?;
        Ok(sockets.add(sock))
    }

    fn new_tcp_socket() -> tcp::Socket<'static> {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF_BYTES]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF_BYTES]),
        )
    }

    fn std_instant(&self, now_us: u64) -> Instant {
        self.base_instant + Duration::from_micros(now_us)
    }
}

/// Chooses the upload compression advertised by an AirDrop receiver.
///
/// Flags that are not yet a complete receiver TXT record keep the protocol's DVZip default.
pub fn compressor_for_receiver_flags(receiver_flags: u32) -> Compressor {
    let known = receiver_flags & (SUPPORTS_PIPELINING | SUPPORTS_MIXED_TYPES) != 0;
    if known && receiver_flags & SUPPORTS_DVZIP == 0 {
        Compressor::Gzip
    } else {
        Compressor::DvZip
    }
}

/// Summary returned by [`step_cluster`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StepClusterStats {
    pub steps_executed: u64,
    pub frames_transmitted: u64,
}

/// Advances all `(hub_id, &mut UserspaceNode)` entries in lockstep on `SimAirHub`.
pub fn step_cluster(
    nodes: &mut [(usize, &mut UserspaceNode)],
    hub: &mut SimAirHub,
    start_us: u64,
    steps: u64,
    dt_us: u64,
) -> StepClusterStats {
    let mut stats = StepClusterStats::default();
    for i in 0..steps {
        let now_us = start_us.saturating_add(i.saturating_mul(dt_us));
        for (hub_id, node) in nodes.iter_mut() {
            let rx = hub.drain_rx(*hub_id);
            let out = node.step(now_us, &rx);
            for frame in &out {
                stats.frames_transmitted = stats.frames_transmitted.saturating_add(1);
                hub.transmit(*hub_id, now_us, frame);
            }
        }
        stats.steps_executed = stats.steps_executed.saturating_add(1);
    }
    stats
}

fn random_hex_id() -> Result<String, String> {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).map_err(|e| format!("getrandom: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn random_uuid_v4() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| format!("getrandom: {e}"))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02X}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
