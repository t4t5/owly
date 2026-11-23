//! Sans-IO `rustls` adapter pumping TLS 1.2/1.3 over a `smoltcp` TCP socket.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::Arc;

use owly_airdrop::driver::tls::{Identity, client_config, server_config, server_name};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use smoltcp::socket::tcp::{self, Socket as TcpSocket};

/// Either a client or server `rustls` state machine.
pub enum TlsRole {
    Client(Box<ClientConnection>),
    Server(Box<ServerConnection>),
}

/// Sans-IO TLS byte pump over a [`smoltcp::socket::tcp::Socket`].
pub struct UserspaceTls {
    conn: TlsRole,
    tx_plain: VecDeque<u8>,
    tls_out: Vec<u8>,
    tls_out_pos: usize,
    rx_plain: Vec<u8>,
    close_requested: bool,
    close_notified: bool,
    tcp_closed: bool,
    peer_eof: bool,
}

impl UserspaceTls {
    /// Creates a client TLS session configured with AirDrop's no-hostname-check verifier.
    pub fn client() -> io::Result<Self> {
        crate::ensure_crypto_provider();
        let cfg: Arc<ClientConfig> = client_config(None)?;
        let conn = ClientConnection::new(cfg, server_name())
            .map_err(|e| io::Error::other(format!("rustls client init: {e}")))?;
        Ok(Self::from_role(TlsRole::Client(Box::new(conn))))
    }

    /// Creates a server TLS session presenting `identity`.
    pub fn server(identity: &Identity) -> io::Result<Self> {
        crate::ensure_crypto_provider();
        let cfg: Arc<ServerConfig> = server_config(identity)?;
        let conn = ServerConnection::new(cfg)
            .map_err(|e| io::Error::other(format!("rustls server init: {e}")))?;
        Ok(Self::from_role(TlsRole::Server(Box::new(conn))))
    }

    fn from_role(conn: TlsRole) -> Self {
        Self {
            conn,
            tx_plain: VecDeque::new(),
            tls_out: Vec::new(),
            tls_out_pos: 0,
            rx_plain: Vec::new(),
            close_requested: false,
            close_notified: false,
            tcp_closed: false,
            peer_eof: false,
        }
    }

    pub fn queue_write(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() && !self.close_requested {
            self.tx_plain.extend(bytes);
        }
    }

    pub fn tx_queued_len(&self) -> usize {
        self.tx_plain.len()
    }

    pub fn take_rx(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.rx_plain)
    }

    pub fn peer_eof(&self) -> bool {
        self.peer_eof
    }

    pub fn initiate_close(&mut self) {
        self.close_requested = true;
    }

    pub fn is_fully_closed(&self) -> bool {
        self.tcp_closed && self.tls_out_pos >= self.tls_out.len()
    }

    /// Drives one non-blocking TLS/TCP exchange step.
    pub fn pump(&mut self, sock: &mut TcpSocket<'_>) -> Result<(), String> {
        // 1. Ingest encrypted TLS records from the smoltcp RX buffer, processing
        // and draining plaintext on each chunk so rustls's deframer and plaintext
        // queues never hit their fixed capacity limits under multi-record bursts.
        let mut drained = false;
        while sock.can_recv() {
            let mut read_res: Result<usize, String> = Ok(0);
            let consumed = sock
                .recv(|data| {
                    let mut slice: &[u8] = data;
                    match self.read_tls(&mut slice) {
                        Ok(n) => {
                            read_res = Ok(n);
                            (n, n)
                        }
                        Err(e) => {
                            read_res = Err(format!("tls read_tls: {e}"));
                            (0, 0)
                        }
                    }
                })
                .unwrap_or(0);
            read_res?;
            self.drain_processed()?;
            drained = true;
            if consumed == 0 {
                break;
            }
        }
        if !drained {
            self.drain_processed()?;
        }

        if matches!(
            sock.state(),
            tcp::State::CloseWait | tcp::State::Closed | tcp::State::TimeWait | tcp::State::LastAck
        ) && !sock.can_recv()
            && !sock.may_recv()
        {
            self.peer_eof = true;
        }

        // 3. Feed queued plaintext into rustls writer.
        while !self.tx_plain.is_empty() {
            let (front, _) = self.tx_plain.as_slices();
            if front.is_empty() {
                break;
            }
            match write_role_plaintext(&mut self.conn, front) {
                Ok(0) => break,
                Ok(n) => {
                    self.tx_plain.drain(..n);
                }
                Err(e) => return Err(format!("tls plaintext write: {e}")),
            }
        }

        if self.close_requested && !self.close_notified && self.tx_plain.is_empty() {
            self.send_close_notify();
            self.close_notified = true;
        }

        // 4. Move encrypted TLS output into tls_out, then flush into smoltcp TX buffer.
        if self.tls_out_pos >= self.tls_out.len() {
            self.tls_out.clear();
            self.tls_out_pos = 0;
        }
        while self.wants_write() {
            let before = self.tls_out.len();
            if self.write_tls_to_vec()? == 0 || self.tls_out.len() == before {
                break;
            }
        }
        if self.tls_out_pos < self.tls_out.len() && sock.can_send() {
            let sent = sock
                .send_slice(&self.tls_out[self.tls_out_pos..])
                .map_err(|e| format!("tcp send_slice: {e:?}"))?;
            self.tls_out_pos += sent;
            if self.tls_out_pos >= self.tls_out.len() {
                self.tls_out.clear();
                self.tls_out_pos = 0;
            }
        }

        if self.close_notified && !self.tcp_closed && self.tls_out_pos >= self.tls_out.len() {
            sock.close();
            self.tcp_closed = true;
        }

        Ok(())
    }

    fn drain_processed(&mut self) -> Result<(), String> {
        let io_state = self
            .process_new_packets()
            .map_err(|e| format!("tls process: {e}"))?;

        if io_state.plaintext_bytes_to_read() > 0 {
            let mut buf = [0u8; 4096];
            loop {
                match self.read_plaintext(&mut buf) {
                    Ok(0) => {
                        self.peer_eof = true;
                        break;
                    }
                    Ok(n) => self.rx_plain.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        self.peer_eof = true;
                        break;
                    }
                    Err(e) => return Err(format!("tls plaintext read: {e}")),
                }
            }
        }

        if io_state.peer_has_closed() {
            self.peer_eof = true;
        }
        Ok(())
    }

    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        match &mut self.conn {
            TlsRole::Client(c) => c.read_tls(rd),
            TlsRole::Server(s) => s.read_tls(rd),
        }
    }

    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match &mut self.conn {
            TlsRole::Client(c) => c.process_new_packets(),
            TlsRole::Server(s) => s.process_new_packets(),
        }
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.conn {
            TlsRole::Client(c) => c.reader().read(buf),
            TlsRole::Server(s) => s.reader().read(buf),
        }
    }

    fn wants_write(&self) -> bool {
        match &self.conn {
            TlsRole::Client(c) => c.wants_write(),
            TlsRole::Server(s) => s.wants_write(),
        }
    }

    fn write_tls_to_vec(&mut self) -> Result<usize, String> {
        match &mut self.conn {
            TlsRole::Client(c) => c
                .write_tls(&mut self.tls_out)
                .map_err(|e| format!("tls write_tls: {e}")),
            TlsRole::Server(s) => s
                .write_tls(&mut self.tls_out)
                .map_err(|e| format!("tls write_tls: {e}")),
        }
    }

    fn send_close_notify(&mut self) {
        match &mut self.conn {
            TlsRole::Client(c) => c.send_close_notify(),
            TlsRole::Server(s) => s.send_close_notify(),
        }
    }
}

fn write_role_plaintext(conn: &mut TlsRole, buf: &[u8]) -> io::Result<usize> {
    match conn {
        TlsRole::Client(c) => c.writer().write(buf),
        TlsRole::Server(s) => s.writer().write(buf),
    }
}
