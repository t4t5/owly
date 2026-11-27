use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::unistd::{read, write};
use owly_airdrop::proto::ble::{APPLE_COMPANY_ID, Advert, INTERVAL_MS};

const AF_BLUETOOTH: i32 = 31;
const BTPROTO_HCI: i32 = 1;
const SOL_HCI: i32 = 0;
const HCI_FILTER: i32 = 2;
const HCI_CHANNEL_RAW: u16 = 0;

const HCI_COMMAND_PKT: u8 = 0x01;
const HCI_EVENT_PKT: u8 = 0x04;
const EVT_COMMAND_COMPLETE: u8 = 0x0e;
const EVT_COMMAND_STATUS: u8 = 0x0f;

/// LE controller commands (OGF 0x08).
const fn le(ocf: u16) -> u16 {
    0x08 << 10 | ocf
}
const SET_EXT_ADV_PARAMS: u16 = le(0x0036);
const SET_EXT_ADV_DATA: u16 = le(0x0037);
const SET_EXT_SCAN_RSP: u16 = le(0x0038);
const SET_EXT_ADV_ENABLE: u16 = le(0x0039);
const READ_NUM_ADV_SETS: u16 = le(0x003b);
const REMOVE_ADV_SET: u16 = le(0x003c);

/// How long a command may take to complete. With the radio busy, each can
/// take around two seconds to be answered.
const COMMAND_TIMEOUT_MS: u16 = 10_000;

#[repr(C)]
struct SockaddrHci {
    family: u16,
    dev: u16,
    channel: u16,
}

#[repr(C)]
struct HciFilter {
    type_mask: u32,
    event_mask: [u32; 2],
    opcode: u16,
}

/// Advertises through the first HCI controller the kernel lists.
pub struct HciAdvertiser {
    socket: Arc<OwnedFd>,
}

impl HciAdvertiser {
    pub async fn new() -> io::Result<Self> {
        tokio::task::spawn_blocking(open)
            .await
            .map_err(io::Error::other)?
            .map(|fd| HciAdvertiser {
                socket: Arc::new(fd),
            })
    }

    /// Transmits `advert` until the registration is dropped.
    pub async fn advertise(&self, advert: Advert) -> io::Result<Registration> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || start(socket, advert))
            .await
            .map_err(io::Error::other)?
    }
}

/// Stops the advert and frees its set when dropped.
pub struct Registration {
    socket: Arc<OwnedFd>,
    handle: u8,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = command(
            &self.socket,
            SET_EXT_ADV_ENABLE,
            &enable(false, self.handle),
        );
        let _ = command(&self.socket, REMOVE_ADV_SET, &[self.handle]);
    }
}

fn start(socket: Arc<OwnedFd>, advert: Advert) -> io::Result<Registration> {
    let sets = command(&socket, READ_NUM_ADV_SETS, &[])?;
    let count = *sets.first().unwrap_or(&0);
    if count == 0 {
        return Err(io::Error::other(
            "the controller has no extended advertising sets",
        ));
    }
    // Handles run 0x00..=0xef.
    let handle = count.min(0xf0) - 1;

    // Each command can cost seconds, so only clear a set an earlier run left
    // behind if the parameters are refused.
    if command(&socket, SET_EXT_ADV_PARAMS, &params(handle)).is_err() {
        let _ = command(&socket, SET_EXT_ADV_ENABLE, &enable(false, handle));
        let _ = command(&socket, REMOVE_ADV_SET, &[handle]);
        command(&socket, SET_EXT_ADV_PARAMS, &params(handle))?;
    }

    command(
        &socket,
        SET_EXT_ADV_DATA,
        &data_command(handle, &adv_data(advert)),
    )?;
    command(&socket, SET_EXT_SCAN_RSP, &data_command(handle, &[]))?;
    command(&socket, SET_EXT_ADV_ENABLE, &enable(true, handle))?;
    Ok(Registration { socket, handle })
}

/// The advertising data: Flags, then Apple's manufacturer data (BLE-1).
fn adv_data(advert: Advert) -> Vec<u8> {
    let manufacturer = advert.manufacturer_data();
    // Type, 2-byte company ID, payload.
    let len = u8::try_from(1 + 2 + manufacturer.len()).expect("advert fits one PDU");
    let mut out = vec![0x02, 0x01, 0x04, len, 0xff];
    out.extend_from_slice(&APPLE_COMPANY_ID.to_le_bytes());
    out.extend_from_slice(&manufacturer);
    out
}

/// LE Set Extended Advertising Parameters: a connectable, scannable legacy
/// PDU (BLE-5) at `INTERVAL_MS`, on all three channels.
fn params(handle: u8) -> Vec<u8> {
    // Units of 0.625 ms.
    let interval = (INTERVAL_MS * 8 / 5).to_le_bytes();
    let mut p = vec![handle];
    p.extend_from_slice(&0x0013u16.to_le_bytes()); // connectable, scannable, legacy
    p.extend_from_slice(&interval[..3]); // minimum
    p.extend_from_slice(&interval[..3]); // maximum
    p.push(0x07); // channels 37, 38, 39
    p.push(0x00); // own address: public
    p.push(0x00); // peer address type
    p.extend_from_slice(&[0; 6]); // peer address
    p.push(0x00); // accept all scans and connections
    p.push(0x7f); // no TX power preference
    p.push(0x01); // primary PHY: 1M
    p.push(0x00); // secondary max skip
    p.push(0x01); // secondary PHY: 1M
    p.push(0x00); // set ID
    p.push(0x00); // no scan request notifications
    p
}

/// LE Set Extended Advertising Data or Scan Response Data, in one piece.
fn data_command(handle: u8, data: &[u8]) -> Vec<u8> {
    let mut p = vec![handle, 0x03, 0x01, data.len() as u8];
    p.extend_from_slice(data);
    p
}

/// LE Set Extended Advertising Enable for one set, with no time limit.
fn enable(on: bool, handle: u8) -> [u8; 6] {
    [u8::from(on), 1, handle, 0, 0, 0]
}

fn controller() -> io::Result<u16> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/sys/class/bluetooth")? {
        let name = entry?.file_name();
        if let Some(n) = name
            .to_str()
            .and_then(|n| n.strip_prefix("hci"))
            .and_then(|n| n.parse::<u16>().ok())
        {
            found.push(n);
        }
    }
    found.sort_unstable();
    found
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Bluetooth controller"))
}

#[allow(unsafe_code)]
fn open() -> io::Result<OwnedFd> {
    let dev = controller()?;
    // SAFETY: socket(2) takes no pointers; the result is checked, and an
    // owned descriptor is made only from a valid one.
    let fd = unsafe {
        let raw = nix::libc::socket(
            AF_BLUETOOTH,
            nix::libc::SOCK_RAW | nix::libc::SOCK_CLOEXEC,
            BTPROTO_HCI,
        );
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(raw)
    };
    // Command Complete and Command Status events only reach us if the
    // filter lets them through.
    let filter = HciFilter {
        type_mask: 1 << HCI_EVENT_PKT,
        event_mask: [u32::MAX; 2],
        opcode: 0,
    };
    // SAFETY: `filter` outlives the call, and the length is its size.
    let rc = unsafe {
        nix::libc::setsockopt(
            fd.as_raw_fd(),
            SOL_HCI,
            HCI_FILTER,
            (&raw const filter).cast(),
            size_of::<HciFilter>() as u32,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let addr = SockaddrHci {
        family: AF_BLUETOOTH as u16,
        dev,
        channel: HCI_CHANNEL_RAW,
    };
    // SAFETY: `addr` outlives the call, and the length is its size.
    let rc = unsafe {
        nix::libc::bind(
            fd.as_raw_fd(),
            (&raw const addr).cast(),
            size_of::<SockaddrHci>() as u32,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Sends one command and returns its return parameters, after the status.
fn command(socket: &OwnedFd, opcode: u16, params: &[u8]) -> io::Result<Vec<u8>> {
    let mut packet = vec![HCI_COMMAND_PKT];
    packet.extend_from_slice(&opcode.to_le_bytes());
    packet.push(u8::try_from(params.len()).map_err(io::Error::other)?);
    packet.extend_from_slice(params);
    write(socket, &packet).map_err(io::Error::from)?;

    let mut buf = [0u8; 260];
    loop {
        let mut fds = [PollFd::new(socket.as_fd(), PollFlags::POLLIN)];
        if poll(&mut fds, PollTimeout::from(COMMAND_TIMEOUT_MS)).map_err(io::Error::from)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no answer to HCI command {opcode:#06x}"),
            ));
        }
        let n = read(socket, &mut buf).map_err(io::Error::from)?;
        match parse_event(&buf[..n], opcode) {
            Some(Ok(rest)) => return Ok(rest),
            Some(Err(status)) => return Err(status_error(opcode, status)),
            None => {}
        }
    }
}

/// `Some` when the event answers `opcode`: the return parameters after the
/// status, or the failing status.
fn parse_event(packet: &[u8], opcode: u16) -> Option<Result<Vec<u8>, u8>> {
    let [HCI_EVENT_PKT, code, _len, body @ ..] = packet else {
        return None;
    };
    let answer = |status: u8, rest: &[u8]| {
        Some(if status == 0 {
            Ok(rest.to_vec())
        } else {
            Err(status)
        })
    };
    match (*code, body) {
        // Packets, opcode, then the status and return parameters.
        (EVT_COMMAND_COMPLETE, [_, lo, hi, status, rest @ ..])
            if u16::from_le_bytes([*lo, *hi]) == opcode =>
        {
            answer(*status, rest)
        }
        // Status, packets, opcode. Only a failure ends the command here: its
        // Command Complete is still to come otherwise.
        (EVT_COMMAND_STATUS, [status, _, lo, hi, ..])
            if u16::from_le_bytes([*lo, *hi]) == opcode && *status != 0 =>
        {
            answer(*status, &[])
        }
        _ => None,
    }
}

fn status_error(opcode: u16, status: u8) -> io::Error {
    let hint = match status {
        0x01 => " (unknown command)",
        0x0c => " (command disallowed: another Bluetooth stack may be using the controller)",
        0x11 => " (unsupported feature or parameter value)",
        0x12 => " (invalid parameters)",
        _ => "",
    };
    io::Error::other(format!(
        "HCI command {opcode:#06x} failed with status {status:#04x}{hint}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: BLE-1, BLE-2, BLE-5
    #[test]
    fn advert_data_holds_apples_airdrop_tlv() {
        let data = adv_data(Advert::anonymous([0xa1, 0xb2, 0xc3]));
        assert_eq!(&data[..3], &[0x02, 0x01, 0x04]); // Flags
        assert_eq!(data[3] as usize, data.len() - 4); // manufacturer data length
        assert_eq!(&data[4..7], &[0xff, 0x4c, 0x00]); // Apple's company ID
        assert_eq!(&data[7..9], &[0x05, 0x12]); // AirDrop TLV
        assert!(data.len() <= 31, "one legacy PDU");
    }

    // spec: BLE-5
    #[test]
    fn params_are_25_bytes_at_100_ms() {
        let p = params(0x07);
        assert_eq!(p.len(), 25);
        assert_eq!(p[0], 0x07);
        assert_eq!(&p[1..3], &[0x13, 0x00]);
        assert_eq!(&p[3..6], &[160, 0, 0]); // 100 ms in 0.625 ms units
        assert_eq!(&p[6..9], &[160, 0, 0]);
    }

    #[test]
    fn enable_and_data_layout() {
        assert_eq!(enable(true, 3), [1, 1, 3, 0, 0, 0]);
        assert_eq!(data_command(3, &[9, 8]), vec![3, 3, 1, 2, 9, 8]);
    }

    #[test]
    fn events_are_matched_by_opcode() {
        let op = READ_NUM_ADV_SETS;
        let [lo, hi] = op.to_le_bytes();
        let complete = |status: u8| [0x04, 0x0e, 5, 1, lo, hi, status, 8];
        assert_eq!(parse_event(&complete(0), op), Some(Ok(vec![8])));
        assert_eq!(parse_event(&complete(0x0c), op), Some(Err(0x0c)));
        // Another command's answer, and a successful Command Status.
        assert_eq!(parse_event(&complete(0), SET_EXT_ADV_DATA), None);
        assert_eq!(parse_event(&[0x04, 0x0f, 4, 0, 1, lo, hi], op), None);
        assert_eq!(
            parse_event(&[0x04, 0x0f, 4, 1, 1, lo, hi], op),
            Some(Err(1))
        );
    }
}
