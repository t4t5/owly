//! Minimal, safe `DLT_IEEE802_11_RADIO` (linktype `127`) Radiotap + PCAP codec.

use std::io::{self, Read, Write};

/// `DLT_IEEE802_11_RADIO` link-layer header type in standard libpcap files.
pub const LINKTYPE_RADIOTAP: u32 = 127;

const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;

/// Builds a minimal Radiotap header, optionally embedding the 1-byte dBm Antenna Signal field.
pub fn tx_radiotap(rssi_dbm: Option<i8>) -> Vec<u8> {
    match rssi_dbm {
        Some(dbm) => vec![
            0x00, // revision
            0x00, // pad
            0x09, 0x00, // length = 9 bytes (8B header + 1B dBm signal at align 1)
            0x20, 0x00, 0x00, 0x00, // present bit 5: dBm Antenna Signal
            dbm as u8,
        ],
        None => vec![
            0x00, 0x00, 0x08, 0x00, // 8-byte empty Radiotap header
            0x00, 0x00, 0x00, 0x00,
        ],
    }
}

/// Strips a Radiotap header from `datagram`, returning `(frame_without_radiotap, rssi_dbm)`.
pub fn parse_radiotap(datagram: &[u8]) -> Option<(&[u8], Option<i8>)> {
    if datagram.len() < 8 || datagram[0] != 0 {
        return None;
    }
    let rt_len = usize::from(u16::from_le_bytes([datagram[2], datagram[3]]));
    if rt_len < 8 || datagram.len() < rt_len {
        return None;
    }
    let present = u32::from_le_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
    // Fast-path our compact 9-byte TX header: only bit 5 (0x20) set -> dBm at offset 8.
    let rssi = if present == 0x20 && rt_len >= 9 {
        Some(datagram[8] as i8)
    } else {
        None
    };
    Some((&datagram[rt_len..], rssi))
}

/// Streaming standard libpcap writer (`DLT_IEEE802_11_RADIO`).
pub struct PcapWriter<W: Write> {
    writer: W,
    packets_written: u64,
}

impl<W: Write> PcapWriter<W> {
    /// Writes the 24-byte global PCAP header immediately.
    pub fn new(mut writer: W) -> io::Result<Self> {
        let mut header = [0u8; 24];
        header[0..4].copy_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        header[4..6].copy_from_slice(&2u16.to_le_bytes());
        header[6..8].copy_from_slice(&4u16.to_le_bytes());
        header[16..20].copy_from_slice(&65535u32.to_le_bytes());
        header[20..24].copy_from_slice(&LINKTYPE_RADIOTAP.to_le_bytes());
        writer.write_all(&header)?;
        Ok(Self {
            writer,
            packets_written: 0,
        })
    }

    /// Writes one raw 802.11 MAC frame (no FCS) wrapped in a minimal Radiotap header.
    pub fn write_80211_frame(
        &mut self,
        ts_us: u64,
        rssi_dbm: Option<i8>,
        frame: &[u8],
    ) -> io::Result<()> {
        let rt = tx_radiotap(rssi_dbm);
        let total_len = rt.len() + frame.len();
        let cap_len = u32::try_from(total_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large for pcap"))?;
        let secs = u32::try_from(ts_us / 1_000_000).unwrap_or(u32::MAX);
        let usecs = (ts_us % 1_000_000) as u32;

        let mut rec = [0u8; 16];
        rec[0..4].copy_from_slice(&secs.to_le_bytes());
        rec[4..8].copy_from_slice(&usecs.to_le_bytes());
        rec[8..12].copy_from_slice(&cap_len.to_le_bytes());
        rec[12..16].copy_from_slice(&cap_len.to_le_bytes());
        self.writer.write_all(&rec)?;
        self.writer.write_all(&rt)?;
        self.writer.write_all(frame)?;
        self.packets_written = self.packets_written.saturating_add(1);
        Ok(())
    }

    pub fn packets_written(&self) -> u64 {
        self.packets_written
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    pub fn into_inner(mut self) -> io::Result<W> {
        self.writer.flush()?;
        Ok(self.writer)
    }
}

/// Reads all packets from a little-endian libpcap stream, returning `(ts_us, payload)`.
pub fn read_pcap<R: Read>(mut reader: R) -> io::Result<Vec<(u64, Vec<u8>)>> {
    let mut global = [0u8; 24];
    reader.read_exact(&mut global)?;
    let magic = u32::from_le_bytes([global[0], global[1], global[2], global[3]]);
    if magic != PCAP_MAGIC_LE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected pcap magic {magic:#010x}"),
        ));
    }
    let version = (
        u16::from_le_bytes([global[4], global[5]]),
        u16::from_le_bytes([global[6], global[7]]),
    );
    if version != (2, 4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported pcap version {}.{}", version.0, version.1),
        ));
    }
    let linktype = u32::from_le_bytes([global[20], global[21], global[22], global[23]]);
    if linktype != LINKTYPE_RADIOTAP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected pcap linktype {linktype}"),
        ));
    }
    let mut packets = Vec::new();
    let mut rec = [0u8; 16];
    loop {
        match reader.read(&mut rec[..1]) {
            Ok(0) => break,
            Ok(1) => reader.read_exact(&mut rec[1..])?,
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        let secs = u64::from(u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]));
        let usecs = u64::from(u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]));
        let incl = usize::try_from(u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pcap length overflow"))?;
        if incl > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pcap record exceeds 1 MiB limit",
            ));
        }
        let mut data = vec![0u8; incl];
        reader.read_exact(&mut data)?;
        packets.push((secs * 1_000_000 + usecs, data));
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_truncated_record_header() {
        let writer = PcapWriter::new(Vec::new()).unwrap();
        let mut bytes = writer.into_inner().unwrap();
        bytes.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            read_pcap(bytes.as_slice()).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn rejects_a_non_radiotap_capture() {
        let writer = PcapWriter::new(Vec::new()).unwrap();
        let mut bytes = writer.into_inner().unwrap();
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            read_pcap(bytes.as_slice()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
