//! Radiotap (radiotap.org), the header Linux puts before every frame a
//! monitor interface captures and expects before every frame injected
//! through one: what owly-awdl's driver reads from it, and writes.

use owly_awdl::TxRate;

/// What a received frame's radiotap header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rx<'a> {
    /// The 802.11 frame, FCS stripped.
    pub frame: &'a [u8],
    /// Antenna signal, dBm.
    pub rssi: Option<i8>,
    /// The frequency it was heard on, MHz.
    pub freq: Option<u16>,
}

const FLAGS: u32 = 1;
const RATE: u32 = 2;
const CHANNEL: u32 = 3;
const DBM_ANTSIGNAL: u32 = 5;
const TX_FLAGS: u32 = 15;
const MCS: u32 = 19;
const EXT: u32 = 31;

const F_FCS: u8 = 0x10;
const F_BADFCS: u8 = 0x40;
const F_TX_NOACK: u16 = 0x0008;

/// Alignment and size of the fields before the antenna signal, which are
/// all that's read: TSFT, flags, rate, channel, FHSS.
const FIELDS: [(usize, usize); 5] = [(8, 8), (1, 1), (1, 1), (2, 4), (1, 2)];

/// Reads a captured frame's radiotap header. `None` for a frame that's
/// malformed or failed its FCS.
pub fn parse(buf: &[u8]) -> Option<Rx<'_>> {
    if buf.len() < 8 || buf[0] != 0 {
        return None;
    }
    let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if len < 8 || len > buf.len() {
        return None;
    }
    let header = &buf[..len];
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(header.get(at..at + 4)?.try_into().ok()?))
    };
    let present = word(4)?;
    // The data follows every present word; extensions only add fields
    // past those read here.
    let mut at = 4;
    while word(at)? & (1 << EXT) != 0 {
        at += 4;
    }
    at += 4;
    let (mut flags, mut freq, mut rssi) = (0u8, None, None);
    for (bit, (align, size)) in FIELDS.iter().enumerate() {
        if present & (1 << bit) == 0 {
            continue;
        }
        at = at.next_multiple_of(*align);
        let f = header.get(at..at + size)?;
        match bit as u32 {
            FLAGS => flags = f[0],
            CHANNEL => freq = Some(u16::from_le_bytes([f[0], f[1]])),
            _ => {}
        }
        at += size;
    }
    if present & (1 << DBM_ANTSIGNAL) != 0 {
        rssi = Some(*header.get(at)? as i8);
    }
    if flags & F_BADFCS != 0 {
        return None;
    }
    let mut frame = &buf[len..];
    if flags & F_FCS != 0 || ends_in_fcs(frame) {
        frame = frame.get(..frame.len().checked_sub(4)?)?;
    }
    Some(Rx { frame, rssi, freq })
}

/// ath12k (WCN7850) appends the FCS without setting radiotap's FCS flag.
fn ends_in_fcs(frame: &[u8]) -> bool {
    let Some(n) = frame.len().checked_sub(4).filter(|n| *n >= 10) else {
        return false;
    };
    let (body, fcs) = frame.split_at(n);
    crc32(body).to_le_bytes() == fcs
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// A received frame's radiotap header with only the channel it was heard
/// on and its signal strength: what the capture corpus keeps.
pub fn rx_header(freq: Option<u16>, rssi: Option<i8>) -> Vec<u8> {
    let mut present = 0u32;
    let mut fields = Vec::with_capacity(5);
    if let Some(f) = freq {
        present |= 1 << CHANNEL;
        fields.extend_from_slice(&f.to_le_bytes());
        // 2 GHz or 5 GHz, OFDM.
        let flags: u16 = if f < 3000 {
            0x0080 | 0x0040
        } else {
            0x0100 | 0x0040
        };
        fields.extend_from_slice(&flags.to_le_bytes());
    }
    if let Some(r) = rssi {
        present |= 1 << DBM_ANTSIGNAL;
        fields.push(r as u8);
    }
    let len = 8 + fields.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.extend_from_slice(&present.to_le_bytes());
    out.extend_from_slice(&fields);
    out
}

/// A radiotap header for injecting a frame at `rate`, without ACK and
/// retries when `no_ack`, as legacy wrote it.
pub fn tx_header(rate: TxRate, no_ack: bool) -> Vec<u8> {
    let mut present = 0u32;
    let mut fields = Vec::with_capacity(8);
    match rate {
        TxRate::Legacy(r) => {
            present |= 1 << RATE;
            fields.push(r);
            if no_ack {
                // TX flags are a u16 at an even offset: the header is 8.
                fields.push(0);
                present |= 1 << TX_FLAGS;
                fields.extend_from_slice(&F_TX_NOACK.to_le_bytes());
            }
        }
        TxRate::Ht { mcs, sgi } => {
            if no_ack {
                present |= 1 << TX_FLAGS;
                fields.extend_from_slice(&F_TX_NOACK.to_le_bytes());
            }
            present |= 1 << MCS;
            // Known: bandwidth, MCS, guard interval. 20 MHz.
            fields.extend_from_slice(&[0x07, if sgi { 0x04 } else { 0 }, mcs]);
        }
    }
    let len = 8 + fields.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.extend_from_slice(&present.to_le_bytes());
    out.extend_from_slice(&fields);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_flags_channel_and_signal() {
        // mac80211's usual header: TSFT, flags, rate, channel, signal, then
        // an extension word for per-antenna fields.
        let mut h = vec![0u8, 0, 0, 0];
        let present: u32 =
            1 | 1 << FLAGS | 1 << RATE | 1 << CHANNEL | 1 << DBM_ANTSIGNAL | 1 << 29 | 1 << EXT;
        h.extend_from_slice(&present.to_le_bytes());
        h.extend_from_slice(&0x20u32.to_le_bytes()); // second word
        h.extend_from_slice(&[0; 4]); // pad TSFT to 8
        h.extend_from_slice(&7u64.to_le_bytes());
        h.push(F_FCS);
        h.push(24);
        h.extend_from_slice(&5745u16.to_le_bytes());
        h.extend_from_slice(&0x0140u16.to_le_bytes());
        h.push(-52i8 as u8);
        h.push(0); // what the extension word announces
        let len = h.len() as u16;
        h[2..4].copy_from_slice(&len.to_le_bytes());
        let mut buf = h.clone();
        buf.extend_from_slice(b"frame");
        buf.extend_from_slice(&[1, 2, 3, 4]); // FCS
        let rx = parse(&buf).unwrap();
        assert_eq!(rx.frame, b"frame");
        assert_eq!(rx.rssi, Some(-52));
        assert_eq!(rx.freq, Some(5745));

        buf[h.len() - 8] |= F_BADFCS;
        assert_eq!(parse(&buf), None, "bad FCS");
        assert_eq!(parse(&buf[..6]), None);
        let mut long = buf.clone();
        long[2] = 200;
        assert_eq!(parse(&long), None);
    }

    #[test]
    fn strips_an_fcs_the_flags_dont_mention() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        let frame = b"an 802.11 frame".to_vec();
        let mut with_fcs = rx_header(Some(2437), Some(-30));
        with_fcs.extend_from_slice(&frame);
        with_fcs.extend_from_slice(&crc32(&frame).to_le_bytes());
        assert_eq!(parse(&with_fcs).unwrap().frame, &frame[..]);

        let mut without = rx_header(Some(2437), Some(-30));
        without.extend_from_slice(&frame);
        assert_eq!(parse(&without).unwrap().frame, &frame[..]);
    }

    #[test]
    fn rx_headers_read_back() {
        for (freq, rssi) in [
            (Some(5220), Some(-61)),
            (Some(2437), None),
            (None, Some(-40)),
            (None, None),
        ] {
            let mut f = rx_header(freq, rssi);
            f.extend_from_slice(b"x");
            let rx = parse(&f).unwrap();
            assert_eq!((rx.frame, rx.freq, rx.rssi), (&b"x"[..], freq, rssi));
        }
    }

    #[test]
    fn writes_owls_tx_headers() {
        assert_eq!(
            tx_header(TxRate::BASIC, false),
            [0, 0, 9, 0, 0x04, 0, 0, 0, 24]
        );
        assert_eq!(
            tx_header(TxRate::BASIC, true),
            [0, 0, 12, 0, 0x04, 0x80, 0, 0, 24, 0, 0x08, 0]
        );
        assert_eq!(
            tx_header(TxRate::Ht { mcs: 7, sgi: true }, true),
            [0, 0, 13, 0, 0, 0x80, 0x08, 0, 0x08, 0, 0x07, 0x04, 7]
        );
        // What it writes, it reads.
        let mut f = tx_header(TxRate::Ht { mcs: 3, sgi: false }, false);
        f.extend_from_slice(b"x");
        assert_eq!(parse(&f).unwrap().frame, b"x");
    }
}
