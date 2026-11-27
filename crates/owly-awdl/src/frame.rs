//! 802.11 framing: the MAC header, AWDL action frames (AWDL-3), data frames
//! and A-MSDUs (AWDL-13, AWDL-14), and Block Ack session setup (AWDL-15).
//!
//! Frames here start at the 802.11 MAC header and carry no FCS: the radio
//! adds it, and the host strips it (and any radiotap or similar header)
//! from what it receives.

use alloc::vec::Vec;

use crate::rate::TxRate;
use crate::wire::{Bytes, Put};
use crate::{BSSID, Error, MacAddr, OUI};

/// A frame for the radio to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// From the 802.11 MAC header on, without FCS.
    pub bytes: Vec<u8>,
    /// Its receiver: a peer, or broadcast.
    pub to: MacAddr,
    pub rate: TxRate,
    /// Sent once, with no wait for an ACK and no retries.
    pub no_ack: bool,
}

impl Frame {
    /// A management action frame (a PSF, MIF or Block Ack answer), rather
    /// than data.
    pub fn is_action(&self) -> bool {
        self.bytes.len() >= 2
            && u16::from_le_bytes([self.bytes[0], self.bytes[1]]) & fc::TYPE_SUBTYPE == fc::ACTION
    }
}

/// Frame control values, type and subtype.
pub mod fc {
    pub const ACTION: u16 = 0x00d0;
    pub const DATA: u16 = 0x0008;
    pub const QOS_DATA: u16 = 0x0088;
    pub const TYPE_SUBTYPE: u16 = 0x00fc;
    pub const TYPE: u16 = 0x000c;
    pub const TYPE_MANAGEMENT: u16 = 0x0000;
    pub const TYPE_DATA: u16 = 0x0008;
    pub const TO_DS: u16 = 0x0100;
    pub const FROM_DS: u16 = 0x0200;
    pub const MORE_FRAGMENTS: u16 = 0x0400;
    pub const RETRY: u16 = 0x0800;
    pub const PROTECTED: u16 = 0x4000;
}

/// The 802.11 MAC header's length, without QoS control.
pub const HEADER_LEN: usize = 24;
/// The AWDL action header's length (AWDL-3).
pub const ACTION_HEADER_LEN: usize = 16;
/// LLC/SNAP and the AWDL data header (AWDL-13).
pub const DATA_HEADER_LEN: usize = 16;
/// AWDL-14: the most A-MSDU subframes unpacked from one frame, as legacy
/// patch `owl-08` bounded them.
pub const MAX_AMSDU_SUBFRAMES: usize = 16;

/// The vendor-specific action category (AWDL-3).
const CATEGORY_VENDOR: u8 = 127;
/// AWDL's type within Apple's OUI.
const AWDL_TYPE: u8 = 8;
/// AWDL 1.0, major in the high nibble: what the action header carries.
const AWDL_VERSION_COMPAT: u8 = 0x10;
/// The Block Ack action category, and its ADDBA request and response.
const CATEGORY_BLOCK_ACK: u8 = 3;
const ADDBA_REQUEST: u8 = 0;
const ADDBA_RESPONSE: u8 = 1;

/// The SNAP header AWDL data frames carry (AWDL-13).
const LLC_SNAP: [u8; 8] = [0xaa, 0xaa, 0x03, OUI[0], OUI[1], OUI[2], 0x08, 0x00];
const DATA_HEAD: u16 = 0x0403;
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Action frame subtypes (AWDL-3).
pub mod subtype {
    /// Periodic Synchronization Frame.
    pub const PSF: u8 = 0;
    /// Master Indication Frame.
    pub const MIF: u8 = 3;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub fc: u16,
    /// Address 1: the receiver.
    pub dst: MacAddr,
    /// Address 2: the transmitter.
    pub src: MacAddr,
    pub bssid: MacAddr,
    /// The 12-bit sequence number.
    pub seq: u16,
}

/// What a received frame is, as far as AWDL cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received<'a> {
    /// An AWDL PSF or MIF.
    Action {
        header: Header,
        subtype: u8,
        /// The sender's clock when it sent the frame, and when it meant to.
        phy_tx: u32,
        target_tx: u32,
        tlvs: &'a [u8],
    },
    /// A request for a Block Ack session (AWDL-15).
    AddBaRequest {
        header: Header,
        token: u8,
        params: u16,
        timeout: u16,
    },
    /// An AWDL data frame: one MSDU, or an A-MSDU.
    Data {
        header: Header,
        amsdu: bool,
        body: &'a [u8],
    },
    /// Anything else on the air.
    Other,
}

/// A frame's three-address MAC header, if it has one.
pub fn parse_header(bytes: &[u8]) -> Option<Header> {
    let b = Bytes(bytes);
    Some(Header {
        fc: b.le16(0).ok()?,
        dst: b.mac(4).ok()?,
        src: b.mac(10).ok()?,
        bssid: b.mac(16).ok()?,
        seq: b.le16(22).ok()? >> 4,
    })
}

/// Reads a frame's MAC header and classifies it.
pub fn parse(bytes: &[u8]) -> Result<Received<'_>, Error> {
    let b = Bytes(bytes);
    // Control frames (ACK, RTS, CTS, Block Ack) and extension frames have
    // no three-address header, and a monitor hears plenty of them: they're
    // not AWDL, not malformed.
    let t = b.le16(0)? & fc::TYPE;
    if t != fc::TYPE_MANAGEMENT && t != fc::TYPE_DATA {
        return Ok(Received::Other);
    }
    let header = parse_header(bytes).ok_or(Error::Truncated)?;
    let fc = header.fc;
    let frag = b.le16(22)? & 0xf;
    if fc & (fc::PROTECTED | fc::MORE_FRAGMENTS) != 0 || frag != 0 {
        return Ok(Received::Other);
    }
    let body = b.rest(HEADER_LEN)?;
    match fc & fc::TYPE_SUBTYPE {
        fc::ACTION => action(header, body),
        t @ (fc::DATA | fc::QOS_DATA) => {
            // AWDL-1: AWDL data is between peers on AWDL's BSSID, neither
            // to nor from a distribution system.
            if fc & (fc::TO_DS | fc::FROM_DS) != 0 || header.bssid != BSSID {
                return Ok(Received::Other);
            }
            if t == fc::QOS_DATA {
                let qos = Bytes(body).le16(0)?;
                Ok(Received::Data {
                    header,
                    amsdu: qos & 0x0080 != 0,
                    body: &body[2..],
                })
            } else {
                Ok(Received::Data {
                    header,
                    amsdu: false,
                    body,
                })
            }
        }
        _ => Ok(Received::Other),
    }
}

fn action(header: Header, body: &[u8]) -> Result<Received<'_>, Error> {
    let b = Bytes(body);
    if body.is_empty() {
        return Ok(Received::Other);
    }
    if b.u8(0)? == CATEGORY_BLOCK_ACK && b.u8(1)? == ADDBA_REQUEST {
        return Ok(Received::AddBaRequest {
            header,
            token: b.u8(2)?,
            params: b.le16(3)?,
            timeout: b.le16(5)?,
        });
    }
    if body.len() < ACTION_HEADER_LEN
        || body[0] != CATEGORY_VENDOR
        || body[1..4] != OUI
        || body[4] != AWDL_TYPE
        || body[5] != AWDL_VERSION_COMPAT
    {
        return Ok(Received::Other);
    }
    let subtype = body[6];
    if subtype != subtype::PSF && subtype != subtype::MIF {
        return Ok(Received::Other);
    }
    Ok(Received::Action {
        header,
        subtype,
        phy_tx: b.le32(8)?,
        target_tx: b.le32(12)?,
        tlvs: &body[ACTION_HEADER_LEN..],
    })
}

/// One packet out of a data frame, with the addresses it travels between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msdu<'a> {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

/// The packets in a data frame's body (AWDL-13). An A-MSDU's subframes each
/// carry their own addresses; there may be at most
/// [`MAX_AMSDU_SUBFRAMES`] (AWDL-14).
pub fn msdus<'a>(header: &Header, amsdu: bool, body: &'a [u8]) -> Result<Vec<Msdu<'a>>, Error> {
    if !amsdu {
        return Ok(Vec::from([msdu(header.dst, header.src, body)?]));
    }
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        if out.len() == MAX_AMSDU_SUBFRAMES {
            return Err(Error::Malformed("too many A-MSDU subframes"));
        }
        let b = Bytes(rest);
        let dst = b.mac(0)?;
        let src = b.mac(6)?;
        let len = b.be16(12)? as usize;
        out.push(msdu(dst, src, b.slice(14, len)?)?);
        rest = &rest[14 + len..];
        if !rest.is_empty() {
            // Each subframe but the last is padded to 4 bytes.
            let pad = (4 - (14 + len) % 4) % 4;
            rest = rest.get(pad..).ok_or(Error::Truncated)?;
        }
    }
    Ok(out)
}

fn msdu(dst: MacAddr, src: MacAddr, body: &[u8]) -> Result<Msdu<'_>, Error> {
    let b = Bytes(body);
    let llc = b.slice(0, 8)?;
    // As legacy checked it: SNAP, and AWDL's protocol ID. The OUI isn't.
    if llc[..3] != LLC_SNAP[..3] || llc[6..] != LLC_SNAP[6..] {
        return Err(Error::Malformed("not AWDL's LLC/SNAP header"));
    }
    Ok(Msdu {
        dst,
        src,
        ethertype: b.be16(14)?,
        payload: b.rest(DATA_HEADER_LEN)?,
    })
}

/// Writes a MAC header on AWDL's BSSID (AWDL-1).
pub fn put_header(out: &mut Vec<u8>, fc: u16, dst: MacAddr, src: MacAddr, seq: u16) {
    out.le16(fc);
    out.le16(0); // duration
    out.mac(dst);
    out.mac(src);
    out.mac(BSSID);
    out.le16((seq & 0x0fff) << 4);
}

/// An AWDL action frame (AWDL-3): the header, stamped with `time`, the
/// sender's clock in µs, then TLVs from `tlvs`.
pub fn action_frame(
    src: MacAddr,
    seq: u16,
    subtype: u8,
    time: u32,
    tlvs: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    put_header(&mut out, fc::ACTION, MacAddr::BROADCAST, src, seq);
    out.u8(CATEGORY_VENDOR);
    out.extend_from_slice(&OUI);
    out.u8(AWDL_TYPE);
    out.u8(AWDL_VERSION_COMPAT);
    out.u8(subtype);
    out.u8(0);
    out.le32(time); // PHY TX time
    out.le32(time); // target TX time
    tlvs(&mut out);
    out
}

fn put_msdu(out: &mut Vec<u8>, awdl_seq: u16, payload: &[u8]) {
    out.extend_from_slice(&LLC_SNAP);
    out.le16(DATA_HEAD);
    out.le16(awdl_seq);
    out.le16(0);
    out.be16(ETHERTYPE_IPV6);
    out.extend_from_slice(payload);
}

/// AWDL-13: a data frame carrying one IPv6 packet.
pub fn data_frame(src: MacAddr, dst: MacAddr, seq: u16, awdl_seq: u16, packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + DATA_HEADER_LEN + packet.len());
    put_header(&mut out, fc::DATA, dst, src, seq);
    put_msdu(&mut out, awdl_seq, packet);
    out
}

/// QoS control: TID 0, Ack Policy No Ack.
const QOS_NO_ACK: u16 = 0x0020;

/// AWDL-13: a QoS data frame (TID 0) carrying one IPv6 packet, whose Ack
/// Policy asks for no ACK. That reaches the hardware with the frame, where
/// radiotap's no-ACK flag may not: iwlwifi's newer TX path (AX210 and
/// later) drops it, and the firmware then retries a frame the peer left
/// its channel without answering, holding up every frame behind it.
pub fn no_ack_data_frame(
    src: MacAddr,
    dst: MacAddr,
    seq: u16,
    awdl_seq: u16,
    packet: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + 2 + DATA_HEADER_LEN + packet.len());
    put_header(&mut out, fc::QOS_DATA, dst, src, seq);
    out.le16(QOS_NO_ACK);
    put_msdu(&mut out, awdl_seq, packet);
    out
}

/// The bytes one packet adds to an A-MSDU, less the up to 3 bytes of
/// padding that may come before it.
pub fn amsdu_subframe_len(packet_len: usize) -> usize {
    14 + DATA_HEADER_LEN + packet_len
}

/// An A-MSDU of IPv6 packets to one peer, in a QoS data frame (TID 0). Its
/// subframes take consecutive AWDL sequence numbers from `awdl_seq`.
pub fn amsdu_frame(
    src: MacAddr,
    dst: MacAddr,
    seq: u16,
    awdl_seq: u16,
    packets: &[&[u8]],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    put_header(&mut out, fc::QOS_DATA, dst, src, seq);
    out.le16(0x0080); // QoS control: A-MSDU present
    for (i, p) in packets.iter().enumerate() {
        if i > 0 {
            while !(out.len() - HEADER_LEN - 2).is_multiple_of(4) {
                out.u8(0);
            }
        }
        out.mac(dst);
        out.mac(src);
        out.be16((DATA_HEADER_LEN + p.len()) as u16);
        put_msdu(&mut out, awdl_seq.wrapping_add(i as u16), p);
    }
    out
}

/// AWDL-15: an ADDBA response accepting a request, as legacy patch
/// `owl-10` answers it: immediate Block Ack, the requested TID, no A-MSDU
/// inside A-MPDUs, a window of at most 64.
pub fn addba_response(
    src: MacAddr,
    dst: MacAddr,
    seq: u16,
    token: u8,
    requested: u16,
    timeout: u16,
) -> Vec<u8> {
    let mut window = (requested >> 6) & 0x3ff;
    if window == 0 || window > 64 {
        window = 64;
    }
    let params = (requested & 0x003c) | 0x0002 | (window << 6);
    let mut out = Vec::with_capacity(HEADER_LEN + 9);
    put_header(&mut out, fc::ACTION, dst, src, seq);
    out.u8(CATEGORY_BLOCK_ACK);
    out.u8(ADDBA_RESPONSE);
    out.u8(token);
    out.le16(0); // success
    out.le16(params);
    out.le16(timeout);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const A: MacAddr = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
    const B: MacAddr = MacAddr([0x86, 0x08, 0x04, 0x8a, 0x2b, 0xf4]);

    // spec: AWDL-13
    #[test]
    fn a_no_ack_data_frame_is_qos_data_asking_for_no_ack() {
        let packet = [0x60, 0, 0, 0, 0, 0, 0x3b, 0x40];
        let frame = no_ack_data_frame(A, B, 0x123, 7, &packet);
        assert_eq!(&frame[..2], &[0x88, 0x00], "QoS data");
        assert_eq!(
            &frame[HEADER_LEN..HEADER_LEN + 2],
            &[0x20, 0x00],
            "TID 0, No Ack"
        );
        let plain = data_frame(A, B, 0x123, 7, &packet);
        assert_eq!(&frame[2..HEADER_LEN], &plain[2..HEADER_LEN]);
        assert_eq!(&frame[HEADER_LEN + 2..], &plain[HEADER_LEN..]);
        let Received::Data {
            header,
            amsdu,
            body,
        } = parse(&frame).unwrap()
        else {
            panic!("not data");
        };
        assert!(!amsdu);
        let m = msdus(&header, amsdu, body).unwrap();
        assert_eq!((m.len(), m[0].dst, m[0].payload), (1, B, &packet[..]));
    }

    // spec: AWDL-13, T-AWDL-2
    #[test]
    fn a_data_frame_matches_the_golden_bytes() {
        let packet = [0x60, 0, 0, 0, 0, 0, 0x3b, 0x40];
        let frame = data_frame(A, B, 0x123, 7, &packet);
        #[rustfmt::skip]
        let golden = vec![
            0x08, 0x00, 0x00, 0x00,                         // data, duration 0
            0x86, 0x08, 0x04, 0x8a, 0x2b, 0xf4,             // receiver
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01,             // transmitter
            0x00, 0x25, 0x00, 0xff, 0x94, 0x73,             // AWDL's BSSID
            0x30, 0x12,                                     // sequence 0x123
            0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00, // LLC/SNAP, AWDL
            0x03, 0x04, 0x07, 0x00, 0x00, 0x00, 0x86, 0xdd, // head, seq, pad, IPv6
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x40, // the packet
        ];
        assert_eq!(frame, golden);
        let Received::Data {
            header,
            amsdu,
            body,
        } = parse(&frame).unwrap()
        else {
            panic!("not data");
        };
        assert_eq!(
            (header.src, header.dst, header.seq, amsdu),
            (A, B, 0x123, false)
        );
        let m = msdus(&header, amsdu, body).unwrap();
        assert_eq!(
            m,
            vec![Msdu {
                dst: B,
                src: A,
                ethertype: 0x86dd,
                payload: &packet
            }]
        );
    }

    // spec: AWDL-3
    #[test]
    fn action_frames_round_trip() {
        let frame = action_frame(A, 5, subtype::MIF, 0xdead_beef, |out| {
            out.extend_from_slice(&[21, 2, 0, 0x34, 1]);
        });
        assert_eq!(
            frame[HEADER_LEN..HEADER_LEN + 8],
            [127, 0x00, 0x17, 0xf2, 8, 0x10, 3, 0]
        );
        match parse(&frame).unwrap() {
            Received::Action {
                header,
                subtype,
                phy_tx,
                target_tx,
                tlvs,
            } => {
                assert_eq!((header.src, header.dst), (A, MacAddr::BROADCAST));
                assert_eq!(subtype, subtype::MIF);
                assert_eq!((phy_tx, target_tx), (0xdead_beef, 0xdead_beef));
                assert_eq!(tlvs, [21, 2, 0, 0x34, 1]);
            }
            other => panic!("{other:?}"),
        }
        // Another vendor's action frame, or another AWDL subtype, isn't ours.
        let mut other = frame.clone();
        other[HEADER_LEN + 3] = 0xf3;
        assert_eq!(parse(&other), Ok(Received::Other));
        let mut other = frame;
        other[HEADER_LEN + 6] = 1;
        assert_eq!(parse(&other), Ok(Received::Other));
    }

    // spec: AWDL-14
    #[test]
    fn amsdus_unpack_with_a_bound() {
        let p1 = [0x60, 1, 2];
        let p2 = [0x60, 3, 4, 5, 6];
        let frame = amsdu_frame(B, A, 1, 10, &[&p1, &p2]);
        let Received::Data {
            header,
            amsdu,
            body,
        } = parse(&frame).unwrap()
        else {
            panic!("not data");
        };
        assert!(amsdu);
        let m = msdus(&header, amsdu, body).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!((m[0].src, m[0].dst, m[0].payload), (B, A, &p1[..]));
        assert_eq!(m[1].payload, &p2[..]);

        let many: Vec<&[u8]> = vec![&p1; MAX_AMSDU_SUBFRAMES + 1];
        let frame = amsdu_frame(B, A, 1, 10, &many);
        let Received::Data {
            header,
            amsdu,
            body,
        } = parse(&frame).unwrap()
        else {
            panic!("not data");
        };
        assert!(msdus(&header, amsdu, body).is_err());
        let ok = amsdu_frame(B, A, 1, 10, &many[..MAX_AMSDU_SUBFRAMES]);
        let Received::Data {
            header,
            amsdu,
            body,
        } = parse(&ok).unwrap()
        else {
            panic!("not data");
        };
        assert_eq!(
            msdus(&header, amsdu, body).unwrap().len(),
            MAX_AMSDU_SUBFRAMES
        );
        // A subframe longer than what's left.
        let mut short = ok.clone();
        short.truncate(short.len() - 1);
        let Received::Data {
            header,
            amsdu,
            body,
        } = parse(&short).unwrap()
        else {
            panic!("not data");
        };
        assert_eq!(msdus(&header, amsdu, body), Err(Error::Truncated));
    }

    #[test]
    fn control_frames_arent_awdl_or_malformed() {
        // An ACK, 10 bytes: frame control, duration, receiver.
        let ack = [0xd4, 0x00, 0x00, 0x00, 0x86, 0x08, 0x04, 0x8a, 0x2b, 0xf4];
        assert_eq!(parse(&ack), Ok(Received::Other));
        // An RTS, 16 bytes, with a transmitter too.
        let mut rts = vec![0xb4, 0x00, 0x00, 0x00];
        rts.extend_from_slice(&B.0);
        rts.extend_from_slice(&A.0);
        assert_eq!(parse(&rts), Ok(Received::Other));
        // A management frame that short still is.
        let mut short = vec![0xd0, 0x00, 0x00, 0x00];
        short.extend_from_slice(&B.0);
        assert_eq!(parse(&short), Err(Error::Truncated));
        // An action frame with no category.
        let mut empty = Vec::new();
        put_header(&mut empty, fc::ACTION, B, A, 0);
        assert_eq!(parse(&empty), Ok(Received::Other));
    }

    #[test]
    fn data_off_awdls_bssid_or_through_an_ap_isnt_awdl() {
        let mut frame = data_frame(A, B, 0, 0, &[0x60]);
        frame[1] = 0x01; // to DS
        assert_eq!(parse(&frame), Ok(Received::Other));
        let mut frame = data_frame(A, B, 0, 0, &[0x60]);
        frame[16] = 0x02;
        assert_eq!(parse(&frame), Ok(Received::Other));
        let mut frame = data_frame(A, B, 0, 0, &[0x60]);
        frame[1] = 0x40; // protected
        assert_eq!(parse(&frame), Ok(Received::Other));
    }

    // spec: AWDL-15
    #[test]
    fn addba_requests_are_answered_with_success() {
        let mut req = Vec::new();
        put_header(&mut req, fc::ACTION, A, B, 3);
        // Dialog 9, TID 5, window 256 (capped to 64), timeout 0.
        req.extend_from_slice(&[3, 0, 9]);
        let params: u16 = (256 << 6) | (5 << 2) | 0x0003;
        req.extend_from_slice(&params.to_le_bytes());
        req.extend_from_slice(&[0, 0, 0, 0]);
        let Received::AddBaRequest {
            header,
            token,
            params,
            timeout,
        } = parse(&req).unwrap()
        else {
            panic!("not ADDBA");
        };
        assert_eq!((header.src, token, timeout), (B, 9, 0));
        let resp = addba_response(A, B, 4, token, params, timeout);
        let body = &resp[HEADER_LEN..];
        assert_eq!(&body[..5], &[3, 1, 9, 0, 0]);
        let p = u16::from_le_bytes([body[5], body[6]]);
        assert_eq!(((p >> 2) & 0xf, p & 0x3, p >> 6), (5, 0x2, 64));
        assert_eq!(&resp[4..10], &B.0);
    }
}
