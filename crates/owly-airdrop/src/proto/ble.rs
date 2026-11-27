//! AirDrop BLE advertisements (§2): encoding outgoing adverts and parsing
//! incoming Apple Continuity manufacturer data.

/// Apple's Bluetooth company ID, the key of the manufacturer data.
pub const APPLE_COMPANY_ID: u16 = 0x004c;

/// The AirDrop TLV type in Apple's manufacturer data.
pub const AIRDROP_TYPE: u8 = 0x05;

/// AirDrop BLE TLV version 1 (BLE-2).
pub const VERSION_1: u8 = 0x01;

/// AirDrop BLE TLV version 3 (BLE-2, BLE-5).
pub const VERSION_3: u8 = 0x03;

/// The advertising interval current Apple devices answer to (BLE-5).
pub const INTERVAL_MS: u32 = 100;

/// The version 3 advert (BLE-2, BLE-5): a per-advert tag and the four
/// contact-hash prefixes, each the first 2 bytes of SHA-256 of an
/// identifier. How identifiers are normalized before hashing is open
/// (BLE-4), so nothing here computes them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Advert {
    pub tag: [u8; 3],
    /// The sender's contact hashes: the first 2 bytes of SHA-256 of its
    /// Apple ID, a phone number or an email address. A slot doesn't say
    /// which, since senders rotate them between advertisements (BLE-2).
    pub hashes: [[u8; 2]; 4],
}

impl Advert {
    /// BLE-3: a sender with no Apple identity sends zero hashes, which wakes
    /// Everyone-mode receivers. BLE-5 asks for a random `tag`.
    pub fn anonymous(tag: [u8; 3]) -> Self {
        Advert {
            tag,
            ..Self::default()
        }
    }

    /// The manufacturer data, without the company ID: the AirDrop TLV and
    /// its 18-byte payload (BLE-1, BLE-2).
    pub fn manufacturer_data(&self) -> Vec<u8> {
        let mut out = vec![AIRDROP_TYPE, 0x12, 0x40];
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&[0; 4]);
        out.push(0x03);
        for hash in self.hashes {
            out.extend_from_slice(&hash);
        }
        out.push(0x00);
        out
    }

    /// Parses the first valid AirDrop TLV from Apple manufacturer data
    /// (without the company ID, BLE-1, BLE-2).
    pub fn parse_manufacturer_data(data: &[u8]) -> Option<ParsedAdvert> {
        parse_continuity(data)
            .into_iter()
            .filter(|record| record.kind == AIRDROP_TYPE)
            .find_map(|record| ParsedAdvert::from_payload(record.payload))
    }

    /// Whether every contact-hash slot is zero, waking Everyone-mode
    /// receivers without identifying a contact (BLE-3).
    pub fn is_anonymous(&self) -> bool {
        self.hashes == [[0; 2]; 4]
    }
}

/// One Type-Length-Value record inside Apple Continuity manufacturer data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuityRecord<'a> {
    pub kind: u8,
    pub payload: &'a [u8],
}

/// A parsed incoming AirDrop BLE advertisement (BLE-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedAdvert {
    pub version: u8,
    pub advert: Advert,
}

impl ParsedAdvert {
    /// Parses an 18-byte AirDrop TLV payload (version 1 or version 3, BLE-2).
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        let bytes: &[u8; 18] = payload.try_into().ok()?;
        let version = bytes[8];
        if version != VERSION_1 && version != VERSION_3 {
            return None;
        }
        // Version 1 zeroes offsets 0..8; version 3 carries a 3-byte tag at 1..4.
        let tag = if version == VERSION_1 {
            [0; 3]
        } else {
            [bytes[1], bytes[2], bytes[3]]
        };
        let hashes = [
            [bytes[9], bytes[10]],
            [bytes[11], bytes[12]],
            [bytes[13], bytes[14]],
            [bytes[15], bytes[16]],
        ];
        Some(ParsedAdvert {
            version,
            advert: Advert { tag, hashes },
        })
    }
}

/// Parses Apple Continuity TLV records from manufacturer data without the
/// `0x004c` company ID, stopping cleanly if a trailing record is truncated.
pub fn parse_continuity(data: &[u8]) -> Vec<ContinuityRecord<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    while let (Some(&kind), Some(&len)) = (data.get(i), data.get(i + 1)) {
        let start = i + 2;
        let end = start + usize::from(len);
        let Some(payload) = data.get(start..end) else {
            break;
        };
        out.push(ContinuityRecord { kind, payload });
        i = end;
    }
    out
}

/// Returns `true` if Apple manufacturer data carries a complete AirDrop TLV
/// (type `0x05`, BLE-1).
pub fn contains_airdrop(data: &[u8]) -> bool {
    parse_continuity(data)
        .into_iter()
        .any(|record| record.kind == AIRDROP_TYPE)
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    // spec: BLE-1, BLE-2, BLE-3
    #[test]
    fn roundtrip_v3_adverts() {
        let anon = Advert::anonymous([0xa1, 0xb2, 0xc3]);
        assert!(anon.is_anonymous());
        let parsed = Advert::parse_manufacturer_data(&anon.manufacturer_data()).unwrap();
        assert_eq!(parsed.version, VERSION_3);
        assert_eq!(parsed.advert, anon);
        assert!(contains_airdrop(&anon.manufacturer_data()));

        let with_hashes = Advert {
            tag: [0x11, 0x22, 0x33],
            hashes: [[0xaa, 0xbb], [0xcc, 0xdd], [0xee, 0xff], [0x01, 0x02]],
        };
        assert!(!with_hashes.is_anonymous());
        let parsed = Advert::parse_manufacturer_data(&with_hashes.manufacturer_data()).unwrap();
        assert_eq!(parsed.version, VERSION_3);
        assert_eq!(parsed.advert, with_hashes);
    }

    // spec: BLE-2
    #[test]
    fn parses_v1_and_multiple_tlvs() {
        // Nearby Info (0x10) followed by a v1 AirDrop TLV (0x05, len 0x12).
        let mut data = vec![0x10, 0x01, 0x03, AIRDROP_TYPE, 0x12];
        data.extend_from_slice(&[0u8; 8]);
        data.push(VERSION_1);
        data.extend_from_slice(&[0x12, 0x34, 0, 0, 0x56, 0x78, 0, 0]);
        data.push(0x00);

        let records = parse_continuity(&data);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, 0x10);
        assert_eq!(records[1].kind, AIRDROP_TYPE);
        assert!(contains_airdrop(&data));

        let parsed = Advert::parse_manufacturer_data(&data).unwrap();
        assert_eq!(parsed.version, VERSION_1);
        assert_eq!(parsed.advert.tag, [0; 3]);
        assert_eq!(
            parsed.advert.hashes,
            [[0x12, 0x34], [0, 0], [0x56, 0x78], [0, 0]]
        );
    }

    #[test]
    fn ignores_non_airdrop_truncated_and_unknown_versions() {
        assert!(!contains_airdrop(&[]));
        assert!(!contains_airdrop(&[0x10, 0x01, 0x03]));
        assert!(Advert::parse_manufacturer_data(&[0x10, 0x01, 0x03]).is_none());

        // Truncated AirDrop TLV.
        let truncated = [AIRDROP_TYPE, 0x12, 0x40, 0x01, 0x02];
        assert!(parse_continuity(&truncated).is_empty());
        assert!(!contains_airdrop(&truncated));
        assert!(Advert::parse_manufacturer_data(&truncated).is_none());

        // Wrong payload length (17 bytes instead of 18).
        let mut wrong_len = vec![AIRDROP_TYPE, 0x11];
        wrong_len.extend_from_slice(&[0u8; 17]);
        assert!(contains_airdrop(&wrong_len));
        assert!(Advert::parse_manufacturer_data(&wrong_len).is_none());

        // Unknown version (0x02).
        let mut unknown_ver = Advert::anonymous([1, 2, 3]).manufacturer_data();
        unknown_ver[2 + 8] = 0x02;
        assert!(Advert::parse_manufacturer_data(&unknown_ver).is_none());

        // Reserved bytes differ from defaults and are ignored on receipt (§0.1).
        let mut non_default_reserved = Advert::anonymous([4, 5, 6]).manufacturer_data();
        non_default_reserved[2] = 0x99;
        non_default_reserved[6] = 0x77;
        non_default_reserved[19] = 0x55;
        let parsed = Advert::parse_manufacturer_data(&non_default_reserved).unwrap();
        assert_eq!(parsed.version, VERSION_3);
        assert_eq!(parsed.advert.tag, [4, 5, 6]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: BLE-1, BLE-2, BLE-3, BLE-5
    #[test]
    fn anonymous_advert_layout() {
        let data = Advert::anonymous([0xa1, 0xb2, 0xc3]).manufacturer_data();
        assert_eq!(data.len(), 2 + 18);
        assert_eq!(&data[..2], &[0x05, 0x12]);
        assert_eq!(&data[2..6], &[0x40, 0xa1, 0xb2, 0xc3]);
        assert_eq!(&data[6..10], &[0; 4]);
        assert_eq!(data[10], 0x03);
        assert_eq!(&data[11..], &[0; 9]);
    }

    #[test]
    fn hashes_in_order() {
        let advert = Advert {
            tag: [0; 3],
            hashes: [[1, 2], [3, 4], [5, 6], [7, 8]],
        };
        assert_eq!(
            &advert.manufacturer_data()[11..],
            &[1, 2, 3, 4, 5, 6, 7, 8, 0]
        );
    }

    // The whole payload for another tag and zero hashes, spelled out.
    // spec: BLE-5
    #[test]
    fn anonymous_advert_bytes() {
        let tag = [0x12, 0x34, 0x56];
        let mut expected = vec![5, 18, 0x40];
        expected.extend(tag);
        expected.extend([0; 4]);
        expected.push(3);
        expected.extend([0; 8]);
        expected.push(0);
        assert_eq!(Advert::anonymous(tag).manufacturer_data(), expected);
    }
}
