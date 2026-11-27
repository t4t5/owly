//! Safe-Rust (`#![forbid(unsafe_code)]`) USB Wi-Fi dongle wire framing and `nusb` transport.
//!
//! Provides clean-room USB bulk/control framing codecs for the two chipsets
//! validated for active-monitor AWDL (`owly-radio`):
//! - [`Mt7612uCodec`]: MediaTek MT7612U (`mt76x2u`, dual-band 5 GHz channels 44/149)
//! - [`Ar9271Codec`]: Qualcomm Atheros AR9271 (`ath9k_htc`, 2.4 GHz channel 6)

use owly_awdl::channel::Channel;
use owly_awdl::{Frame, TxRate};

/// USB control transfer descriptor (`bmRequestType = 0x40` / `0xC0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorCtrlTransfer {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub data: Vec<u8>,
}

/// USB Wi-Fi chipset family for bulk/control wire framing and endpoint selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbChipset {
    Ar9271,
    Mt7612u,
}

/// Bulk endpoints chosen from a USB alternate setting descriptor list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedEndpoints {
    pub bulk_out_ep: u8,
    pub bulk_in_ep: u8,
    pub cmd_out_ep: Option<u8>,
    pub cmd_in_ep: Option<u8>,
    pub in_max_packet: usize,
}

/// Selects TX/RX data (and optional MCU command) bulk endpoints for `chipset` from `(address, max_packet_size)` pairs.
///
/// On real MT7612U (`0e8d:7612`) hardware, inband MCU endpoint `0x08` appears before `0x04` in
/// the USB interface descriptor; picking `0x04`/`0x84` avoids sending 802.11 frames to the MCU pipe.
pub fn select_endpoints(
    chipset: UsbChipset,
    bulk_eps: &[(u8, usize)],
) -> Option<SelectedEndpoints> {
    let is_in = |addr: u8| addr & 0x80 != 0;
    let in_mps = |target: u8| {
        bulk_eps
            .iter()
            .find(|&&(addr, _)| addr == target)
            .map(|&(_, mps)| mps.max(64))
            .unwrap_or(512)
    };

    match chipset {
        UsbChipset::Mt7612u => {
            let bulk_out_ep = bulk_eps
                .iter()
                .find(|&&(addr, _)| addr == Mt7612uCodec::EP_OUT_TX_DATA)
                .or_else(|| {
                    bulk_eps
                        .iter()
                        .find(|&&(addr, _)| !is_in(addr) && addr != Mt7612uCodec::EP_OUT_INBAND_CMD)
                })
                .or_else(|| bulk_eps.iter().find(|&&(addr, _)| !is_in(addr)))?
                .0;
            let bulk_in_ep = bulk_eps
                .iter()
                .find(|&&(addr, _)| addr == Mt7612uCodec::EP_IN_RX_DATA)
                .or_else(|| bulk_eps.iter().find(|&&(addr, _)| is_in(addr)))?
                .0;
            let cmd_out_ep = bulk_eps
                .iter()
                .find(|&&(addr, _)| addr == Mt7612uCodec::EP_OUT_INBAND_CMD)
                .map(|&(addr, _)| addr);
            let cmd_in_ep = bulk_eps
                .iter()
                .find(|&&(addr, _)| addr == Mt7612uCodec::EP_IN_RX_CMD)
                .map(|&(addr, _)| addr);
            Some(SelectedEndpoints {
                bulk_out_ep,
                bulk_in_ep,
                cmd_out_ep,
                cmd_in_ep,
                in_max_packet: in_mps(bulk_in_ep),
            })
        }
        UsbChipset::Ar9271 => {
            let bulk_out_ep = bulk_eps
                .iter()
                .find(|&&(addr, _)| addr == Ar9271Codec::USB_EP_OUT_WLAN_TX)
                .or_else(|| bulk_eps.iter().find(|&&(addr, _)| !is_in(addr)))?
                .0;
            let bulk_in_ep = bulk_eps
                .iter()
                .find(|&&(addr, _)| addr == Ar9271Codec::USB_EP_IN_WLAN_RX)
                .or_else(|| bulk_eps.iter().find(|&&(addr, _)| is_in(addr)))?
                .0;
            Some(SelectedEndpoints {
                bulk_out_ep,
                bulk_in_ep,
                cmd_out_ep: None,
                cmd_in_ep: None,
                in_max_packet: in_mps(bulk_in_ep),
            })
        }
    }
}

/// Abstract wire encapsulation/decapsulation for userspace USB Wi-Fi bulk URBs.
pub trait RadioWire {
    fn name(&self) -> &'static str;
    fn encapsulate_tx(&self, frame: &Frame) -> Vec<u8>;
    /// Inspects an encoded host-to-radio TX buffer and recovers its 802.11 MPDU.
    ///
    /// This is useful for validating codecs and simulated USB radio paths; hardware consumes
    /// the TX buffer and emits the MPDU over RF.
    fn decapsulate_tx(&self, usb_packet: &[u8]) -> Option<Vec<u8>>;
    fn decapsulate_rx(&self, usb_packet: &[u8]) -> Option<(Option<i8>, Vec<u8>)>;
}

/// Clean-room parsed MediaTek `mt7662u_rom_patch.bin` header (30 B) + patch payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mt7612uRomPatch {
    pub build_time: String,
    pub platform: String,
    pub hw_sw_ver: u32,
    pub patch_ver: u32,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl Mt7612uRomPatch {
    /// Parses a decompressed `mt7662u_rom_patch.bin` image.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() <= Mt7612uCodec::PATCH_HEADER_LEN {
            return Err(format!(
                "mt7662u ROM patch too short: {} bytes (need > {})",
                bytes.len(),
                Mt7612uCodec::PATCH_HEADER_LEN
            ));
        }
        let build_time = trim_ascii_field(&bytes[0..16]);
        let platform = trim_ascii_field(&bytes[16..20]);
        if platform.is_empty() {
            return Err("mt7662u ROM patch header missing platform tag".to_string());
        }
        let hw_sw_ver = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
        let patch_ver = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
        let checksum = u16::from_be_bytes(bytes[28..30].try_into().unwrap());
        Ok(Self {
            build_time,
            platform,
            hw_sw_ver,
            patch_ver,
            checksum,
            payload: bytes[Mt7612uCodec::PATCH_HEADER_LEN..].to_vec(),
        })
    }
}

/// Clean-room parsed MediaTek `mt7662u.bin` header (32 B) + ILM/DLM segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mt7612uFirmware {
    pub ilm_len: u32,
    pub dlm_len: u32,
    pub build_ver: u16,
    pub fw_ver: u16,
    pub build_time: String,
    pub ilm: Vec<u8>,
    pub dlm: Vec<u8>,
}

impl Mt7612uFirmware {
    /// Parses a decompressed `mt7662u.bin` MCU firmware image.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < Mt7612uCodec::FW_HEADER_LEN {
            return Err(format!(
                "mt7662u firmware too short: {} bytes (need >= {})",
                bytes.len(),
                Mt7612uCodec::FW_HEADER_LEN
            ));
        }
        let ilm_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let dlm_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let build_ver = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
        let fw_ver = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
        let build_time = trim_ascii_field(&bytes[16..32]);

        let expected = Mt7612uCodec::FW_HEADER_LEN
            .checked_add(ilm_len as usize)
            .and_then(|v| v.checked_add(dlm_len as usize))
            .ok_or_else(|| "mt7662u firmware header lengths overflow".to_string())?;
        if expected != bytes.len() {
            return Err(format!(
                "mt7662u firmware length mismatch: header declares {expected} bytes ({ilm_len} ILM + {dlm_len} DLM + {}), got {}",
                Mt7612uCodec::FW_HEADER_LEN,
                bytes.len()
            ));
        }

        let ilm_end = Mt7612uCodec::FW_HEADER_LEN + ilm_len as usize;
        Ok(Self {
            ilm_len,
            dlm_len,
            build_ver,
            fw_ver,
            build_time,
            ilm: bytes[Mt7612uCodec::FW_HEADER_LEN..ilm_end].to_vec(),
            dlm: bytes[ilm_end..].to_vec(),
        })
    }
}

/// One DMA-addressed firmware upload chunk for MT7612U EP `0x08` + FCE DMA registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mt7612uFwChunk {
    pub dma_addr: u32,
    pub dma_len: u32,
    /// `MT_VEND_WRITE_FCE` writes one 16-bit half through `wValue`, so a
    /// 32-bit FCE register write is two control transfers.
    pub addr_ctrl: [VendorCtrlTransfer; 2],
    pub len_ctrl: [VendorCtrlTransfer; 2],
    pub bulk_frame: Vec<u8>,
}

fn trim_ascii_field(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.trim_matches(|c: char| c == '\0' || c.is_ascii_whitespace())
        .to_string()
}

/// MediaTek MT7612U (`mt76x2u`) USB bulk TXWI/RXWI and vendor-control framing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mt7612uCodec;

impl Mt7612uCodec {
    pub const SUPPORTED_USB_IDS: &[(u16, u16)] = &[
        (0x0e8d, 0x7612),
        (0x0e8d, 0x7632),
        (0x0b05, 0x17eb),
        (0x0846, 0x9053),
    ];
    pub const TX_DMA_INFO_LEN: usize = 4;
    pub const TXWI_LEN: usize = 20;
    pub const TX_TRAILER_LEN: usize = 4;
    pub const RX_DMA_INFO_LEN: usize = 4;
    pub const RXWI_LEN: usize = 32;

    pub const VEND_DEV_MODE: u8 = 0x01;
    pub const VEND_WRITE: u8 = 0x02;
    pub const VEND_POWER_ON: u8 = 0x04;
    pub const VEND_MULTI_WRITE: u8 = 0x06;
    pub const VEND_MULTI_READ: u8 = 0x07;
    pub const VEND_READ_EEPROM: u8 = 0x09;
    pub const VEND_WRITE_FCE: u8 = 0x42;
    pub const VEND_WRITE_CFG: u8 = 0x46;
    pub const VEND_READ_CFG: u8 = 0x47;
    pub const VEND_READ_EXT: u8 = 0x63;
    pub const VEND_WRITE_EXT: u8 = 0x66;
    pub const VEND_FEATURE_SET: u8 = 0x91;

    pub const REG_ASIC_VERSION: u32 = 0x0000;
    pub const REG_FCE_DMA_ADDR: u32 = 0x0230;
    pub const REG_FCE_DMA_LEN: u32 = 0x0234;
    pub const REG_USB_DMA_CFG: u32 = 0x0238;
    pub const CFG_USB_U3DMA_CFG: u32 = 0x9018;
    pub const REG_TX_CPU_FROM_FCE_CPU_DESC_IDX: u32 = 0x09a8;
    pub const REG_MCU_CLOCK_CTL: u32 = 0x0708;
    pub const REG_MCU_COM_REG0: u32 = 0x0730;
    pub const REG_FCE_L2_STUFF: u32 = 0x080c;
    pub const REG_MAC_SYS_CTRL: u32 = 0x1004;
    pub const REG_MAC_ADDR_DW0: u32 = 0x1008;
    pub const REG_MAC_ADDR_DW1: u32 = 0x100c;
    pub const REG_RX_FILTR_CFG: u32 = 0x1400;

    pub const USB_DMA_CFG_RX_DROP_OR_PAD: u32 = 1 << 18;
    pub const USB_DMA_CFG_RX_BULK_AGG_EN: u32 = 1 << 21;
    pub const USB_DMA_CFG_RX_BULK_EN: u32 = 1 << 22;
    pub const USB_DMA_CFG_TX_BULK_EN: u32 = 1 << 23;
    pub const USB_DMA_CFG_RX_BUSY: u32 = 1 << 30;
    pub const USB_DMA_CFG_TX_BUSY: u32 = 1 << 31;

    pub const TXD_INFO_80211: u32 = 1 << 19;
    pub const TXD_INFO_WIV: u32 = 1 << 24;
    pub const TXD_INFO_QSEL_MGMT: u32 = 0 << 25;
    pub const TXD_INFO_QSEL_EDCA: u32 = 2 << 25;

    pub const RXINFO_CRCERR: u32 = 1 << 8;
    pub const RXINFO_ICVERR: u32 = 1 << 9;
    pub const RXINFO_MICERR: u32 = 1 << 10;
    pub const RXINFO_L2PAD: u32 = 1 << 14;
    pub const RXINFO_AMPDU: u32 = 1 << 15;

    pub const MAC_SYS_CTRL_RESET_CSR: u32 = 1 << 0;
    pub const MAC_SYS_CTRL_RESET_BBP: u32 = 1 << 1;
    pub const MAC_SYS_CTRL_ENABLE_TX: u32 = 1 << 2;
    pub const MAC_SYS_CTRL_ENABLE_RX: u32 = 1 << 3;

    pub const MCU_MSG_TYPE_CMD: u32 = 1 << 30;
    pub const MCU_MSG_PORT_CPU_TX: u32 = 2 << 27;

    pub const VEND_DEV_MODE_RESET: u16 = 0x01;
    pub const VEND_DEV_MODE_RESET_IVB: u16 = 0x12;

    pub const PATCH_HEADER_LEN: usize = 30;
    pub const FW_HEADER_LEN: usize = 32;
    pub const PATCH_LOAD_ADDR: u32 = 0x0009_0000;
    pub const FW_ILM_LOAD_ADDR: u32 = 0x0008_0000;
    pub const FW_DLM_LOAD_ADDR: u32 = 0x0011_0800;
    /// The ROM-patch USB buffer is 2048 bytes including the 8-byte DMA
    /// header/trailer.
    pub const ROM_PATCH_MAX_CHUNK_LEN: usize = 2048 - 8;
    /// The firmware USB buffer is 0x3900 bytes including the 8-byte DMA
    /// header/trailer.
    pub const FW_MAX_CHUNK_LEN: usize = 0x3900 - 8;

    pub const EP_OUT_TX_DATA: u8 = 0x04;
    pub const EP_OUT_INBAND_CMD: u8 = 0x08;
    pub const EP_IN_RX_DATA: u8 = 0x84;
    pub const EP_IN_RX_CMD: u8 = 0x85;

    /// Computes the IEEE 802.11 MAC header length (without FCS) for `mpdu`.
    pub fn ieee80211_hdr_len(mpdu: &[u8]) -> Option<usize> {
        if mpdu.len() < 2 {
            return None;
        }
        let fc = u16::from_le_bytes([mpdu[0], mpdu[1]]);
        let ftype = (fc >> 2) & 0x03;
        let subtype = (fc >> 4) & 0x0f;
        let len = match ftype {
            // Management
            0 => {
                if fc & 0x8000 != 0 {
                    28
                } else {
                    24
                }
            }
            // Control
            1 => match subtype {
                0x08..=0x0b => 16, // RTS, PS-Poll, BAR, BA
                0x0c | 0x0d => 10, // CTS, ACK
                _ => 16,
            },
            // Data
            2 => {
                let mut l = if (fc & 0x0300) == 0x0300 { 30 } else { 24 };
                if subtype & 0x08 != 0 {
                    l += 2;
                    if fc & 0x8000 != 0 {
                        l += 4;
                    }
                }
                l
            }
            _ => return None,
        };
        (mpdu.len() >= len).then_some(len)
    }

    fn encode_tx_rate(rate: TxRate) -> u16 {
        const PHY_OFDM: u16 = 1 << 13;
        const PHY_HT: u16 = 2 << 13;
        match rate {
            TxRate::Legacy(half_mbps) => {
                let idx = match half_mbps {
                    12 => 0,
                    18 => 1,
                    24 => 2,
                    36 => 3,
                    48 => 4,
                    72 => 5,
                    96 => 6,
                    108 => 7,
                    _ => 0,
                };
                PHY_OFDM | idx
            }
            TxRate::Ht { mcs, sgi } => {
                PHY_HT | u16::from(mcs & 0x3f) | if sgi { 1 << 9 } else { 0 }
            }
        }
    }

    /// Encodes a simulated or hardware RX packet (`RX_DMA_INFO (4B) + mt76x02_rxwi (32B) + 802.11 MPDU`).
    pub fn encode_rx_packet(mpdu: &[u8], rssi_dbm: i8) -> Vec<u8> {
        let padded_payload_len = (mpdu.len() + 3) & !3;
        let rx_total = u16::try_from(Self::RXWI_LEN + padded_payload_len).unwrap_or(u16::MAX);
        let dma_info = u32::from(rx_total);

        let mut rxwi = [0u8; Self::RXWI_LEN];
        // ctl[29:16] carries exact unpadded MPDU byte length in MT76x02 RXWI.
        let mpdu_len = u16::try_from(mpdu.len()).unwrap_or(u16::MAX) & 0x3fff;
        let ctl = u32::from(mpdu_len) << 16;
        rxwi[4..8].copy_from_slice(&ctl.to_le_bytes());
        // rssi[0..2] (offset 12..14 of struct mt76x02_rxwi) carries signed RSSI.
        rxwi[12] = rssi_dbm as u8;
        rxwi[13] = rssi_dbm as u8;

        let mut out =
            Vec::with_capacity(Self::RX_DMA_INFO_LEN + Self::RXWI_LEN + padded_payload_len);
        out.extend_from_slice(&dma_info.to_le_bytes());
        out.extend_from_slice(&rxwi);
        out.extend_from_slice(mpdu);
        out.resize(
            Self::RX_DMA_INFO_LEN + Self::RXWI_LEN + padded_payload_len,
            0,
        );
        out
    }

    /// Reads a 32-bit MAC/BBP register (`MT_VEND_MULTI_READ`, `0x07`).
    pub fn vendor_read_reg(addr: u32) -> VendorCtrlTransfer {
        VendorCtrlTransfer {
            request_type: 0xc0,
            request: Self::VEND_MULTI_READ,
            value: (addr >> 16) as u16,
            index: addr as u16,
            data: vec![0u8; 4],
        }
    }

    /// Writes a 32-bit MAC/BBP register (`MT_VEND_MULTI_WRITE`, `0x06`).
    pub fn vendor_write_reg(addr: u32, val: u32) -> VendorCtrlTransfer {
        VendorCtrlTransfer {
            request_type: 0x40,
            request: Self::VEND_MULTI_WRITE,
            value: (addr >> 16) as u16,
            index: addr as u16,
            data: val.to_le_bytes().to_vec(),
        }
    }

    /// Reads a 32-bit configuration register (`MT_VEND_READ_CFG`, `0x47`).
    pub fn vendor_read_cfg(addr: u32) -> VendorCtrlTransfer {
        VendorCtrlTransfer {
            request_type: 0xc0,
            request: Self::VEND_READ_CFG,
            value: (addr >> 16) as u16,
            index: addr as u16,
            data: vec![0u8; 4],
        }
    }

    /// Writes a 32-bit configuration register (`MT_VEND_WRITE_CFG`, `0x46`).
    pub fn vendor_write_cfg(addr: u32, val: u32) -> VendorCtrlTransfer {
        VendorCtrlTransfer {
            request_type: 0x40,
            request: Self::VEND_WRITE_CFG,
            value: (addr >> 16) as u16,
            index: addr as u16,
            data: val.to_le_bytes().to_vec(),
        }
    }

    /// Writes a 32-bit Flow Control Engine register (`MT_VEND_WRITE_FCE`,
    /// `0x42`) as the two 16-bit, zero-length control requests the device
    /// expects.
    pub fn vendor_write_fce(addr: u32, val: u32) -> [VendorCtrlTransfer; 2] {
        [
            VendorCtrlTransfer {
                request_type: 0x40,
                request: Self::VEND_WRITE_FCE,
                value: val as u16,
                index: addr as u16,
                data: Vec::new(),
            },
            VendorCtrlTransfer {
                request_type: 0x40,
                request: Self::VEND_WRITE_FCE,
                value: (val >> 16) as u16,
                index: addr.wrapping_add(2) as u16,
                data: Vec::new(),
            },
        ]
    }

    /// Issues `MT_VEND_DEV_MODE` (`0x01`) mode/reset control transfer.
    pub fn vendor_dev_mode(mode: u16) -> VendorCtrlTransfer {
        VendorCtrlTransfer {
            request_type: 0x40,
            request: Self::VEND_DEV_MODE,
            value: mode,
            index: 0,
            data: Vec::new(),
        }
    }

    /// Encodes an inband MCU command buffer for Bulk OUT EP `0x08`.
    pub fn encode_mcu_cmd(cmd: u8, seq: u8, payload: &[u8]) -> Vec<u8> {
        let padded_len = (payload.len() + 3) & !3;
        let tx_info = Self::MCU_MSG_TYPE_CMD
            | Self::MCU_MSG_PORT_CPU_TX
            | (u32::from(cmd & 0x7f) << 20)
            | (u32::from(seq & 0x0f) << 16)
            | (u32::try_from(padded_len).unwrap_or(0xffff) & 0xffff);
        let mut out = Vec::with_capacity(4 + padded_len + 4);
        out.extend_from_slice(&tx_info.to_le_bytes());
        out.extend_from_slice(payload);
        out.resize(4 + padded_len + 4, 0);
        out
    }

    /// Splits a firmware payload section into FCE DMA ctrl + EP `0x08` bulk upload chunks.
    pub fn fw_upload_chunks(
        base_addr: u32,
        payload: &[u8],
        max_chunk: usize,
    ) -> Vec<Mt7612uFwChunk> {
        let chunk_limit = max_chunk.max(1);
        let mut chunks = Vec::new();
        let mut offset = 0usize;
        for part in payload.chunks(chunk_limit) {
            let dma_addr = base_addr.wrapping_add(u32::try_from(offset).unwrap_or(u32::MAX));
            let dma_len = u32::try_from(part.len()).unwrap_or(u32::MAX);
            let padded_len = (part.len() + 3) & !3;
            // The DMA header carries the unpadded payload length. The FCE
            // register below carries the rounded transfer length.
            let tx_info = Self::MCU_MSG_TYPE_CMD
                | Self::MCU_MSG_PORT_CPU_TX
                | (u32::try_from(part.len()).unwrap_or(0xffff) & 0xffff);
            let mut bulk_frame = Vec::with_capacity(4 + padded_len + 4);
            bulk_frame.extend_from_slice(&tx_info.to_le_bytes());
            bulk_frame.extend_from_slice(part);
            bulk_frame.resize(4 + padded_len + 4, 0);

            chunks.push(Mt7612uFwChunk {
                dma_addr,
                dma_len,
                addr_ctrl: Self::vendor_write_fce(Self::REG_FCE_DMA_ADDR, dma_addr),
                len_ctrl: Self::vendor_write_fce(
                    Self::REG_FCE_DMA_LEN,
                    (u32::try_from(padded_len).unwrap_or(u32::MAX)) << 16,
                ),
                bulk_frame,
            });
            offset += part.len();
        }
        chunks
    }

    /// Generates clean-room register configuration transfers for an AWDL 20 MHz channel.
    pub fn channel_config_transfers(channel: Channel) -> Result<Vec<VendorCtrlTransfer>, String> {
        let (freq_mhz, band_bit): (u32, u32) = match channel.0 {
            1..=13 => (2407 + u32::from(channel.0) * 5, 0),
            36..=165 => (5000 + u32::from(channel.0) * 5, 1),
            other => return Err(format!("unsupported MT7612U channel {other}")),
        };
        Ok(vec![
            Self::vendor_write_cfg(0x0200, freq_mhz),
            Self::vendor_write_cfg(0x0204, band_bit),
            Self::vendor_write_reg(Self::REG_RX_FILTR_CFG, 0x0000_000f),
        ])
    }

    /// Builds active-monitor initialization transfers (MAC address, USB DMA, RX filter, TX/RX enable, channel).
    pub fn active_monitor_init_transfers(
        mac: [u8; 6],
        channel: Channel,
    ) -> Result<Vec<VendorCtrlTransfer>, String> {
        let mut transfers = Self::channel_config_transfers(channel)?;
        let dw0 = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
        let dw1 = u32::from_le_bytes([mac[4], mac[5], 0xff, 0x00]);
        let mut init = vec![
            Self::vendor_write_reg(Self::REG_MAC_ADDR_DW0, dw0),
            Self::vendor_write_reg(Self::REG_MAC_ADDR_DW1, dw1),
            Self::vendor_write_reg(
                Self::REG_USB_DMA_CFG,
                Self::USB_DMA_CFG_TX_BULK_EN
                    | Self::USB_DMA_CFG_RX_BULK_EN
                    | Self::USB_DMA_CFG_RX_DROP_OR_PAD,
            ),
            Self::vendor_write_reg(Self::REG_FCE_L2_STUFF, 0x0000_0001),
            Self::vendor_write_reg(
                Self::REG_MAC_SYS_CTRL,
                Self::MAC_SYS_CTRL_ENABLE_TX | Self::MAC_SYS_CTRL_ENABLE_RX,
            ),
        ];
        init.append(&mut transfers);
        Ok(init)
    }
}

impl RadioWire for Mt7612uCodec {
    fn name(&self) -> &'static str {
        "mt7612u-usb"
    }

    fn encapsulate_tx(&self, frame: &Frame) -> Vec<u8> {
        let hdr_len = Self::ieee80211_hdr_len(&frame.bytes).unwrap_or(frame.bytes.len());
        let l2_pad = if !hdr_len.is_multiple_of(4) {
            2usize
        } else {
            0usize
        };
        let padded_mpdu_len = frame.bytes.len() + l2_pad;
        let xfer_len = (Self::TXWI_LEN + padded_mpdu_len + 3) & !3;
        let dma_info = (u32::try_from(xfer_len).unwrap_or(0xffff) & 0xffff)
            | Self::TXD_INFO_WIV
            | Self::TXD_INFO_80211
            | Self::TXD_INFO_QSEL_EDCA;

        let mut txwi = [0u8; Self::TXWI_LEN];
        let rate_val = Self::encode_tx_rate(frame.rate);
        txwi[2..4].copy_from_slice(&rate_val.to_le_bytes());
        if !frame.no_ack && !frame.to.is_multicast() {
            txwi[4] = 0x01; // MT_TXWI_ACK_CTL_REQ
        }
        txwi[5] = 0xff; // global WCID
        let mpdu_len = u16::try_from(frame.bytes.len()).unwrap_or(u16::MAX);
        txwi[6..8].copy_from_slice(&mpdu_len.to_le_bytes());
        txwi[17] = 0x13; // MT76XX_REV_E4 / 2-stream TX
        txwi[19] = 0x80 | ((rate_val & 0x1f) as u8); // MT_PACKET_ID_HAS_RATE

        let total = Self::TX_DMA_INFO_LEN + xfer_len + Self::TX_TRAILER_LEN;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&dma_info.to_le_bytes());
        out.extend_from_slice(&txwi);
        out.extend_from_slice(&frame.bytes[..hdr_len]);
        if l2_pad == 2 {
            out.extend_from_slice(&[0u8, 0u8]);
        }
        out.extend_from_slice(&frame.bytes[hdr_len..]);
        out.resize(total, 0);
        out
    }

    fn decapsulate_tx(&self, usb_packet: &[u8]) -> Option<Vec<u8>> {
        let min_len = Self::TX_DMA_INFO_LEN + Self::TXWI_LEN + Self::TX_TRAILER_LEN;
        if usb_packet.len() < min_len {
            return None;
        }
        let dma_info = u32::from_le_bytes(usb_packet[0..4].try_into().ok()?);
        let xfer_len = (dma_info & 0xffff) as usize;
        if (dma_info & (Self::TXD_INFO_WIV | Self::TXD_INFO_80211))
            != (Self::TXD_INFO_WIV | Self::TXD_INFO_80211)
            || xfer_len < Self::TXWI_LEN
            || !xfer_len.is_multiple_of(4)
            || Self::TX_DMA_INFO_LEN + xfer_len + Self::TX_TRAILER_LEN != usb_packet.len()
        {
            return None;
        }
        let txwi = &usb_packet[Self::TX_DMA_INFO_LEN..Self::TX_DMA_INFO_LEN + Self::TXWI_LEN];
        let mpdu_len = u16::from_le_bytes(txwi[6..8].try_into().ok()?) as usize;
        let payload =
            &usb_packet[Self::TX_DMA_INFO_LEN + Self::TXWI_LEN..Self::TX_DMA_INFO_LEN + xfer_len];
        if mpdu_len < 10 || mpdu_len > payload.len() {
            return None;
        }
        let hdr_len = Self::ieee80211_hdr_len(payload).unwrap_or(mpdu_len);
        if !hdr_len.is_multiple_of(4) {
            if mpdu_len + 2 > payload.len() {
                return None;
            }
            let mut mpdu = Vec::with_capacity(mpdu_len);
            mpdu.extend_from_slice(&payload[..hdr_len]);
            mpdu.extend_from_slice(&payload[hdr_len + 2..mpdu_len + 2]);
            Some(mpdu)
        } else {
            Some(payload[..mpdu_len].to_vec())
        }
    }

    fn decapsulate_rx(&self, usb_packet: &[u8]) -> Option<(Option<i8>, Vec<u8>)> {
        let min_len = Self::RX_DMA_INFO_LEN + Self::RXWI_LEN;
        if usb_packet.len() < min_len {
            return None;
        }
        let dma_len = u16::from_le_bytes(usb_packet[0..2].try_into().ok()?) as usize;
        if dma_len < Self::RXWI_LEN
            || !dma_len.is_multiple_of(4)
            || Self::RX_DMA_INFO_LEN + dma_len > usb_packet.len()
        {
            return None;
        }
        let rxwi = &usb_packet[Self::RX_DMA_INFO_LEN..Self::RX_DMA_INFO_LEN + Self::RXWI_LEN];
        let rxinfo = u32::from_le_bytes(rxwi[0..4].try_into().ok()?);
        if rxinfo & (Self::RXINFO_CRCERR | Self::RXINFO_ICVERR | Self::RXINFO_MICERR) != 0 {
            return None;
        }
        let ctl = u32::from_le_bytes(rxwi[4..8].try_into().ok()?);
        let mpdu_len = ((ctl >> 16) & 0x3fff) as usize;
        let payload =
            &usb_packet[Self::RX_DMA_INFO_LEN + Self::RXWI_LEN..Self::RX_DMA_INFO_LEN + dma_len];
        let rssi = rxwi[12] as i8;
        let mpdu = if rxinfo & Self::RXINFO_L2PAD != 0 {
            let hdr_len = Self::ieee80211_hdr_len(payload)?;
            if mpdu_len < hdr_len || mpdu_len + 2 > payload.len() {
                return None;
            }
            let mut out = Vec::with_capacity(mpdu_len);
            out.extend_from_slice(&payload[..hdr_len]);
            out.extend_from_slice(&payload[hdr_len + 2..mpdu_len + 2]);
            out
        } else {
            if mpdu_len < 10 || mpdu_len > payload.len() {
                return None;
            }
            payload[..mpdu_len].to_vec()
        };
        Some((Some(rssi), mpdu))
    }
}

/// Qualcomm Atheros AR9271 (`ath9k_htc`) HTC + TX/RX USB framing and firmware chunker.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ar9271Codec;

impl Ar9271Codec {
    pub const USB_ID: (u16, u16) = (0x0cf3, 0x9271);
    pub const HTC_HEADER_LEN: usize = 8;
    pub const TX_HDR_LEN: usize = 12;
    pub const RX_STATUS_LEN: usize = 24;
    pub const EP_DATA: u8 = 0x03;
    pub const EP_MGMT: u8 = 0x02;
    pub const FW_DOWNLOAD_REQ: u8 = 0x30;
    pub const FW_DOWNLOAD_COMP: u8 = 0x31;
    pub const USB_EP_OUT_WLAN_TX: u8 = 0x01;
    pub const USB_EP_IN_WLAN_RX: u8 = 0x82;

    /// Builds an AR9271 RX USB packet (`HTC 8B + rx_status 24B + 802.11 MPDU`).
    pub fn encode_rx_packet(mpdu: &[u8], rssi_dbm: i8) -> Vec<u8> {
        let payload_len = u16::try_from(Self::RX_STATUS_LEN + mpdu.len()).unwrap_or(u16::MAX);
        let mut htc = [0u8; Self::HTC_HEADER_LEN];
        htc[0] = Self::EP_DATA;
        htc[1] = 0;
        htc[2..4].copy_from_slice(&payload_len.to_be_bytes());

        let mut rx_status = [0u8; Self::RX_STATUS_LEN];
        let rssi_rel = i16::from(rssi_dbm).saturating_sub(-95).clamp(0, 95) as u8;
        rx_status[0] = rssi_rel;
        let mpdu_len = u16::try_from(mpdu.len()).unwrap_or(u16::MAX);
        rx_status[2..4].copy_from_slice(&mpdu_len.to_be_bytes());

        let mut out = Vec::with_capacity(Self::HTC_HEADER_LEN + Self::RX_STATUS_LEN + mpdu.len());
        out.extend_from_slice(&htc);
        out.extend_from_slice(&rx_status);
        out.extend_from_slice(mpdu);
        out
    }

    /// Slices firmware binary into USB vendor control transfers (`0x30` chunks + `0x31` start).
    pub fn fw_download_transfers(fw_bytes: &[u8], load_addr: u16) -> Vec<VendorCtrlTransfer> {
        let mut transfers = Vec::new();
        let mut offset: usize = 0;
        for chunk in fw_bytes.chunks(4096) {
            let addr = load_addr.wrapping_add((offset >> 8) as u16);
            transfers.push(VendorCtrlTransfer {
                request_type: 0x40,
                request: Self::FW_DOWNLOAD_REQ,
                value: addr,
                index: 0,
                data: chunk.to_vec(),
            });
            offset += chunk.len();
        }
        transfers.push(VendorCtrlTransfer {
            request_type: 0x40,
            request: Self::FW_DOWNLOAD_COMP,
            value: load_addr,
            index: 0,
            data: Vec::new(),
        });
        transfers
    }
}

impl RadioWire for Ar9271Codec {
    fn name(&self) -> &'static str {
        "ar9271-htc-usb"
    }

    fn encapsulate_tx(&self, frame: &Frame) -> Vec<u8> {
        let payload_len = u16::try_from(Self::TX_HDR_LEN + frame.bytes.len()).unwrap_or(u16::MAX);
        let mut htc = [0u8; Self::HTC_HEADER_LEN];
        htc[0] = if frame.is_action() {
            Self::EP_MGMT
        } else {
            Self::EP_DATA
        };
        htc[2..4].copy_from_slice(&payload_len.to_be_bytes());

        let mut tx_hdr = [0u8; Self::TX_HDR_LEN];
        tx_hdr[0] = 0; // node_idx
        tx_hdr[1] = 0; // vif_idx
        tx_hdr[2] = u8::from(frame.no_ack); // flags
        let body_len = u16::try_from(frame.bytes.len()).unwrap_or(u16::MAX);
        tx_hdr[4..6].copy_from_slice(&body_len.to_be_bytes());

        let mut out =
            Vec::with_capacity(Self::HTC_HEADER_LEN + Self::TX_HDR_LEN + frame.bytes.len());
        out.extend_from_slice(&htc);
        out.extend_from_slice(&tx_hdr);
        out.extend_from_slice(&frame.bytes);
        out
    }

    fn decapsulate_tx(&self, usb_packet: &[u8]) -> Option<Vec<u8>> {
        let min_len = Self::HTC_HEADER_LEN + Self::TX_HDR_LEN;
        if usb_packet.len() < min_len {
            return None;
        }
        let ep = usb_packet[0];
        if ep != Self::EP_DATA && ep != Self::EP_MGMT {
            return None;
        }
        let payload_len = u16::from_be_bytes(usb_packet[2..4].try_into().ok()?) as usize;
        if payload_len < Self::TX_HDR_LEN || Self::HTC_HEADER_LEN + payload_len != usb_packet.len()
        {
            return None;
        }
        let tx_hdr = &usb_packet[Self::HTC_HEADER_LEN..min_len];
        let mpdu_len = u16::from_be_bytes(tx_hdr[4..6].try_into().ok()?) as usize;
        if mpdu_len < 10 || Self::TX_HDR_LEN + mpdu_len > payload_len {
            return None;
        }
        Some(usb_packet[min_len..min_len + mpdu_len].to_vec())
    }

    fn decapsulate_rx(&self, usb_packet: &[u8]) -> Option<(Option<i8>, Vec<u8>)> {
        let min_len = Self::HTC_HEADER_LEN + Self::RX_STATUS_LEN;
        if usb_packet.len() < min_len {
            return None;
        }
        let ep = usb_packet[0];
        if ep != Self::EP_DATA && ep != Self::EP_MGMT {
            return None;
        }
        let htc_payload_len = u16::from_be_bytes(usb_packet[2..4].try_into().ok()?) as usize;
        if htc_payload_len < Self::RX_STATUS_LEN
            || Self::HTC_HEADER_LEN + htc_payload_len > usb_packet.len()
        {
            return None;
        }
        let rx_status = &usb_packet[Self::HTC_HEADER_LEN..min_len];
        let rssi_dbm = (-95i16 + i16::from(rx_status[0])).clamp(-127, 0) as i8;
        let mpdu_len = u16::from_be_bytes(rx_status[2..4].try_into().ok()?) as usize;
        if mpdu_len < 10 || min_len + mpdu_len > usb_packet.len() {
            return None;
        }
        Some((
            Some(rssi_dbm),
            usb_packet[min_len..min_len + mpdu_len].to_vec(),
        ))
    }
}

#[cfg(all(
    feature = "usb",
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows",
        target_arch = "wasm32"
    )
))]
pub mod nusb_transport {
    //! Safe-Rust `nusb` bulk/control transport handle for detected AR9271 / MT7612U dongles.

    use std::io;
    use std::time::{Duration, Instant};

    use nusb::MaybeFuture;
    use nusb::descriptors::TransferType;
    use nusb::transfer::{Buffer, Bulk, ControlIn, ControlOut, ControlType, In, Out, Recipient};

    #[cfg(not(target_os = "android"))]
    use crate::air::usb::DetectedDongle;
    use crate::air::usb::SupportedDongle;

    impl From<SupportedDongle> for super::UsbChipset {
        fn from(value: SupportedDongle) -> Self {
            match value {
                SupportedDongle::Ar9271 => Self::Ar9271,
                SupportedDongle::Mt7612u => Self::Mt7612u,
            }
        }
    }

    /// Open `nusb` USB device handle with discovered bulk IN/OUT endpoints.
    pub struct UsbRadioHandle {
        pub kind: SupportedDongle,
        pub interface_number: u8,
        pub bulk_out_ep: u8,
        pub bulk_in_ep: u8,
        pub cmd_out_ep: Option<u8>,
        pub cmd_in_ep: Option<u8>,
        pub in_max_packet: usize,
        interface: nusb::Interface,
    }

    impl UsbRadioHandle {
        /// Opens the USB device matching `dongle` (`bus_id` + `device_address`), claims its
        /// primary interface, and selects chipset-aware Bulk IN/OUT endpoints.
        #[cfg(not(target_os = "android"))]
        pub fn open(dongle: &DetectedDongle) -> io::Result<Self> {
            let info = nusb::list_devices()
                .wait()
                .map_err(|e| io::Error::other(format!("list_devices: {e}")))?
                .find(|d| {
                    d.vendor_id() == dongle.vendor_id
                        && d.product_id() == dongle.product_id
                        && d.bus_id() == dongle.bus_id
                        && d.device_address() == dongle.device_address
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("USB device {} not found", dongle.kind.name()),
                    )
                })?;

            let device = info
                .open()
                .wait()
                .map_err(|e| io::Error::other(format!("device.open: {e}")))?;
            Self::from_device(dongle.kind, device)
        }

        /// Opens an already-authorized USB device file descriptor (for example from Android
        /// `UsbDeviceConnection.getFileDescriptor()` over USB OTG or Linux `usbfs`),
        /// claims its primary interface, and selects chipset-aware Bulk IN/OUT endpoints.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        pub fn open_from_fd(kind: SupportedDongle, fd: std::os::fd::OwnedFd) -> io::Result<Self> {
            let device = nusb::Device::from_fd(fd).wait().map_err(io::Error::other)?;
            Self::from_device(kind, device)
        }

        fn from_device(kind: SupportedDongle, device: nusb::Device) -> io::Result<Self> {
            let cfg = device.active_configuration().map_err(io::Error::other)?;

            let mut chosen: Option<(u8, super::SelectedEndpoints)> = None;
            for group in cfg.interfaces() {
                for alt in group.alt_settings() {
                    let bulk_eps: Vec<(u8, usize)> = alt
                        .endpoints()
                        .filter(|ep| ep.transfer_type() == TransferType::Bulk)
                        .map(|ep| (ep.address(), ep.max_packet_size()))
                        .collect();
                    if let Some(selected) = super::select_endpoints(kind.into(), &bulk_eps) {
                        chosen = Some((alt.interface_number(), selected));
                        break;
                    }
                }
                if chosen.is_some() {
                    break;
                }
            }

            let (interface_number, selected) = chosen.ok_or_else(|| {
                io::Error::other("USB device exposes no Bulk IN/OUT endpoint pair")
            })?;

            let interface = device
                .claim_interface(interface_number)
                .wait()
                .map_err(|e| {
                    io::Error::other(format!("claim_interface({interface_number}): {e}"))
                })?;

            Ok(Self {
                kind,
                interface_number,
                bulk_out_ep: selected.bulk_out_ep,
                bulk_in_ep: selected.bulk_in_ep,
                cmd_out_ep: selected.cmd_out_ep,
                cmd_in_ep: selected.cmd_in_ep,
                in_max_packet: selected.in_max_packet,
                interface,
            })
        }

        /// Issues a synchronous vendor OUT control transfer.
        pub fn control_out(
            &self,
            transfer: &super::VendorCtrlTransfer,
            timeout: Duration,
        ) -> io::Result<()> {
            self.interface
                .control_out(
                    ControlOut {
                        control_type: ControlType::Vendor,
                        recipient: Recipient::Device,
                        request: transfer.request,
                        value: transfer.value,
                        index: transfer.index,
                        data: &transfer.data,
                    },
                    timeout,
                )
                .wait()
                .map_err(io::Error::other)?;
            Ok(())
        }

        /// Issues a synchronous vendor IN control transfer.
        pub fn control_in(
            &self,
            transfer: &super::VendorCtrlTransfer,
            timeout: Duration,
        ) -> io::Result<Vec<u8>> {
            let len = transfer.data.len().clamp(1, u16::MAX as usize) as u16;
            self.interface
                .control_in(
                    ControlIn {
                        control_type: ControlType::Vendor,
                        recipient: Recipient::Device,
                        request: transfer.request,
                        value: transfer.value,
                        index: transfer.index,
                        length: len,
                    },
                    timeout,
                )
                .wait()
                .map_err(io::Error::other)
        }

        /// Reads a 32-bit little-endian MAC/BBP register (`VEND_MULTI_READ`).
        pub fn read_reg_u32(&self, addr: u32, timeout: Duration) -> io::Result<u32> {
            let bytes = self.control_in(&super::Mt7612uCodec::vendor_read_reg(addr), timeout)?;
            let raw: [u8; 4] = bytes.try_into().map_err(|v: Vec<u8>| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected 4-byte register read, got {}", v.len()),
                )
            })?;
            Ok(u32::from_le_bytes(raw))
        }

        /// Writes a 32-bit little-endian MAC/BBP register (`VEND_MULTI_WRITE`).
        pub fn write_reg_u32(&self, addr: u32, val: u32, timeout: Duration) -> io::Result<()> {
            self.control_out(&super::Mt7612uCodec::vendor_write_reg(addr, val), timeout)
        }

        /// Issues a synchronous USB Class OUT control transfer (`ControlType::Class`).
        pub fn control_class_out(
            &self,
            request: u8,
            value: u16,
            index: u16,
            data: &[u8],
            timeout: Duration,
        ) -> io::Result<()> {
            self.interface
                .control_out(
                    ControlOut {
                        control_type: ControlType::Class,
                        recipient: Recipient::Device,
                        request,
                        value,
                        index,
                        data,
                    },
                    timeout,
                )
                .wait()
                .map_err(io::Error::other)?;
            Ok(())
        }

        /// Reads a 32-bit little-endian configuration register (`VEND_READ_CFG`).
        pub fn read_cfg_u32(&self, addr: u32, timeout: Duration) -> io::Result<u32> {
            let bytes = self.control_in(&super::Mt7612uCodec::vendor_read_cfg(addr), timeout)?;
            let raw: [u8; 4] = bytes.try_into().map_err(|v: Vec<u8>| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected 4-byte cfg read, got {}", v.len()),
                )
            })?;
            Ok(u32::from_le_bytes(raw))
        }

        /// Writes a 32-bit little-endian configuration register (`VEND_WRITE_CFG`).
        pub fn write_cfg_u32(&self, addr: u32, val: u32, timeout: Duration) -> io::Result<()> {
            self.control_out(&super::Mt7612uCodec::vendor_write_cfg(addr, val), timeout)
        }

        /// Read-modify-writes a 32-bit configuration register and returns the new value.
        pub fn rmw_cfg_u32(
            &self,
            addr: u32,
            clear: u32,
            set: u32,
            timeout: Duration,
        ) -> io::Result<u32> {
            let next = (self.read_cfg_u32(addr, timeout)? & !clear) | set;
            self.write_cfg_u32(addr, next, timeout)?;
            Ok(next)
        }

        /// Read-modify-writes a 32-bit MAC/BBP register and returns the new value.
        pub fn rmw_reg_u32(
            &self,
            addr: u32,
            clear: u32,
            set: u32,
            timeout: Duration,
        ) -> io::Result<u32> {
            let next = (self.read_reg_u32(addr, timeout)? & !clear) | set;
            self.write_reg_u32(addr, next, timeout)?;
            Ok(next)
        }

        /// Polls a 32-bit MAC/BBP register until `(val & mask) == expected`.
        pub fn poll_reg_u32(
            &self,
            addr: u32,
            mask: u32,
            expected: u32,
            max_wait: Duration,
        ) -> io::Result<u32> {
            let deadline = Instant::now() + max_wait;
            let per_io = Duration::from_millis(250);
            loop {
                let val = self.read_reg_u32(addr, per_io)?;
                if (val & mask) == expected {
                    return Ok(val);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "reg 0x{addr:04x} poll timeout: val=0x{val:08x} mask=0x{mask:08x} want=0x{expected:08x}"
                        ),
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        /// Polls a 32-bit configuration register until `(val & mask) == expected`.
        pub fn poll_cfg_u32(
            &self,
            addr: u32,
            mask: u32,
            expected: u32,
            max_wait: Duration,
        ) -> io::Result<u32> {
            let deadline = Instant::now() + max_wait;
            let per_io = Duration::from_millis(250);
            loop {
                let val = self.read_cfg_u32(addr, per_io)?;
                if (val & mask) == expected {
                    return Ok(val);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "cfg 0x{addr:04x} poll timeout: val=0x{val:08x} mask=0x{mask:08x} want=0x{expected:08x}"
                        ),
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        /// Reads the 512-byte MT7612U EEPROM via eFuse (`0x0024..0x0034`), falling back to `VEND_READ_EEPROM`.
        pub fn read_eeprom_512(&self, timeout: Duration) -> io::Result<[u8; 512]> {
            const REG_EFUSE_CTRL: u32 = 0x0024;
            const REG_EFUSE_DATA_BASE: u32 = 0x0028;
            const EFUSE_AIN_AND_MODE_MASK: u32 = (0x3ff << 16) | (0x03 << 6);
            const EFUSE_KICK: u32 = 1 << 30;

            let valid_id = |buf: &[u8; 512]| {
                let chip_id = u16::from_le_bytes([buf[0], buf[1]]);
                let pci_id = u16::from_le_bytes([buf[0x0a], buf[0x0b]]);
                matches!(chip_id, 0x7612 | 0x7662 | 0x7632)
                    || matches!(pci_id, 0x7612 | 0x7662 | 0x7632)
            };

            let mut efuse = [0u8; 512];
            let mut efuse_ok = true;
            for base in (0..512usize).step_by(16) {
                let ain = ((base as u32) & !0x0f) << 16;
                if self
                    .rmw_reg_u32(
                        REG_EFUSE_CTRL,
                        EFUSE_AIN_AND_MODE_MASK,
                        ain | EFUSE_KICK,
                        timeout,
                    )
                    .is_err()
                    || self
                        .poll_reg_u32(REG_EFUSE_CTRL, EFUSE_KICK, 0, Duration::from_millis(500))
                        .is_err()
                {
                    efuse_ok = false;
                    break;
                }
                std::thread::sleep(Duration::from_micros(50));
                let ctrl = self.read_reg_u32(REG_EFUSE_CTRL, timeout)?;
                if (ctrl & 0x3f) == 0x3f {
                    efuse[base..base + 16].fill(0xff);
                } else {
                    for word in 0..4usize {
                        let val =
                            self.read_reg_u32(REG_EFUSE_DATA_BASE + ((word as u32) << 2), timeout)?;
                        efuse[base + word * 4..base + word * 4 + 4]
                            .copy_from_slice(&val.to_le_bytes());
                    }
                }
            }
            if efuse_ok && valid_id(&efuse) {
                return Ok(efuse);
            }

            let mut vend = [0u8; 512];
            for offset in (0..512usize).step_by(4) {
                let bytes = self.control_in(
                    &super::VendorCtrlTransfer {
                        request_type: 0xc0,
                        request: super::Mt7612uCodec::VEND_READ_EEPROM,
                        value: 0,
                        index: offset as u16,
                        data: vec![0u8; 4],
                    },
                    timeout,
                )?;
                let raw: [u8; 4] = bytes.try_into().map_err(|v: Vec<u8>| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "expected 4-byte EEPROM read at 0x{offset:03x}, got {}",
                            v.len()
                        ),
                    )
                })?;
                vend[offset..offset + 4].copy_from_slice(&raw);
            }
            if valid_id(&vend) || !efuse_ok {
                Ok(vend)
            } else {
                Ok(efuse)
            }
        }

        /// Sends an inband MCU command over EP `0x08` and optionally waits for `EVT_CMD_DONE` on EP `0x85`.
        pub fn send_mcu_cmd(
            &self,
            cmd: u8,
            seq: u8,
            payload: &[u8],
            wait_resp: bool,
            timeout: Duration,
        ) -> io::Result<()> {
            let seq4 = if seq & 0x0f == 0 { 1 } else { seq & 0x0f };
            let packet = super::Mt7612uCodec::encode_mcu_cmd(cmd, seq4, payload);
            self.send_cmd(&packet, timeout)?;
            if !wait_resp {
                return Ok(());
            }

            let mut timeouts = 0usize;
            for _ in 0..8usize {
                match self.recv_cmd(512, Duration::from_millis(300)) {
                    Ok(buf) => {
                        if buf.len() < 4 {
                            continue;
                        }
                        let rxfce = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                        let evt_seq = ((rxfce >> 16) & 0x0f) as u8;
                        let evt_type = (rxfce >> 20) & 0x0f;
                        if evt_seq == seq4 && evt_type == 0 {
                            return Ok(());
                        }
                    }
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                                | io::ErrorKind::WouldBlock
                        ) =>
                    {
                        timeouts += 1;
                        if timeouts >= 5 {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!("MCU cmd 0x{cmd:02x} seq {seq4} response timed out"),
                            ));
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("MCU cmd 0x{cmd:02x} seq {seq4} did not receive EVT_CMD_DONE"),
            ))
        }

        /// Opens owned Bulk OUT and Bulk IN endpoints for dedicated TX and continuous RX streaming.
        pub fn open_data_endpoints(
            &self,
        ) -> io::Result<(nusb::Endpoint<Bulk, Out>, nusb::Endpoint<Bulk, In>)> {
            let out_ep = self
                .interface
                .endpoint::<Bulk, Out>(self.bulk_out_ep)
                .map_err(io::Error::other)?;
            let in_ep = self
                .interface
                .endpoint::<Bulk, In>(self.bulk_in_ep)
                .map_err(io::Error::other)?;
            Ok((out_ep, in_ep))
        }

        pub(crate) fn upload_mt7612u_chunk(
            &self,
            chunk: &super::Mt7612uFwChunk,
            timeout: Duration,
        ) -> io::Result<()> {
            for transfer in &chunk.addr_ctrl {
                self.control_out(transfer, timeout)?;
            }
            for transfer in &chunk.len_ctrl {
                self.control_out(transfer, timeout)?;
            }
            self.send_cmd(&chunk.bulk_frame, timeout)?;

            // The FCE consumes one descriptor per upload. Without advancing
            // this index the first chunk succeeds but subsequent chunks
            // overwrite a descriptor the device has already consumed.
            let idx = self.read_reg_u32(
                super::Mt7612uCodec::REG_TX_CPU_FROM_FCE_CPU_DESC_IDX,
                timeout,
            )?;
            self.write_reg_u32(
                super::Mt7612uCodec::REG_TX_CPU_FROM_FCE_CPU_DESC_IDX,
                idx.wrapping_add(1),
                timeout,
            )?;
            std::thread::sleep(Duration::from_millis(5));
            Ok(())
        }

        /// Uploads `patch` (`mt7662u_rom_patch.bin`) and `fw`
        /// (`mt7662u.bin`) over EP `0x08` + FCE DMA.
        ///
        /// This performs the image transfer only. A complete userspace
        /// driver must also perform the chipset's reset, patch-enable,
        /// firmware-start, EEPROM, calibration, and MCU channel sequences.
        pub fn load_mt7612u_firmware(
            &self,
            patch: &super::Mt7612uRomPatch,
            fw: &super::Mt7612uFirmware,
            timeout: Duration,
        ) -> io::Result<()> {
            if self.kind != SupportedDongle::Mt7612u {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "load_mt7612u_firmware requires an MT7612U dongle",
                ));
            }
            for chunk in super::Mt7612uCodec::fw_upload_chunks(
                super::Mt7612uCodec::PATCH_LOAD_ADDR,
                &patch.payload,
                super::Mt7612uCodec::ROM_PATCH_MAX_CHUNK_LEN,
            ) {
                self.upload_mt7612u_chunk(&chunk, timeout)?;
            }
            for (base, bytes) in [
                (super::Mt7612uCodec::FW_ILM_LOAD_ADDR, &fw.ilm),
                (super::Mt7612uCodec::FW_DLM_LOAD_ADDR, &fw.dlm),
            ] {
                for chunk in super::Mt7612uCodec::fw_upload_chunks(
                    base,
                    bytes,
                    super::Mt7612uCodec::FW_MAX_CHUNK_LEN,
                ) {
                    self.upload_mt7612u_chunk(&chunk, timeout)?;
                }
            }
            Ok(())
        }

        /// Sends a USB bulk OUT data frame buffer.
        pub fn send_bulk(&self, data: &[u8], timeout: Duration) -> io::Result<()> {
            self.send_to_ep(self.bulk_out_ep, data, timeout)
        }

        /// Sends a USB bulk OUT MCU/inband command buffer (MT7612U `0x08`).
        pub fn send_cmd(&self, data: &[u8], timeout: Duration) -> io::Result<()> {
            let ep = self.cmd_out_ep.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "dongle exposes no bulk command OUT endpoint",
                )
            })?;
            self.send_to_ep(ep, data, timeout)
        }

        /// Reads up to `min_bytes` (rounded up to `in_max_packet`) from Bulk IN data endpoint.
        pub fn recv_bulk(&self, min_bytes: usize, timeout: Duration) -> io::Result<Vec<u8>> {
            self.recv_from_ep(self.bulk_in_ep, min_bytes, timeout)
        }

        /// Reads up to `min_bytes` (rounded up to `in_max_packet`) from Bulk IN command endpoint.
        pub fn recv_cmd(&self, min_bytes: usize, timeout: Duration) -> io::Result<Vec<u8>> {
            let ep = self.cmd_in_ep.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "dongle exposes no bulk command IN endpoint",
                )
            })?;
            self.recv_from_ep(ep, min_bytes, timeout)
        }

        fn send_to_ep(&self, ep_addr: u8, data: &[u8], timeout: Duration) -> io::Result<()> {
            let mut ep = self
                .interface
                .endpoint::<Bulk, Out>(ep_addr)
                .map_err(io::Error::other)?;
            ep.transfer_blocking(data.to_vec().into(), timeout)
                .into_result()
                .map_err(io::Error::other)?;
            Ok(())
        }

        fn recv_from_ep(
            &self,
            ep_addr: u8,
            min_bytes: usize,
            timeout: Duration,
        ) -> io::Result<Vec<u8>> {
            let mut ep = self
                .interface
                .endpoint::<Bulk, In>(ep_addr)
                .map_err(io::Error::other)?;
            let aligned = min_bytes.max(1).div_ceil(self.in_max_packet) * self.in_max_packet;
            let buf = ep
                .transfer_blocking(Buffer::new(aligned), timeout)
                .into_result()
                .map_err(io::Error::other)?;
            Ok(buf.into_vec())
        }
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "android")))]
    mod tests {
        use std::os::fd::OwnedFd;

        use super::*;

        #[test]
        fn open_from_fd_rejects_non_usbfs_descriptor() {
            let file = tempfile::tempfile().unwrap();
            let err = UsbRadioHandle::open_from_fd(SupportedDongle::Mt7612u, OwnedFd::from(file))
                .err()
                .expect("non-usbfs descriptor must fail cleanly");
            assert!(!err.to_string().is_empty());
        }
    }
}
