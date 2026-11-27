//! Clean-room safe-Rust (`#![forbid(unsafe_code)]`) USB radio driver for MediaTek MT7612U (`mt76x2u`).
//!
//! Drives a WinUSB / usbfs MT7612U dongle (`0e8d:7612`) via `nusb` in active-monitor mode:
//! - Full chip power-on, eFuse/EEPROM read, ROM patch (`0x0009_0000`) & MCU ILM/DLM load (`0x0008_0000` / `0x0011_0800`)
//! - MAC/BBP initialization, XTAL fixup, CR loading, channel tuning, and RF/IQ/LC/RXDCOC/TXLOFT calibration
//! - Continuous asynchronous queued `nusb` Bulk IN MPDU receiver (`EP 0x84`) and Bulk OUT TX (`EP 0x04`)

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nusb::Endpoint;
use nusb::transfer::{Buffer, Bulk, In, Out};
use owly_awdl::Frame;
use owly_awdl::channel::Channel;

#[cfg(not(target_os = "android"))]
use crate::air::usb::DetectedDongle;
use crate::air::usb::SupportedDongle;
use crate::usb_radio::nusb_transport::UsbRadioHandle;
use crate::usb_radio::{Mt7612uCodec, Mt7612uFirmware, Mt7612uRomPatch, RadioWire};

const CTRL_TIMEOUT: Duration = Duration::from_millis(1_000);
const BULK_TIMEOUT: Duration = Duration::from_millis(1_000);
const RX_BUF_LEN: usize = 16 * 1024;
const RX_QUEUE_DEPTH: usize = 8;

// MCU opcodes (CMD_*).
const CMD_FUN_SET_OP: u8 = 1;
const CMD_LOAD_CR: u8 = 2;
const CMD_INIT_GAIN_OP: u8 = 3;
const CMD_POWER_SAVING_OP: u8 = 20;
const CMD_SWITCH_CHANNEL_OP: u8 = 30;
const CMD_CALIBRATION_OP: u8 = 31;

// MCU calibration IDs.
const MCU_CAL_R: u32 = 1;
const MCU_CAL_TEMP_SENSOR: u32 = 2;
const MCU_CAL_RXDCOC: u32 = 3;
const MCU_CAL_RC: u32 = 4;
const MCU_CAL_LC: u32 = 6;
const MCU_CAL_TX_LOFT: u32 = 7;
const MCU_CAL_TXIQ: u32 = 8;
const MCU_CAL_RXIQC_FI: u32 = 12;
const MCU_CAL_TX_SHAPING: u32 = 15;

// MCU power modes & CR load types.
const RADIO_OFF: u32 = 0x30;
const RADIO_ON: u32 = 0x31;
const MT_RF_BBP_CR: u8 = 2;

// EEPROM offsets.
const EE_MAC_ADDR: usize = 0x004;
const EE_NIC_CONF_0: usize = 0x034;
const EE_NIC_CONF_1: usize = 0x036;
const EE_XTAL_TRIM_1: usize = 0x03a;
const EE_NIC_CONF_2: usize = 0x042;
const EE_LNA_GAIN: usize = 0x044;
const EE_RSSI_OFFSET_2G_1: usize = 0x048;
const EE_RSSI_OFFSET_5G_1: u16 = 0x04c;
const EE_XTAL_TRIM_2: usize = 0x09e;
const EE_BT_RCAL_RESULT: usize = 0x138;

// Initial MAC/BBP register table for MT7612U (`mt76x2_init.c` + protection table).
const MAC_INIT_VALS: &[(u32, u32)] = &[
    (0x0400, 0x0008_0c00), // MT_PBF_SYS_CTRL
    (0x0404, 0x1efe_bcff), // MT_PBF_CFG
    (0x0800, 0x0000_0001), // MT_FCE_PSE_CTRL
    (0x1004, 0x0000_0000), // MT_MAC_SYS_CTRL
    (0x1018, 0x003e_3f00), // MT_MAX_LEN_CFG
    (0x1030, 0xaaa9_9887), // MT_AMPDU_MAX_LEN_20M1S
    (0x1034, 0x0000_00aa), // MT_AMPDU_MAX_LEN_20M2S
    (0x1100, 0x33a4_0d0a), // MT_XIFS_TIME_CFG
    (0x1104, 0x0000_0209), // MT_BKOFF_SLOT_CFG
    (0x1118, 0x0042_2010), // MT_TBTT_SYNC_CFG
    (0x1204, 0x0000_0000), // MT_PWR_PIN_CFG
    (0x1238, 0x0017_00c8),
    (0x1330, 0x0010_1001), // MT_TX_SW_CFG0
    (0x1334, 0x0001_0000), // MT_TX_SW_CFG1
    (0x1338, 0x0000_0000), // MT_TX_SW_CFG2
    (0x1340, 0x0400_583f), // MT_TXOP_CTRL_CFG
    (0x1344, 0x00ff_ff20), // MT_TX_RTS_CFG
    (0x1348, 0x000a_2290), // MT_TX_TIMEOUT_CFG
    (0x134c, 0x47f0_1f0f), // MT_TX_RETRY_CFG
    (0x1380, 0x002c_00dc), // MT_EXP_ACK_TIME
    (0x13e0, 0xe3f4_2004), // MT_TX_PROT_CFG6
    (0x13e4, 0xe3f4_2084), // MT_TX_PROT_CFG7
    (0x13e8, 0xe3f4_2104), // MT_TX_PROT_CFG8
    (0x13ec, 0x0006_0fff), // MT_PIFS_TX_CFG
    (0x1400, 0x0001_5f97), // MT_RX_FILTR_CFG
    (0x1408, 0x0000_017f), // MT_LEGACY_BASIC_RATE
    (0x140c, 0x0000_4003), // MT_HT_BASIC_RATE
    (0x150c, 0x0000_0003), // MT_PN_PAD_MODE
    (0x1608, 0x0000_0002), // MT_TXOP_HLDR_ET
    (0x0a44, 0x0000_0000),
    (0x0260, 0x0000_0000),               // MT_HEADER_TRANS_CTRL_REG
    (0x0250, 0x0000_0000),               // MT_TSO_CTRL
    (0x120c, 0x0000_0000),               // MT_AUX_CLK_CFG
    (0x1264, 0x0000_0000),               // MT_DACCLK_EN_DLY_CFG
    (0x13c0, 0x0000_0000),               // MT_TX_ALC_CFG_4
    (0x13c8, 0x0000_0000),               // MT_TX_ALC_VGA3
    (0x1314, 0x3a3a_3a3a),               // MT_TX_PWR_CFG_0
    (0x1318, 0x3a3a_3a3a),               // MT_TX_PWR_CFG_1
    (0x131c, 0x3a3a_3a3a),               // MT_TX_PWR_CFG_2
    (0x1320, 0x3a3a_3a3a),               // MT_TX_PWR_CFG_3
    (0x1324, 0x3a3a_3a3a),               // MT_TX_PWR_CFG_4
    (0x13d4, 0x3a3a_3a3a),               // MT_TX_PWR_CFG_7
    (0x13d8, 0x0000_003a),               // MT_TX_PWR_CFG_8
    (0x13dc, 0x0000_003a),               // MT_TX_PWR_CFG_9
    (0x0024, 0x0000_d000),               // MT_EFUSE_CTRL
    (0x0a38, 0x0000_000a),               // MT_PAUSE_ENABLE_CONTROL1
    (0x0824, 0x6040_1c18),               // MT_FCE_WLAN_FLOW_CONTROL1
    (0x0210, 0x94ff_0000),               // MT_WPDMA_DELAY_INT_CFG
    (0x1478, 0x0000_0004),               // MT_TX_SW_CFG3
    (0x1384, 0x0000_1818),               // MT_HT_FBK_TO_LEGACY
    (0x1358, 0xedc8_a980 | 0x0030_0000), // 0xedcba980: MT_VHT_HT_FBK_CFG1
    (0x1648, 0x0083_0083),               // MT_PROT_AUTO_TX_CFG
    (0x1410, 0x0000_01ff),               // MT_HT_CTRL_CFG
    (0x1350, 0x0000_1020),               // MT_TX_LINK_CFG
    // Protection defaults
    (0x1364, 0x07f4_0003), // MT_CCK_PROT_CFG
    (0x1368, 0x07f4_2004), // MT_OFDM_PROT_CFG
    (0x136c, 0x0175_2004), // MT_MM20_PROT_CFG
    (0x1370, 0x03f5_2084), // MT_MM40_PROT_CFG
    (0x1374, 0x0175_2004), // MT_GF20_PROT_CFG
    (0x1378, 0x03f5_2084), // MT_GF40_PROT_CFG
];

// Active-monitor RX filter: passes Monitor/MCAST/BCAST/CTRL ACKed packets &
// AWDL frames addressed to `mac` while letting hardware drop CRC/PHY/version errors.
const ACTIVE_MONITOR_RX_FILTER: u32 = 0x0001_5f93;

/// Initialized MediaTek MT7612U userspace radio handle with active RX stream thread.
pub struct Mt7612uRadio {
    handle: UsbRadioHandle,
    bulk_out: Endpoint<Bulk, Out>,
    stop: Arc<AtomicBool>,
    rx_thread: Option<JoinHandle<()>>,
    rx_ch: Receiver<(Option<i8>, Vec<u8>)>,
    mac: [u8; 6],
    asic_ver: u32,
    eeprom: [u8; 512],
    channel: Channel,
    mcu_seq: u8,
}

impl Mt7612uRadio {
    /// Opens `dongle` via `nusb` and initializes it into active-monitor AWDL mode on `channel`.
    #[cfg(not(target_os = "android"))]
    pub fn open_and_init(
        dongle: &DetectedDongle,
        patch: &Mt7612uRomPatch,
        fw: &Mt7612uFirmware,
        mac_override: Option<[u8; 6]>,
        channel: Channel,
    ) -> io::Result<Self> {
        if dongle.kind != SupportedDongle::Mt7612u {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("expected MT7612U dongle, got {}", dongle.kind.name()),
            ));
        }
        let handle = UsbRadioHandle::open(dongle).map_err(|e| phase_err("open_usb", e))?;
        Self::from_handle_and_init(handle, patch, fw, mac_override, channel)
    }

    /// Initializes an already-opened MT7612U `UsbRadioHandle` into active-monitor mode on `channel`.
    pub fn from_handle_and_init(
        handle: UsbRadioHandle,
        patch: &Mt7612uRomPatch,
        fw: &Mt7612uFirmware,
        mac_override: Option<[u8; 6]>,
        channel: Channel,
    ) -> io::Result<Self> {
        if handle.kind != SupportedDongle::Mt7612u {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "from_handle_and_init requires an MT7612U UsbRadioHandle",
            ));
        }

        let asic_ver = handle
            .read_reg_u32(Mt7612uCodec::REG_ASIC_VERSION, CTRL_TIMEOUT)
            .map_err(|e| phase_err("read_asic_version", e))?;
        let chip_id = (asic_ver >> 16) as u16;
        if !matches!(chip_id, 0x7612 | 0x7662 | 0x7632) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected MT76x2 ASIC_VERSION 0x{asic_ver:08x}"),
            ));
        }
        let rev_e3 = (asic_ver & 0xffff) >= 0x0033;
        let rom_protect = chip_id != 0x7612;

        reset_wlan(&handle).map_err(|e| phase_err("reset_wlan", e))?;
        power_on(&handle).map_err(|e| phase_err("power_on", e))?;
        wait_for_mac(&handle).map_err(|e| phase_err("wait_for_mac_pre_fw", e))?;

        let eeprom = handle
            .read_eeprom_512(CTRL_TIMEOUT)
            .map_err(|e| phase_err("read_eeprom_512", e))?;
        let mac = pick_mac_address(&eeprom, mac_override);

        load_rom_patch(&handle, rev_e3, rom_protect, patch)
            .map_err(|e| phase_err("load_rom_patch", e))?;
        load_firmware(&handle, rev_e3, fw).map_err(|e| phase_err("load_firmware", e))?;

        handle
            .poll_reg_u32(0x0208, 0x0a, 0, Duration::from_millis(200))
            .map_err(|e| phase_err("poll_wpdma_post_fw", e))?;
        wait_for_mac(&handle).map_err(|e| phase_err("wait_for_mac_post_fw", e))?;
        init_dma(&handle).map_err(|e| phase_err("init_dma", e))?;

        let (bulk_out, in_ep) = handle
            .open_data_endpoints()
            .map_err(|e| phase_err("open_data_endpoints", e))?;
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx_ch) = mpsc::sync_channel(2048);
        let stop_rx = Arc::clone(&stop);
        let rx_thread = thread::Builder::new()
            .name("mt7612u-rx".to_string())
            .spawn(move || rx_worker(in_ep, stop_rx, tx))?;

        let mut radio = Self {
            handle,
            bulk_out,
            stop,
            rx_thread: Some(rx_thread),
            rx_ch,
            mac,
            asic_ver,
            eeprom,
            channel,
            mcu_seq: 0,
        };

        radio.mcu_init().map_err(|e| phase_err("mcu_init", e))?;
        radio.mac_reset().map_err(|e| phase_err("mac_reset", e))?;
        mac_setaddr(&radio.handle, radio.mac).map_err(|e| phase_err("mac_setaddr", e))?;
        reset_wcid_and_keys(&radio.handle).map_err(|e| phase_err("reset_wcid_and_keys", e))?;
        radio
            .handle
            .write_reg_u32(0x1114, 0, CTRL_TIMEOUT)
            .map_err(|e| phase_err("beacon_off", e))?;
        radio
            .handle
            .rmw_reg_u32(0x02a4, 0xff, 0x1e, CTRL_TIMEOUT)
            .map_err(|e| phase_err("us_cyc", e))?;
        radio
            .handle
            .write_reg_u32(0x1340, 0x583f, CTRL_TIMEOUT)
            .map_err(|e| phase_err("txop_ctrl", e))?;

        radio
            .mcu_load_cr()
            .map_err(|e| phase_err("mcu_load_cr", e))?;
        // Set 2x2 RX path and 2-stream TX DAC before tuning channel.
        radio
            .handle
            .rmw_reg_u32(0x2300, 1 << 4, 1 << 3, CTRL_TIMEOUT)
            .map_err(|e| phase_err("rxpath", e))?;
        radio
            .handle
            .rmw_reg_u32(0x2714, 0, 0x3, CTRL_TIMEOUT)
            .map_err(|e| phase_err("txdac", e))?;

        radio
            .set_channel(channel)
            .map_err(|e| phase_err("set_channel", e))?;
        radio.mac_start().map_err(|e| phase_err("mac_start", e))?;

        Ok(radio)
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub fn asic_version(&self) -> u32 {
        self.asic_ver
    }

    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// Encapsulates and submits one 802.11 frame to Bulk OUT `EP 0x04`.
    pub fn send_frame(&mut self, frame: &Frame) -> io::Result<()> {
        let urb = Mt7612uCodec.encapsulate_tx(frame);
        self.bulk_out
            .transfer_blocking(urb.into(), BULK_TIMEOUT)
            .into_result()
            .map_err(io::Error::other)?;
        Ok(())
    }

    /// Non-blocking poll for one decoded `(Option<rssi_dbm>, 802.11_mpdu)` from `EP 0x84`.
    pub fn try_recv_mpdu(&mut self) -> Option<(Option<i8>, Vec<u8>)> {
        self.rx_ch.try_recv().ok()
    }

    /// Drains up to 16 pending TX status FIFO entries (`0x1718`) so the FIFO never stalls.
    pub fn drain_tx_status(&self) {
        for _ in 0..16 {
            let Ok(fifo) = self.handle.read_reg_u32(0x1718, Duration::from_millis(50)) else {
                break;
            };
            if fifo & 1 == 0 {
                break;
            }
            let _ = self.handle.read_reg_u32(0x1798, Duration::from_millis(50));
        }
    }

    /// Tunes the MT7612U radio to `channel` (20 MHz active-monitor mode).
    pub fn set_channel(&mut self, channel: Channel) -> io::Result<()> {
        let is_5g = match channel.0 {
            1..=13 => false,
            36..=165 => true,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported MT7612U channel {other}"),
                ));
            }
        };

        let ext_pa = has_ext_pa(&self.eeprom, is_5g);
        let ext_lna = has_ext_lna(&self.eeprom, is_5g);
        let mcu_gain = compute_mcu_gain(&self.eeprom);

        set_txpower_regs(&self.handle, is_5g, ext_pa)?;
        configure_tx_delay(&self.handle, ext_pa)?;

        // Baseline TX ALC + per-rate offset (0 dB delta => CH_INIT = 0x22).
        self.handle
            .write_reg_u32(0x13b0, 0x2f2f_2222, CTRL_TIMEOUT)?;
        for reg in [
            0x1314u32, 0x1318, 0x131c, 0x1320, 0x1324, 0x13d4, 0x13d8, 0x13dc,
        ] {
            self.handle.write_reg_u32(reg, 0, CTRL_TIMEOUT)?;
        }

        // Band select & 20 MHz BW.
        if is_5g {
            self.handle
                .rmw_reg_u32(0x132c, (1 << 2) | 1, 1 << 1, CTRL_TIMEOUT)?;
        } else {
            self.handle
                .rmw_reg_u32(0x132c, (1 << 1) | 1, 1 << 2, CTRL_TIMEOUT)?;
        }
        self.handle.rmw_reg_u32(0x2004, 0x3 << 3, 0, CTRL_TIMEOUT)?;
        self.handle
            .rmw_reg_u32(0x2300, (0x7 << 12) | (0x3 << 8), 1 << 12, CTRL_TIMEOUT)?;
        self.handle.rmw_reg_u32(0x2700, 0x3, 0, CTRL_TIMEOUT)?;
        self.handle
            .rmw_reg_u32(0x141c, 0x0fff, 0x01e4, CTRL_TIMEOUT)?;

        // CMD_SWITCH_CHANNEL_OP (without ext_chan, then ext_chan = 0xe0).
        let ch = channel.0;
        let msg_a = [ch, 0, 0, 0, 0x02, 0x02, 0x00, 0x00];
        let seq = self.next_seq();
        self.handle
            .send_mcu_cmd(CMD_SWITCH_CHANNEL_OP, seq, &msg_a, true, CTRL_TIMEOUT)?;
        thread::sleep(Duration::from_millis(10));
        let msg_b = [ch, 0, 0, 0, 0x02, 0x02, 0xe0, 0x00];
        let seq = self.next_seq();
        self.handle
            .send_mcu_cmd(CMD_SWITCH_CHANNEL_OP, seq, &msg_b, true, CTRL_TIMEOUT)?;

        // CMD_INIT_GAIN_OP (force = true => bit 31).
        let mut gain_msg = [0u8; 8];
        gain_msg[0..4].copy_from_slice(&(u32::from(ch) | (1 << 31)).to_le_bytes());
        gain_msg[4..8].copy_from_slice(&mcu_gain.to_le_bytes());
        let seq = self.next_seq();
        self.handle
            .send_mcu_cmd(CMD_INIT_GAIN_OP, seq, &gain_msg, true, CTRL_TIMEOUT)?;

        // Enable LDPC RX.
        self.handle.rmw_reg_u32(0x2934, 0, 1 << 10, CTRL_TIMEOUT)?;

        if self.eeprom[EE_BT_RCAL_RESULT] != 0xff {
            self.calibrate(MCU_CAL_R, 0)?;
        }
        self.calibrate(MCU_CAL_RXDCOC, u32::from(ch))?;
        self.calibrate(MCU_CAL_RC, 0)?;

        self.handle
            .write_reg_u32(0x23f4, 0xff64_a4e2, CTRL_TIMEOUT)?;
        self.handle
            .write_reg_u32(0x231c, 0x0808_1010, CTRL_TIMEOUT)?;
        self.handle
            .write_reg_u32(0x232c, 0x0000_0404, CTRL_TIMEOUT)?;
        self.handle
            .write_reg_u32(0x2308, 0x0000_7070, CTRL_TIMEOUT)?;
        self.handle
            .write_reg_u32(0x1340, 0x0410_1b3f, CTRL_TIMEOUT)?;
        self.handle.rmw_reg_u32(0x2610, 0, 1 << 25, CTRL_TIMEOUT)?;
        self.handle.rmw_reg_u32(0x2934, 0, 1 << 8, CTRL_TIMEOUT)?;

        let band_arg = u32::from(is_5g);
        if is_5g {
            self.calibrate(MCU_CAL_LC, 0)?;
        }
        self.calibrate(MCU_CAL_TX_LOFT, band_arg)?;
        self.calibrate(MCU_CAL_TXIQ, band_arg)?;
        self.calibrate(MCU_CAL_RXIQC_FI, band_arg)?;
        self.calibrate(MCU_CAL_TEMP_SENSOR, 0)?;
        self.calibrate(MCU_CAL_TX_SHAPING, 0)?;

        edcca_init(&self.handle)?;
        update_channel_gain(&self.handle, is_5g, ext_lna)?;

        self.channel = channel;
        Ok(())
    }

    fn next_seq(&mut self) -> u8 {
        self.mcu_seq = (self.mcu_seq % 15) + 1;
        self.mcu_seq
    }

    fn mcu_init(&mut self) -> io::Result<()> {
        let mut qsel = [0u8; 8];
        qsel[0..4].copy_from_slice(&1u32.to_le_bytes()); // Q_SELECT = 1
        qsel[4..8].copy_from_slice(&1u32.to_le_bytes());
        let seq = self.next_seq();
        self.handle
            .send_mcu_cmd(CMD_FUN_SET_OP, seq, &qsel, false, CTRL_TIMEOUT)?;

        let mut power = [0u8; 8];
        power[0..4].copy_from_slice(&RADIO_ON.to_le_bytes());
        let seq = self.next_seq();
        self.handle
            .send_mcu_cmd(CMD_POWER_SAVING_OP, seq, &power, false, CTRL_TIMEOUT)
    }

    fn mac_reset(&self) -> io::Result<()> {
        self.handle
            .write_reg_u32(0x0208, (1 << 4) | (1 << 5), CTRL_TIMEOUT)?;
        self.handle
            .write_reg_u32(0x0408, 0xefef_3f1f, CTRL_TIMEOUT)?;
        self.handle
            .write_reg_u32(0x040c, 0x0000_febf, CTRL_TIMEOUT)?;

        for &(addr, val) in MAC_INIT_VALS {
            self.handle.write_reg_u32(addr, val, CTRL_TIMEOUT)?;
        }

        self.handle.write_reg_u32(0x1350, 0x1020, CTRL_TIMEOUT)?;
        self.handle.write_reg_u32(0x1404, 0x13, CTRL_TIMEOUT)?;
        self.handle.write_reg_u32(0x1018, 0x2f00, CTRL_TIMEOUT)?;
        self.handle.write_reg_u32(0x0214, 0x2273, CTRL_TIMEOUT)?;
        self.handle.write_reg_u32(0x0218, 0x2344, CTRL_TIMEOUT)?;
        self.handle.write_reg_u32(0x021c, 0x34aa, CTRL_TIMEOUT)?;

        self.handle.rmw_reg_u32(0x1004, 0x3, 0, CTRL_TIMEOUT)?;
        self.handle.rmw_reg_u32(0x0040, 1, 0, CTRL_TIMEOUT)?;
        self.handle.rmw_reg_u32(0x141c, 0, 0xf000, CTRL_TIMEOUT)?;
        self.handle.rmw_reg_u32(0x13c0, 1 << 31, 0, CTRL_TIMEOUT)?;

        fixup_xtal(&self.handle, &self.eeprom)
    }

    fn mcu_load_cr(&mut self) -> io::Result<()> {
        let nic_conf_0 = eeprom_u16(&self.eeprom, EE_NIC_CONF_0);
        let nic_conf_1 = eeprom_u16(&self.eeprom, EE_NIC_CONF_1);
        let cfg = (1u32 << 31)
            | u32::from((nic_conf_0 >> 8) & 0x00ff)
            | ((u32::from(nic_conf_1) << 8) & 0xff00);
        let mut msg = [0u8; 8];
        msg[0] = MT_RF_BBP_CR;
        msg[4..8].copy_from_slice(&cfg.to_le_bytes());
        let seq = self.next_seq();
        self.handle
            .send_mcu_cmd(CMD_LOAD_CR, seq, &msg, true, CTRL_TIMEOUT)
    }

    fn calibrate(&mut self, cal_id: u32, param: u32) -> io::Result<()> {
        let mut msg = [0u8; 8];
        msg[0..4].copy_from_slice(&cal_id.to_le_bytes());
        msg[4..8].copy_from_slice(&param.to_le_bytes());
        let seq = self.next_seq();
        self.handle
            .send_mcu_cmd(CMD_CALIBRATION_OP, seq, &msg, true, CTRL_TIMEOUT)
    }

    fn mac_start(&self) -> io::Result<()> {
        self.handle.write_reg_u32(
            Mt7612uCodec::REG_MAC_SYS_CTRL,
            Mt7612uCodec::MAC_SYS_CTRL_ENABLE_TX,
            CTRL_TIMEOUT,
        )?;
        self.handle
            .poll_reg_u32(0x0208, 0x0a, 0, Duration::from_millis(200))?;
        self.handle.write_reg_u32(
            Mt7612uCodec::REG_RX_FILTR_CFG,
            ACTIVE_MONITOR_RX_FILTER,
            CTRL_TIMEOUT,
        )?;
        self.handle.write_reg_u32(
            Mt7612uCodec::REG_MAC_SYS_CTRL,
            Mt7612uCodec::MAC_SYS_CTRL_ENABLE_TX | Mt7612uCodec::MAC_SYS_CTRL_ENABLE_RX,
            CTRL_TIMEOUT,
        )?;
        self.handle
            .poll_reg_u32(0x0208, 0x0a, 0, Duration::from_millis(50))?;
        Ok(())
    }
}

impl Drop for Mt7612uRadio {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.rx_thread.take() {
            let _ = join.join();
        }
        let _ = self.handle.write_reg_u32(
            Mt7612uCodec::REG_MAC_SYS_CTRL,
            0,
            Duration::from_millis(200),
        );
        let mut off_msg = [0u8; 8];
        off_msg[0..4].copy_from_slice(&RADIO_OFF.to_le_bytes());
        let seq = self.next_seq();
        let _ = self.handle.send_mcu_cmd(
            CMD_POWER_SAVING_OP,
            seq,
            &off_msg,
            false,
            Duration::from_millis(200),
        );
    }
}

fn rx_worker(
    mut in_ep: Endpoint<Bulk, In>,
    stop: Arc<AtomicBool>,
    tx: mpsc::SyncSender<(Option<i8>, Vec<u8>)>,
) {
    let codec = Mt7612uCodec;
    for _ in 0..RX_QUEUE_DEPTH {
        in_ep.submit(Buffer::new(RX_BUF_LEN));
    }

    while !stop.load(Ordering::Relaxed) {
        if let Some(comp) = in_ep.wait_next_complete(Duration::from_millis(50)) {
            if comp.status.is_ok()
                && comp.actual_len > 0
                && let Some(decoded) = codec.decapsulate_rx(&comp.buffer[..comp.actual_len])
            {
                let _ = tx.try_send(decoded);
            }
            if !stop.load(Ordering::Relaxed) {
                in_ep.submit(comp.buffer);
            }
        }
    }

    in_ep.cancel_all();
    while in_ep.pending() > 0 {
        if in_ep
            .wait_next_complete(Duration::from_millis(50))
            .is_none()
        {
            break;
        }
    }
}

fn phase_err(phase: &str, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{phase}: {err}"))
}

fn eeprom_u16(eeprom: &[u8; 512], offset: usize) -> u16 {
    u16::from_le_bytes([eeprom[offset], eeprom[offset + 1]])
}

fn is_valid_mac(mac: [u8; 6]) -> bool {
    let non_zero = mac.iter().any(|&b| b != 0);
    let non_bcast = mac.iter().any(|&b| b != 0xff);
    non_zero && non_bcast && (mac[0] & 0x01) == 0
}

fn pick_mac_address(eeprom: &[u8; 512], mac_override: Option<[u8; 6]>) -> [u8; 6] {
    if let Some(mac) = mac_override {
        return mac;
    }
    let from_ee: [u8; 6] = eeprom[EE_MAC_ADDR..EE_MAC_ADDR + 6]
        .try_into()
        .expect("6-byte slice");
    if is_valid_mac(from_ee) {
        return from_ee;
    }
    [0x02, 0x76, 0x12, eeprom[8], eeprom[9], 0x01]
}

fn has_ext_pa(eeprom: &[u8; 512], is_5g: bool) -> bool {
    let conf0 = eeprom_u16(eeprom, EE_NIC_CONF_0);
    if is_5g {
        (conf0 & (1 << 9)) == 0
    } else {
        (conf0 & (1 << 8)) == 0
    }
}

fn has_ext_lna(eeprom: &[u8; 512], is_5g: bool) -> bool {
    let conf1 = eeprom_u16(eeprom, EE_NIC_CONF_1);
    if is_5g {
        (conf1 & (1 << 3)) != 0
    } else {
        (conf1 & (1 << 2)) != 0
    }
}

fn compute_mcu_gain(eeprom: &[u8; 512]) -> u32 {
    let lna_val = eeprom_u16(eeprom, EE_LNA_GAIN);
    let lna_2g = (lna_val & 0xff) as u8;
    let lna_5g_0 = (lna_val >> 8) as u8;
    let mut lna_5g_1 = (eeprom_u16(eeprom, EE_RSSI_OFFSET_2G_1) >> 8) as u8;
    let mut lna_5g_2 = (eeprom_u16(eeprom, usize::from(EE_RSSI_OFFSET_5G_1)) >> 8) as u8;
    if lna_5g_1 == 0 || lna_5g_1 == 0xff {
        lna_5g_1 = lna_5g_0;
    }
    if lna_5g_2 == 0 || lna_5g_2 == 0xff {
        lna_5g_2 = lna_5g_0;
    }
    u32::from_le_bytes([lna_2g, lna_5g_0, lna_5g_1, lna_5g_2])
}

fn reset_wlan(handle: &UsbRadioHandle) -> io::Result<()> {
    const REG_WLAN_FUN_CTRL: u32 = 0x0080;
    let mut val = handle.read_reg_u32(REG_WLAN_FUN_CTRL, CTRL_TIMEOUT)?;
    val &= !(1 << 5);
    if val & 1 != 0 {
        handle.write_reg_u32(REG_WLAN_FUN_CTRL, val | (1 << 2), CTRL_TIMEOUT)?;
        thread::sleep(Duration::from_millis(1));
        val &= !(1 << 2);
    }
    handle.write_reg_u32(REG_WLAN_FUN_CTRL, val, CTRL_TIMEOUT)?;
    thread::sleep(Duration::from_millis(1));
    handle.rmw_reg_u32(REG_WLAN_FUN_CTRL, 0, 0x3, CTRL_TIMEOUT)?;
    thread::sleep(Duration::from_millis(1));
    Ok(())
}

fn power_on_rf(handle: &UsbRadioHandle, unit: u32) -> io::Result<()> {
    let shift = unit * 8;
    handle.rmw_cfg_u32(0x0130, 0, 1 << shift, CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x0130, 0, 0x3a << shift, CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x0130, 4 << shift, 0, CTRL_TIMEOUT)?;

    // RF patch sequence.
    handle.rmw_cfg_u32(0x0130, 0, 1 | (1 << 16), CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x001c, 0xff, 0x30, CTRL_TIMEOUT)?;
    handle.write_cfg_u32(0x0014, 0x484f, CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x0130, 0, 1 << 17, CTRL_TIMEOUT)?;
    thread::sleep(Duration::from_millis(1));
    handle.rmw_cfg_u32(0x0130, 1 << 16, 0, CTRL_TIMEOUT)?;
    thread::sleep(Duration::from_millis(1));
    handle.rmw_cfg_u32(0x014c, 0, (1 << 19) | (1 << 20), CTRL_TIMEOUT)?;

    handle.rmw_reg_u32(0x0530, 0, 0xf, CTRL_TIMEOUT)?;
    Ok(())
}

fn power_on(handle: &UsbRadioHandle) -> io::Result<()> {
    const MTC_ACK_MASK: u32 = (1 << 28) | (1 << 12) | (1 << 13);
    handle.rmw_cfg_u32(0x0148, 0, 1, CTRL_TIMEOUT)?;
    handle.poll_cfg_u32(
        0x0148,
        MTC_ACK_MASK,
        MTC_ACK_MASK,
        Duration::from_millis(500),
    )?;
    handle.rmw_cfg_u32(0x0148, 0x7f << 16, 0, CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x0148, 0xf << 24, 0, CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x0148, 0, 0xf << 24, CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x0148, 0x0fff, 0, CTRL_TIMEOUT)?;

    handle.rmw_cfg_u32(0x1204, 1 << 3, 0, CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x0080, 0, 1, CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x0064, 1 << 18, 0, CTRL_TIMEOUT)?;

    power_on_rf(handle, 0)?;
    power_on_rf(handle, 1)?;
    Ok(())
}

fn wait_for_mac(handle: &UsbRadioHandle) -> io::Result<()> {
    const REG_MAC_CSR0: u32 = 0x1000;
    for _ in 0..100 {
        let val = handle.read_reg_u32(REG_MAC_CSR0, CTRL_TIMEOUT)?;
        if val != 0 && val != u32::MAX {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "MT7612U MAC_CSR0 did not become ready",
    ))
}

fn setup_fce_for_upload(handle: &UsbRadioHandle) -> io::Result<()> {
    handle.write_cfg_u32(
        Mt7612uCodec::CFG_USB_U3DMA_CFG,
        Mt7612uCodec::USB_DMA_CFG_RX_BULK_EN | Mt7612uCodec::USB_DMA_CFG_TX_BULK_EN | 0x20,
        CTRL_TIMEOUT,
    )?;
    handle.write_reg_u32(0x0800, 0x1, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x09a0, 0x0040_0230, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x09a4, 0x1, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x09c4, 0x44, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x0a6c, 0x3, CTRL_TIMEOUT)?;
    Ok(())
}

fn load_rom_patch(
    handle: &UsbRadioHandle,
    rev_e3: bool,
    rom_protect: bool,
    patch: &Mt7612uRomPatch,
) -> io::Result<()> {
    const REG_MCU_SEMAPHORE_03: u32 = 0x07bc;
    if rom_protect {
        handle.poll_reg_u32(REG_MCU_SEMAPHORE_03, 1, 1, Duration::from_millis(600))?;
    }

    let (patch_reg, patch_mask) = if rev_e3 {
        (Mt7612uCodec::REG_MCU_CLOCK_CTL, 1u32)
    } else {
        (Mt7612uCodec::REG_MCU_COM_REG0, 1u32 << 1)
    };

    let already_applied =
        rom_protect && (handle.read_reg_u32(patch_reg, CTRL_TIMEOUT)? & patch_mask) != 0;
    let res = if already_applied {
        Ok(())
    } else {
        handle.control_out(
            &Mt7612uCodec::vendor_dev_mode(Mt7612uCodec::VEND_DEV_MODE_RESET),
            CTRL_TIMEOUT,
        )?;
        thread::sleep(Duration::from_millis(10));
        setup_fce_for_upload(handle)?;

        for (i, chunk) in Mt7612uCodec::fw_upload_chunks(
            Mt7612uCodec::PATCH_LOAD_ADDR,
            &patch.payload,
            Mt7612uCodec::ROM_PATCH_MAX_CHUNK_LEN,
        )
        .into_iter()
        .enumerate()
        {
            handle
                .upload_mt7612u_chunk(&chunk, BULK_TIMEOUT)
                .map_err(|e| phase_err(&format!("patch_chunk_{i}"), e))?;
        }

        const ENABLE_PATCH_MSG: [u8; 11] = [
            0x6f, 0xfc, 0x08, 0x01, 0x20, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00,
        ];
        const RESET_WMT_MSG: [u8; 8] = [0x6f, 0xfc, 0x05, 0x01, 0x07, 0x01, 0x00, 0x04];
        handle
            .control_class_out(
                Mt7612uCodec::VEND_DEV_MODE,
                Mt7612uCodec::VEND_DEV_MODE_RESET_IVB,
                0,
                &ENABLE_PATCH_MSG,
                CTRL_TIMEOUT,
            )
            .map_err(|e| phase_err("enable_patch", e))?;
        handle
            .control_class_out(
                Mt7612uCodec::VEND_DEV_MODE,
                Mt7612uCodec::VEND_DEV_MODE_RESET_IVB,
                0,
                &RESET_WMT_MSG,
                CTRL_TIMEOUT,
            )
            .map_err(|e| phase_err("reset_wmt", e))?;
        thread::sleep(Duration::from_millis(25));
        handle.poll_reg_u32(
            patch_reg,
            patch_mask,
            patch_mask,
            Duration::from_millis(500),
        )?;
        Ok(())
    };

    if rom_protect {
        let _ = handle.write_reg_u32(REG_MCU_SEMAPHORE_03, 1, CTRL_TIMEOUT);
    }
    res
}

fn load_firmware(handle: &UsbRadioHandle, rev_e3: bool, fw: &Mt7612uFirmware) -> io::Result<()> {
    handle.control_out(
        &Mt7612uCodec::vendor_dev_mode(Mt7612uCodec::VEND_DEV_MODE_RESET),
        CTRL_TIMEOUT,
    )?;
    thread::sleep(Duration::from_millis(10));
    setup_fce_for_upload(handle)?;

    let dlm_addr = if rev_e3 {
        Mt7612uCodec::FW_DLM_LOAD_ADDR
    } else {
        0x0011_0000
    };
    for (base, bytes) in [
        (Mt7612uCodec::FW_ILM_LOAD_ADDR, &fw.ilm),
        (dlm_addr, &fw.dlm),
    ] {
        for chunk in Mt7612uCodec::fw_upload_chunks(base, bytes, Mt7612uCodec::FW_MAX_CHUNK_LEN) {
            handle.upload_mt7612u_chunk(&chunk, BULK_TIMEOUT)?;
        }
    }

    handle.control_out(
        &Mt7612uCodec::vendor_dev_mode(Mt7612uCodec::VEND_DEV_MODE_RESET_IVB),
        CTRL_TIMEOUT,
    )?;
    handle.poll_reg_u32(
        Mt7612uCodec::REG_MCU_COM_REG0,
        1,
        1,
        Duration::from_millis(500),
    )?;
    handle.rmw_reg_u32(Mt7612uCodec::REG_MCU_COM_REG0, 0, 1 << 1, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x0800, 0x1, CTRL_TIMEOUT)?;
    Ok(())
}

fn init_dma(handle: &UsbRadioHandle) -> io::Result<()> {
    handle.rmw_cfg_u32(
        Mt7612uCodec::CFG_USB_U3DMA_CFG,
        Mt7612uCodec::USB_DMA_CFG_RX_BULK_AGG_EN,
        Mt7612uCodec::USB_DMA_CFG_RX_DROP_OR_PAD
            | Mt7612uCodec::USB_DMA_CFG_RX_BULK_EN
            | Mt7612uCodec::USB_DMA_CFG_TX_BULK_EN,
        CTRL_TIMEOUT,
    )?;
    Ok(())
}

fn fixup_xtal(handle: &UsbRadioHandle, eeprom: &[u8; 512]) -> io::Result<()> {
    let eep_xtal2 = eeprom_u16(eeprom, EE_XTAL_TRIM_2);
    let offset: i16 = if (eep_xtal2 & 0xff) == 0xff {
        0
    } else if (eep_xtal2 & 0x80) != 0 {
        -((eep_xtal2 & 0x7f) as i16)
    } else {
        (eep_xtal2 & 0x7f) as i16
    };
    let mut xtal_val = ((eep_xtal2 >> 8) & 0xff) as i16;
    if xtal_val == 0x00 || xtal_val == 0xff {
        let x1 = (eeprom_u16(eeprom, EE_XTAL_TRIM_1) & 0xff) as i16;
        xtal_val = if x1 == 0x00 || x1 == 0xff { 0x14 } else { x1 };
    }
    let c2_val = ((xtal_val + offset).clamp(0, 0x7f) as u32) << 8;

    handle.rmw_cfg_u32(0x0114, 0x7f << 8, c2_val, CTRL_TIMEOUT)?;
    handle.rmw_cfg_u32(0x0118, 0, 0x7f << 8, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x0504, 0x0600_0000, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x050c, 0x0880_0000, CTRL_TIMEOUT)?;
    thread::sleep(Duration::from_millis(5));
    handle.write_reg_u32(0x0504, 0, CTRL_TIMEOUT)?;

    handle.rmw_reg_u32(0x1100, 0xff << 8, 0x0d << 8, CTRL_TIMEOUT)?;
    handle.rmw_reg_u32(0x1104, 0xf << 8, 1 << 8, CTRL_TIMEOUT)?;
    handle.rmw_reg_u32(0x080c, 1 << 4, 0, CTRL_TIMEOUT)?;

    let xtal_opt = (eeprom_u16(eeprom, EE_NIC_CONF_2) >> 9) & 0x3;
    match xtal_opt {
        0 => handle.write_reg_u32(0x011c, 0x5c1f_ee80, CTRL_TIMEOUT)?,
        1 => handle.write_reg_u32(0x011c, 0x5c1f_eed0, CTRL_TIMEOUT)?,
        _ => {}
    }
    Ok(())
}

fn mac_setaddr(handle: &UsbRadioHandle, mac: [u8; 6]) -> io::Result<()> {
    let dw0 = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
    let dw1 = u32::from_le_bytes([mac[4], mac[5], 0xff, 0x00]);
    handle.write_reg_u32(Mt7612uCodec::REG_MAC_ADDR_DW0, dw0, CTRL_TIMEOUT)?;
    handle.write_reg_u32(Mt7612uCodec::REG_MAC_ADDR_DW1, dw1, CTRL_TIMEOUT)?;

    let bssid1 = u32::from(u16::from_le_bytes([mac[4], mac[5]]))
        | (3 << 16) // MBSS_MODE = 3
        | (7 << 18) // MBEACON_N = 7
        | (1 << 21); // MBSS_LOCAL_BIT
    handle.write_reg_u32(0x1010, dw0, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x1014, bssid1, CTRL_TIMEOUT)?;

    for i in 0..8u32 {
        handle.write_reg_u32(0x1090 + i * 8, 0, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x1094 + i * 8, 0, CTRL_TIMEOUT)?;
    }
    Ok(())
}

fn reset_wcid_and_keys(handle: &UsbRadioHandle) -> io::Result<()> {
    for i in 0..256u32 {
        handle.write_reg_u32(0x1800 + i * 8, 0, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x1800 + i * 8 + 4, 0, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0xa800 + i * 4, 0, CTRL_TIMEOUT)?;
    }
    for i in 0..8u32 {
        handle.write_reg_u32(0xb000 + i * 4, 0, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0xb3f0 + i * 4, 0, CTRL_TIMEOUT)?;
    }
    Ok(())
}

fn set_txpower_regs(handle: &UsbRadioHandle, is_5g: bool, ext_pa: bool) -> io::Result<()> {
    let pa_mode: [u32; 2] = if !is_5g {
        handle.write_reg_u32(0x13a8, 0x3516_0a00, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x13ac, 0x3516_0a06, CTRL_TIMEOUT)?;
        if ext_pa {
            handle.write_reg_u32(0x1228, 0x0000_ec00, CTRL_TIMEOUT)?;
            handle.write_reg_u32(0x122c, 0x0000_ec00, CTRL_TIMEOUT)?;
        } else {
            handle.write_reg_u32(0x1228, 0xf400_0200, CTRL_TIMEOUT)?;
            handle.write_reg_u32(0x122c, 0xfa00_0200, CTRL_TIMEOUT)?;
        }
        [0x0100_55ff, 0x0055_0055]
    } else {
        let (alc2, alc3, pa_adj) = if ext_pa {
            (0x2f0f_0400, 0x2f0f_0476, 0x0400_0000)
        } else {
            (0x1b0f_0400, 0x1b0f_0476, 0)
        };
        handle.write_reg_u32(0x13a8, alc2, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x13ac, alc3, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x1228, pa_adj, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x122c, pa_adj, CTRL_TIMEOUT)?;
        [0x0000_ffff, 0x00ff_00ff]
    };

    handle.write_reg_u32(0x1214, pa_mode[0], CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x1218, pa_mode[1], CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x121c, pa_mode[0], CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x1220, pa_mode[1], CTRL_TIMEOUT)?;

    if ext_pa {
        let corr = if is_5g { 0x363c_023c } else { 0x3c3c_023c };
        handle.write_reg_u32(0x13a0, corr, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x13a4, corr, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x13c0, 0x0000_1818, CTRL_TIMEOUT)?;
    } else if !is_5g {
        handle.write_reg_u32(0x13a0, 0x0f3c_3c3c, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x13a4, 0x0f3c_3c3c, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x13c0, 0x0000_0606, CTRL_TIMEOUT)?;
    } else {
        handle.write_reg_u32(0x13a0, 0x383c_023c, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x13a4, 0x2428_2e28, CTRL_TIMEOUT)?;
        handle.write_reg_u32(0x13c0, 0, CTRL_TIMEOUT)?;
    }
    Ok(())
}

fn configure_tx_delay(handle: &UsbRadioHandle, ext_pa: bool) -> io::Result<()> {
    let (cfg0, cfg1) = if ext_pa {
        (0x0010_1101, 0x0001_1414)
    } else {
        (0x0010_1001, 0x0002_1414)
    };
    handle.write_reg_u32(0x1330, cfg0, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x1334, cfg1, CTRL_TIMEOUT)?;
    handle.rmw_reg_u32(0x1100, 0xff << 8, 15 << 8, CTRL_TIMEOUT)?;
    Ok(())
}

fn edcca_init(handle: &UsbRadioHandle) -> io::Result<()> {
    handle.rmw_reg_u32(0x1350, 0, 1 << 12, CTRL_TIMEOUT)?;
    handle.rmw_reg_u32(0x1340, 1 << 20, 0, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x2308, 0x0000_7070, CTRL_TIMEOUT)?;
    handle.rmw_reg_u32(0x1608, 0, 1 << 1, CTRL_TIMEOUT)?;
    handle.rmw_reg_u32(0x1328, 0, 0x0005_0f0f, CTRL_TIMEOUT)?;
    handle.rmw_reg_u32(0x1404, 0, 1, CTRL_TIMEOUT)?;
    let _ = handle.read_reg_u32(0x1140, CTRL_TIMEOUT)?;
    Ok(())
}

fn update_channel_gain(handle: &UsbRadioHandle, is_5g: bool, ext_lna: bool) -> io::Result<()> {
    handle.write_reg_u32(0x2938, 0x0056_0423, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x2948, 0xf000_a991, CTRL_TIMEOUT)?;
    let agc35 = if is_5g { 0x1111_1116 } else { 0x1111_1516 };
    handle.write_reg_u32(0x238c, agc35, CTRL_TIMEOUT)?;
    handle.write_reg_u32(0x2394, 0x2121_262c, CTRL_TIMEOUT)?;

    let low_gain_delta: u32 = if ext_lna { 10 } else { 14 };
    let val_hi = if ext_lna && !is_5g {
        0x0f36u32 << 16
    } else {
        0x1836u32 << 16
    } | 0xf8;

    for agc_reg in [0x2320u32, 0x2324] {
        let cur = handle.read_reg_u32(agc_reg, CTRL_TIMEOUT)?;
        let gain_init = (cur >> 8) & 0x7f;
        let adjusted = gain_init.saturating_sub(low_gain_delta);
        handle.write_reg_u32(agc_reg, val_hi | (adjusted << 8), CTRL_TIMEOUT)?;
    }

    let _ = handle.read_reg_u32(0x1704, CTRL_TIMEOUT)?;
    Ok(())
}
