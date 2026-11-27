use owly_userspace::owly_airdrop::proto::mdns::{BrowseEvent, RECEIVER_FLAGS, SUPPORTS_DVZIP};
use owly_userspace::owly_airdrop::proto::sender::Outcome;
use owly_userspace::owly_awdl::channel::Channel;
use owly_userspace::owly_awdl::{Frame, MacAddr, TxRate};
use owly_userspace::usb_radio::{
    Ar9271Codec, Mt7612uCodec, Mt7612uFirmware, Mt7612uRomPatch, RadioWire, UsbChipset,
    select_endpoints,
};
use owly_userspace::{
    DEFAULT_RECEIVER_PORT, UserspaceNode, UserspaceReceiveEvent, default_awdl_config,
};

#[test]
fn mt7612u_endpoint_selection_skips_inband_cmd_ep08() {
    // Exact descriptor order reported by a physical PAU0D (0e8d:7612).
    let eps = [
        (0x84u8, 512usize),
        (0x85, 512),
        (0x08, 512),
        (0x04, 512),
        (0x05, 512),
        (0x06, 512),
        (0x07, 512),
        (0x09, 512),
    ];
    let sel = select_endpoints(UsbChipset::Mt7612u, &eps).expect("MT7612U endpoints");
    assert_eq!(sel.bulk_out_ep, 0x04);
    assert_eq!(sel.bulk_in_ep, 0x84);
    assert_eq!(sel.cmd_out_ep, Some(0x08));
    assert_eq!(sel.cmd_in_ep, Some(0x85));
    assert_eq!(sel.in_max_packet, 512);

    let ar = select_endpoints(UsbChipset::Ar9271, &[(0x01, 512), (0x82, 512)])
        .expect("AR9271 endpoints");
    assert_eq!(ar.bulk_out_ep, 0x01);
    assert_eq!(ar.bulk_in_ep, 0x82);
    assert_eq!(ar.cmd_out_ep, None);
    assert_eq!(ar.cmd_in_ep, None);
}

#[test]
fn codecs_encapsulate_and_decapsulate_rx_with_rssi() {
    let mpdu = vec![
        0xd0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xaa, 0xbb,
    ];
    let frame = Frame {
        bytes: mpdu.clone(),
        to: MacAddr([0xff; 6]),
        rate: TxRate::BASIC,
        no_ack: true,
    };

    let mt = Mt7612uCodec;
    let mt_tx = mt.encapsulate_tx(&frame);
    assert!(mt_tx.len() >= Mt7612uCodec::TX_DMA_INFO_LEN + Mt7612uCodec::TXWI_LEN + mpdu.len());
    assert_eq!(mt_tx.len() % 4, 0);
    assert_eq!(mt.decapsulate_tx(&mt_tx), Some(mpdu.clone()));
    let mt_rx_wire = Mt7612uCodec::encode_rx_packet(&mpdu, -48);
    assert_eq!(
        mt.decapsulate_rx(&mt_rx_wire),
        Some((Some(-48), mpdu.clone()))
    );
    assert!(mt.decapsulate_rx(&[0u8; 8]).is_none());

    let mt_ctrl = Mt7612uCodec::channel_config_transfers(Channel(149)).unwrap();
    assert_eq!(mt_ctrl.len(), 3);
    assert_eq!(mt_ctrl[0].request, Mt7612uCodec::VEND_WRITE_CFG);
    assert_eq!(mt_ctrl[2].request, Mt7612uCodec::VEND_MULTI_WRITE);

    let ar = Ar9271Codec;
    let ar_tx = ar.encapsulate_tx(&frame);
    assert_eq!(ar_tx[0], Ar9271Codec::EP_MGMT);
    assert_eq!(ar.decapsulate_tx(&ar_tx), Some(mpdu.clone()));
    let ar_rx_wire = Ar9271Codec::encode_rx_packet(&mpdu, -53);
    assert_eq!(ar.decapsulate_rx(&ar_rx_wire), Some((Some(-53), mpdu)));
    assert!(ar.decapsulate_rx(&[0u8; 10]).is_none());

    let fw = Ar9271Codec::fw_download_transfers(&vec![0xa5u8; 9000], 0x5010);
    assert_eq!(fw.len(), 4); // 3 chunks + 1 completion ctrl
    assert_eq!(fw.last().unwrap().request, Ar9271Codec::FW_DOWNLOAD_COMP);
}

#[test]
fn mt7612u_control_plane_firmware_mcu_and_monitor_setup() {
    let rd = Mt7612uCodec::vendor_read_reg(Mt7612uCodec::REG_ASIC_VERSION);
    assert_eq!(rd.request_type, 0xc0);
    assert_eq!(rd.request, Mt7612uCodec::VEND_MULTI_READ);
    assert_eq!(rd.index, 0x0000);

    let high_rd = Mt7612uCodec::vendor_read_reg(0x1234_5678);
    assert_eq!(high_rd.value, 0x1234);
    assert_eq!(high_rd.index, 0x5678);

    let wr = Mt7612uCodec::vendor_write_reg(Mt7612uCodec::REG_RX_FILTR_CFG, 0x0f);
    assert_eq!(wr.request_type, 0x40);
    assert_eq!(wr.request, Mt7612uCodec::VEND_MULTI_WRITE);
    assert_eq!(wr.index, Mt7612uCodec::REG_RX_FILTR_CFG as u16);

    assert_eq!(
        Mt7612uCodec::vendor_read_cfg(0x0200).request,
        Mt7612uCodec::VEND_READ_CFG
    );
    let fce = Mt7612uCodec::vendor_write_fce(Mt7612uCodec::REG_FCE_DMA_ADDR, 0x0009_0000);
    assert_eq!(fce[0].request, Mt7612uCodec::VEND_WRITE_FCE);
    assert_eq!(fce[0].value, 0x0000);
    assert_eq!(fce[0].index, Mt7612uCodec::REG_FCE_DMA_ADDR as u16);
    assert!(fce[0].data.is_empty());
    assert_eq!(fce[1].request, Mt7612uCodec::VEND_WRITE_FCE);
    assert_eq!(fce[1].value, 0x0009);
    assert_eq!(fce[1].index, Mt7612uCodec::REG_FCE_DMA_ADDR as u16 + 2);
    assert!(fce[1].data.is_empty());
    assert_eq!(
        Mt7612uCodec::vendor_dev_mode(Mt7612uCodec::VEND_DEV_MODE_RESET_IVB).value,
        0x12
    );

    let mut patch_bytes = Vec::new();
    patch_bytes.extend_from_slice(b"20140408060640a\n");
    patch_bytes.extend_from_slice(b"ALPS");
    patch_bytes.extend_from_slice(&0x8a10_8a10u32.to_be_bytes());
    patch_bytes.extend_from_slice(&0x0000_0010u32.to_be_bytes());
    patch_bytes.extend_from_slice(&0x19efu16.to_be_bytes());
    patch_bytes.extend_from_slice(&[0xaau8; 100]);
    let patch = Mt7612uRomPatch::parse(&patch_bytes).expect("valid patch");
    assert_eq!(patch.platform, "ALPS");
    assert_eq!(patch.build_time, "20140408060640a");
    assert_eq!(patch.payload.len(), 100);
    assert!(Mt7612uRomPatch::parse(&patch_bytes[..30]).is_err());

    let mut fw_bytes = Vec::new();
    fw_bytes.extend_from_slice(&16u32.to_le_bytes());
    fw_bytes.extend_from_slice(&12u32.to_le_bytes());
    fw_bytes.extend_from_slice(&1u16.to_le_bytes());
    fw_bytes.extend_from_slice(&2u16.to_le_bytes());
    fw_bytes.extend_from_slice(&[0u8; 4]);
    fw_bytes.extend_from_slice(b"201406241830____");
    fw_bytes.extend_from_slice(&[0x11u8; 16]);
    fw_bytes.extend_from_slice(&[0x22u8; 12]);
    let fw = Mt7612uFirmware::parse(&fw_bytes).expect("valid fw");
    assert_eq!(fw.ilm_len, 16);
    assert_eq!(fw.dlm_len, 12);
    assert_eq!(fw.build_time, "201406241830____");
    assert!(Mt7612uFirmware::parse(&fw_bytes[..fw_bytes.len() - 1]).is_err());

    let mcu = Mt7612uCodec::encode_mcu_cmd(0x1f, 0x05, &[1, 2, 3]);
    assert_eq!(mcu.len(), 12); // 4 tx_info + 4 padded + 4 trailer
    assert_eq!(
        u32::from_le_bytes(mcu[0..4].try_into().unwrap()),
        Mt7612uCodec::MCU_MSG_TYPE_CMD
            | Mt7612uCodec::MCU_MSG_PORT_CPU_TX
            | (0x1f << 20)
            | (0x05 << 16)
            | 4
    );

    let chunks = Mt7612uCodec::fw_upload_chunks(Mt7612uCodec::PATCH_LOAD_ADDR, &[0x33u8; 300], 128);
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[1].dma_addr, Mt7612uCodec::PATCH_LOAD_ADDR + 128);
    assert_eq!(chunks[2].dma_len, 44);
    assert_eq!(chunks[0].addr_ctrl[0].request, Mt7612uCodec::VEND_WRITE_FCE);

    let unaligned =
        Mt7612uCodec::fw_upload_chunks(Mt7612uCodec::PATCH_LOAD_ADDR, &[0x33u8; 5], 128);
    assert_eq!(
        u32::from_le_bytes(unaligned[0].bulk_frame[..4].try_into().unwrap()),
        Mt7612uCodec::MCU_MSG_TYPE_CMD | Mt7612uCodec::MCU_MSG_PORT_CPU_TX | 5
    );
    assert_eq!(unaligned[0].bulk_frame.len(), 4 + 8 + 4);
    assert_eq!(unaligned[0].len_ctrl[0].value, 0);
    assert_eq!(unaligned[0].len_ctrl[1].value, 8);

    let mac = [0x9c, 0xef, 0xd5, 0xf7, 0x3a, 0xe2];
    for ch in [Channel(6), Channel(44), Channel(149)] {
        let init = Mt7612uCodec::active_monitor_init_transfers(mac, ch).unwrap();
        assert_eq!(init[0].index, Mt7612uCodec::REG_MAC_ADDR_DW0 as u16);
        assert_eq!(init[0].data, [0x9c, 0xef, 0xd5, 0xf7]);
        assert_eq!(init[1].index, Mt7612uCodec::REG_MAC_ADDR_DW1 as u16);
        assert_eq!(init[1].data, [0x3a, 0xe2, 0xff, 0x00]);
    }
    assert!(Mt7612uCodec::active_monitor_init_transfers(mac, Channel(200)).is_err());
}

#[test]
fn full_7_layer_airdrop_runs_over_mt7612u_and_ar9271_usb_framing() {
    run_over_usb_wire(&Mt7612uCodec, Channel(149), |bytes, rssi| {
        Mt7612uCodec::encode_rx_packet(bytes, rssi)
    });
    run_over_usb_wire(&Ar9271Codec, Channel(6), |bytes, rssi| {
        Ar9271Codec::encode_rx_packet(bytes, rssi)
    });
}

fn run_over_usb_wire<W: RadioWire>(codec: &W, channel: Channel, wrap_rx: fn(&[u8], i8) -> Vec<u8>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut rx_node = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0xaa, 0x00, 0x00, 0x00, 0x01]),
            "usb-rx",
            channel,
        ),
        0,
    );
    let mut tx_node = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0xaa, 0x00, 0x00, 0x00, 0x02]),
            "usb-tx",
            channel,
        ),
        0,
    );
    rx_node
        .enable_receiver(
            "USB Radio Rx",
            "02aa00000001",
            "usb-rx",
            DEFAULT_RECEIVER_PORT,
            RECEIVER_FLAGS | SUPPORTS_DVZIP,
            0,
        )
        .unwrap();
    tx_node.enable_browser(0);

    let payload = vec![(
        format!("{}.bin", codec.name()),
        b"Full 7-layer AWDL + AirDrop transferred inside simulated USB bulk URBs".to_vec(),
    )];

    let mut q_to_rx: Vec<Vec<u8>> = Vec::new();
    let mut q_to_tx: Vec<Vec<u8>> = Vec::new();
    let mut now_us = 0u64;
    let mut sent = false;
    let mut received = Vec::new();
    let mut outcome: Option<Outcome> = None;

    for _ in 0..4000 {
        let rx_in: Vec<_> = q_to_rx
            .drain(..)
            .filter_map(|urb| codec.decapsulate_rx(&urb))
            .collect();
        for frame in rx_node.step(now_us, &rx_in) {
            let tx_urb = codec.encapsulate_tx(&frame);
            assert!(tx_urb.len() > frame.bytes.len());
            let mpdu = codec
                .decapsulate_tx(&tx_urb)
                .expect("codec rejected its own TX URB");
            q_to_tx.push(wrap_rx(&mpdu, -42));
        }

        let tx_in: Vec<_> = q_to_tx
            .drain(..)
            .filter_map(|urb| codec.decapsulate_rx(&urb))
            .collect();
        for frame in tx_node.step(now_us, &tx_in) {
            let tx_urb = codec.encapsulate_tx(&frame);
            assert!(tx_urb.len() > frame.bytes.len());
            let mpdu = codec
                .decapsulate_tx(&tx_urb)
                .expect("codec rejected its own TX URB");
            q_to_rx.push(wrap_rx(&mpdu, -42));
        }

        while let Some(ev) = rx_node.poll_receiver_event() {
            match ev {
                UserspaceReceiveEvent::Ask { id, .. } => {
                    assert!(rx_node.accept_ask(id));
                }
                UserspaceReceiveEvent::ReceivedFiles { files, .. } => {
                    received = files;
                }
                UserspaceReceiveEvent::Failed { reason, .. } => {
                    panic!("receiver failed on {}: {reason}", codec.name());
                }
                _ => {}
            }
        }

        if !sent && let Some(BrowseEvent::Found(svc)) = tx_node.poll_browse_event() {
            tx_node
                .start_send_files(svc.addr, svc.port, svc.flags, "USB Sender", &payload)
                .unwrap();
            sent = true;
        }
        if sent && outcome.is_none() {
            outcome = tx_node.take_transfer_outcome();
        }
        if outcome.is_some() && !received.is_empty() {
            break;
        }
        now_us += 2_000;
    }

    assert_eq!(outcome, Some(Outcome::Delivered), "{}", codec.name());
    assert_eq!(received, payload, "{}", codec.name());
}
