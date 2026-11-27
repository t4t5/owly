use owly_userspace::air::SimAirHub;
use owly_userspace::owly_airdrop::proto::mdns::Message as MdnsMessage;
use owly_userspace::owly_awdl::channel::Channel;
use owly_userspace::owly_awdl::frame::{self, Received, subtype};
use owly_userspace::owly_awdl::tlv::{
    Advert, DataPathState, ElectionParams, HtCapabilities, SyncParams, kind, parse_arpa,
    parse_version, tlvs,
};
use owly_userspace::owly_awdl::{BSSID, Ipv6Packet, MacAddr};
use owly_userspace::{UserspaceNode, default_awdl_config, parse_radiotap};

const OWL_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x01, 0x00]);
const PSF_OWL: &[u8] = include_bytes!("vectors/psf_owl.bin");
const MIF_OWL: &[u8] = include_bytes!("vectors/mif_owl.bin");
const PSF_GOLDEN: &[u8] = include_bytes!("vectors/psf_golden.bin");

#[test]
fn golden_owl_vectors_decode_to_expected_tlvs_and_feed_node() {
    for (name, bytes, expected_subtype) in [
        ("psf_owl", PSF_OWL, subtype::PSF),
        ("mif_owl", MIF_OWL, subtype::MIF),
    ] {
        let Received::Action {
            header,
            subtype,
            tlvs: tlv_bytes,
            ..
        } = frame::parse(bytes).unwrap_or_else(|e| panic!("parse {name}: {e:?}"))
        else {
            panic!("{name} did not parse as Action");
        };
        assert_eq!(subtype, expected_subtype, "{name} subtype");
        assert_eq!(header.src, OWL_MAC, "{name} src MAC");
        assert_eq!(header.bssid, BSSID, "{name} BSSID");

        let parsed_tlvs: Vec<_> = tlvs(tlv_bytes)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("{name} tlvs: {e:?}"));
        let advert = Advert::parse(tlv_bytes).unwrap_or_else(|e| panic!("{name} Advert: {e:?}"));
        assert!(advert.sync.is_some());
        assert!(parsed_tlvs.iter().any(|t| t.kind == kind::SYNC_PARAMS));
        assert!(parsed_tlvs.iter().any(|t| t.kind == kind::ELECTION_PARAMS));
        assert!(parsed_tlvs.iter().any(|t| t.kind == kind::DATA_PATH_STATE));
        assert!(parsed_tlvs.iter().any(|t| t.kind == kind::VERSION));

        for tlv in &parsed_tlvs {
            match tlv.kind {
                kind::SYNC_PARAMS => {
                    let sync = SyncParams::parse(tlv.value).expect("SyncParams");
                    assert_eq!(sync.master, OWL_MAC);
                    assert_eq!(sync.master_channel, 6);
                }
                kind::ELECTION_PARAMS => {
                    let ep = ElectionParams::parse_v1(tlv.value).expect("ElectionV1");
                    assert_eq!(ep.master, OWL_MAC);
                    assert_eq!(ep.master_metric, 60);
                }
                kind::ELECTION_PARAMS_V2 => {
                    let ep2 = ElectionParams::parse_v2(tlv.value).expect("ElectionV2");
                    assert_eq!(ep2.master, OWL_MAC);
                    assert_eq!(ep2.master_metric, 60);
                }
                kind::CHANNEL_SEQUENCE => {
                    assert!(!tlv.value.is_empty());
                }
                kind::HT_CAPABILITIES => {
                    HtCapabilities::parse(tlv.value).expect("HtCapabilities");
                }
                kind::DATA_PATH_STATE => {
                    let dp = DataPathState::parse(tlv.value).expect("DataPathState");
                    assert_eq!(dp.country, Some([b'X', b'0', 0]));
                }
                kind::ARPA => {
                    let host = parse_arpa(tlv.value).expect("Arpa");
                    assert!(!host.is_empty());
                }
                kind::VERSION => {
                    let (ver, devclass) = parse_version(tlv.value).expect("Version");
                    assert_eq!((ver, devclass), (0x34, 1));
                }
                _ => {}
            }
        }
    }

    let Received::Action {
        subtype,
        tlvs: tbytes,
        ..
    } = frame::parse(PSF_GOLDEN).expect("parse psf_golden")
    else {
        panic!("psf_golden not Action");
    };
    assert_eq!(subtype, subtype::PSF);
    let golden_tlvs: Vec<_> = tlvs(tbytes)
        .collect::<Result<Vec<_>, _>>()
        .expect("psf_golden tlvs");
    assert_eq!(
        golden_tlvs.iter().map(|t| t.kind).collect::<Vec<_>>(),
        vec![
            kind::SYNC_PARAMS,
            kind::ELECTION_PARAMS,
            kind::CHANNEL_SEQUENCE,
            kind::VERSION,
            kind::SERVICE_PARAMS,
        ]
    );
    SyncParams::parse(golden_tlvs[0].value).expect("psf_golden SyncParams");
    ElectionParams::parse_v1(golden_tlvs[1].value).expect("psf_golden ElectionV1");
    assert_eq!(
        parse_version(golden_tlvs[3].value).expect("psf_golden Version"),
        (0x10, 8)
    );

    // Feed live OWL action frames into a UserspaceNode and assert peer registration.
    let mut node = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            "rx",
            Channel(6),
        ),
        0,
    );
    let _ = node.step(
        10_000,
        &[(Some(-40), PSF_OWL.to_vec()), (Some(-40), MIF_OWL.to_vec())],
    );
    assert_eq!(node.valid_peers(), vec![OWL_MAC]);
}

#[test]
fn adversarial_parser_and_userspace_fuzz_never_panics() {
    let mut node = UserspaceNode::new(
        default_awdl_config(
            MacAddr([0x02, 0x99, 0x88, 0x77, 0x66, 0x55]),
            "fuzz",
            Channel(149),
        ),
        0,
    );
    let _hub = SimAirHub::new();

    let mut state: u64 = 0x1234_5678_9abc_def0;
    let mut next_u64 = || -> u64 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };

    for len in [0usize, 1, 2, 16, 64, 256, 512] {
        for fill in [0x00u8, 0xffu8] {
            let buf = vec![fill; len];
            exercise_parsers(&buf, &mut node, 20_000);
        }
    }

    for i in 0..2000u64 {
        let len = (next_u64() as usize) % 384;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = next_u64() as u8;
        }
        exercise_parsers(&buf, &mut node, 100_000 + i * 100);
    }

    for i in 0..600u64 {
        let base = if i % 2 == 0 { PSF_OWL } else { MIF_OWL };
        let trunc = ((next_u64() as usize) % (base.len() + 1)).max(1);
        let mut mutated = base[..trunc].to_vec();
        if !mutated.is_empty() {
            let idx = (next_u64() as usize) % mutated.len();
            mutated[idx] ^= (next_u64() as u8) | 1;
        }
        exercise_parsers(&mutated, &mut node, 500_000 + i * 100);
    }
}

fn exercise_parsers(bytes: &[u8], node: &mut UserspaceNode, now_us: u64) {
    let _ = frame::parse_header(bytes);
    let _ = Advert::parse(bytes);
    if let Ok(Received::Action { tlvs: inner, .. }) = frame::parse(bytes) {
        let _ = Advert::parse(inner);
        for t in tlvs(inner).flatten() {
            let _ = SyncParams::parse(t.value);
            let _ = ElectionParams::parse_v1(t.value);
            let _ = ElectionParams::parse_v2(t.value);
            let _ = HtCapabilities::parse(t.value);
            let _ = DataPathState::parse(t.value);
            let _ = parse_arpa(t.value);
            let _ = parse_version(t.value);
        }
    }
    let _ = Ipv6Packet::from_ip(bytes.to_vec());
    let _ = MdnsMessage::decode(bytes);
    let _ = parse_radiotap(bytes);
    let _ = node.step(now_us, &[(Some(-60), bytes.to_vec())]);
}
