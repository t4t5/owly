//! Golden C-OWL frame vectors and deterministic adversarial parser fuzzing.

use owly_awdl::channel::{Channel, SLOTS};
use owly_awdl::frame::{self, Received, subtype};
use owly_awdl::tlv::{
    Advert, DataPathState, ElectionParams, HtCapabilities, SyncParams, kind, parse_arpa,
    parse_version, tlvs,
};
use owly_awdl::{Action, Config, Input, MacAddr, Node, Presence, RadioConstraints, Time};

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
        assert_eq!(header.bssid, owly_awdl::BSSID, "{name} BSSID");

        let advert = Advert::parse(tlv_bytes).unwrap_or_else(|e| panic!("{name} Advert: {e:?}"));
        let sync = advert.sync.expect("missing SyncParams");
        assert_eq!(sync.master, OWL_MAC);
        assert_eq!(sync.master_channel, 6);
        let ep = advert.election.expect("missing ElectionParams");
        assert_eq!(ep.master, OWL_MAC);
        assert_eq!(ep.master_metric, 60);
        let seq = advert.sequence.expect("missing Sequence");
        assert_eq!(seq.channels(), [6; SLOTS]);
        assert_eq!(advert.version, Some((0x34, 1)));
        assert_eq!(
            advert.data_path.and_then(|dp| dp.country),
            Some([b'X', b'0', 0])
        );

        for res in tlvs(tlv_bytes) {
            let tlv = res.unwrap_or_else(|e| panic!("{name} tlv: {e:?}"));
            match tlv.kind {
                kind::SYNC_PARAMS => {
                    assert_eq!(SyncParams::parse(tlv.value).expect("SyncParams"), sync);
                }
                kind::ELECTION_PARAMS => {
                    let e1 = ElectionParams::parse_v1(tlv.value).expect("ElectionV1");
                    assert_eq!(e1.master, OWL_MAC);
                    assert_eq!(e1.master_metric, 60);
                }
                kind::ELECTION_PARAMS_V2 => {
                    let e2 = ElectionParams::parse_v2(tlv.value).expect("ElectionV2");
                    assert_eq!(e2.master, OWL_MAC);
                    assert_eq!(e2.master_metric, 60);
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
                    assert_eq!(parse_version(tlv.value).expect("Version"), (0x34, 1));
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

    let radio = RadioConstraints {
        channel: Channel(6),
        presence: Presence::Fixed,
    };
    let mut node = Node::new(
        Config::new(MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]), "rx", radio),
        Time(0),
    );
    let _ = node
        .handle(Input::Frame {
            rx_time: Time(10_000),
            rssi: Some(-40),
            bytes: PSF_OWL,
        })
        .count();
    let actions: Vec<Action> = node
        .handle(Input::Frame {
            rx_time: Time(20_000),
            rssi: Some(-40),
            bytes: MIF_OWL,
        })
        .collect();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::PeerUp(p) if p.mac == OWL_MAC)),
        "expected PeerUp for {OWL_MAC}, actions={actions:?}"
    );
    assert!(node.peer(OWL_MAC).is_some_and(|p| p.valid));
}

#[test]
fn adversarial_parser_fuzz_10k_never_panics() {
    let radio = RadioConstraints {
        channel: Channel(149),
        presence: Presence::Fixed,
    };
    let mut node = Node::new(
        Config::new(MacAddr([0x02, 0x99, 0x88, 0x77, 0x66, 0x55]), "fuzz", radio),
        Time(0),
    );

    let mut state: u64 = 0x1234_5678_9abc_def0;
    let mut next_u64 = || -> u64 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };

    let mut case_idx = 0u64;
    for len in [0usize, 1, 2, 16, 24, 36, 40, 64, 128, 256, 512] {
        for fill in [0x00u8, 0xffu8] {
            let buf = vec![fill; len];
            exercise_parsers(&buf, &mut node, Time(10_000 + case_idx * 100));
            case_idx += 1;
        }
    }

    for _ in 0..7_000 {
        let len = (next_u64() as usize) % 512;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = next_u64() as u8;
        }
        exercise_parsers(&buf, &mut node, Time(100_000 + case_idx * 100));
        case_idx += 1;
    }

    let corpus = [PSF_OWL, MIF_OWL, PSF_GOLDEN];
    for i in 0..3_000 {
        let base = corpus[i % corpus.len()];
        let trunc = ((next_u64() as usize) % (base.len() + 1)).max(1);
        let mut mutated = base[..trunc].to_vec();
        if !mutated.is_empty() {
            let idx = (next_u64() as usize) % mutated.len();
            mutated[idx] ^= (next_u64() as u8) | 1;
        }
        exercise_parsers(&mutated, &mut node, Time(1_000_000 + case_idx * 100));
        case_idx += 1;
    }
    assert!(case_idx >= 10_000);
}

fn exercise_parsers(bytes: &[u8], node: &mut Node, now: Time) {
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
    let _ = node
        .handle(Input::Frame {
            rx_time: now,
            rssi: Some(-60),
            bytes,
        })
        .count();
}
