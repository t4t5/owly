//! Transmit rates for data frames.
//!
//! A node sends at one configured rate, 12 Mbit/s by default, as legacy
//! did, except that an HT rate is only used towards a peer whose HT
//! Capabilities TLV says it receives it, and short guard interval only
//! towards one that announces it; other peers get the 12 Mbit/s that every
//! AWDL device receives. There's no rate control from transmit status: the
//! host would have to report each frame's fate.

use core::fmt;

use crate::tlv::HtCapabilities;

/// A rate for one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxRate {
    /// A non-HT rate, in units of 500 kbit/s as radiotap counts it.
    Legacy(u8),
    /// An HT MCS on 20 MHz.
    Ht { mcs: u8, sgi: bool },
}

impl TxRate {
    /// 12 Mbit/s, the default, for action frames and multicast.
    pub const BASIC: TxRate = TxRate::Legacy(24);

    /// Parses a rate: `12` (Mbit/s, one of 6, 9, 12, 18, 24, 36, 48,
    /// 54), `mcs7` or `mcs7-sgi` (MCS 0–15).
    pub fn parse(s: &str) -> Option<TxRate> {
        if let Some(rest) = s.strip_prefix("mcs") {
            let (n, sgi) = match rest.strip_suffix("-sgi") {
                Some(n) => (n, true),
                None => (rest, false),
            };
            let mcs: u8 = n.parse().ok()?;
            return (mcs <= 15 && !n.starts_with('+')).then_some(TxRate::Ht { mcs, sgi });
        }
        let mbps: u8 = s.parse().ok()?;
        [6, 9, 12, 18, 24, 36, 48, 54]
            .contains(&mbps)
            .then_some(TxRate::Legacy(mbps * 2))
    }

    /// The rate in kbit/s.
    pub fn kbps(self) -> u32 {
        match self {
            TxRate::Legacy(r) => r as u32 * 500,
            TxRate::Ht { mcs, sgi } => {
                // One stream's rates on 20 MHz, times the streams.
                let one = [
                    6_500, 13_000, 19_500, 26_000, 39_000, 52_000, 58_500, 65_000,
                ];
                let rate = one[mcs as usize % 8] * (mcs as u32 / 8 + 1);
                if sgi { rate * 10 / 9 } else { rate }
            }
        }
    }

    /// The rate to use towards a peer with these HT capabilities (or none).
    pub fn for_peer(self, peer: Option<&HtCapabilities>) -> TxRate {
        match (self, peer) {
            (TxRate::Legacy(_), _) => self,
            (TxRate::Ht { mcs, sgi }, Some(ht)) if mcs < 32 && ht.rx_mcs & (1 << mcs) != 0 => {
                TxRate::Ht {
                    mcs,
                    sgi: sgi && ht.sgi20(),
                }
            }
            (TxRate::Ht { .. }, _) => TxRate::BASIC,
        }
    }
}

impl fmt::Display for TxRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TxRate::Legacy(r) if r % 2 == 0 => write!(f, "{} Mbit/s", r / 2),
            TxRate::Legacy(r) => write!(f, "{}.5 Mbit/s", r / 2),
            TxRate::Ht { mcs, sgi } => {
                write!(f, "HT MCS {mcs}")?;
                if sgi {
                    f.write_str(", short GI")
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_in_kbits() {
        assert_eq!(TxRate::BASIC.kbps(), 12_000);
        assert_eq!(TxRate::Ht { mcs: 7, sgi: false }.kbps(), 65_000);
        assert_eq!(
            TxRate::Ht {
                mcs: 15,
                sgi: false
            }
            .kbps(),
            130_000
        );
        assert_eq!(TxRate::Ht { mcs: 15, sgi: true }.kbps(), 144_444);
    }

    #[test]
    fn owls_rate_syntax() {
        assert_eq!(TxRate::parse("12"), Some(TxRate::BASIC));
        assert_eq!(TxRate::parse("54"), Some(TxRate::Legacy(108)));
        assert_eq!(
            TxRate::parse("mcs7"),
            Some(TxRate::Ht { mcs: 7, sgi: false })
        );
        assert_eq!(
            TxRate::parse("mcs15-sgi"),
            Some(TxRate::Ht { mcs: 15, sgi: true })
        );
        for bad in ["", "11", "mcs", "mcs16", "mcs7-lgi", "mcs+7", "-12"] {
            assert_eq!(TxRate::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn ht_only_to_peers_that_receive_it() {
        let ht = TxRate::Ht { mcs: 7, sgi: true };
        assert_eq!(ht.for_peer(None), TxRate::BASIC);
        let one_stream = HtCapabilities::ONE_STREAM; // MCS 0-7, no short GI
        assert_eq!(
            ht.for_peer(Some(&one_stream)),
            TxRate::Ht { mcs: 7, sgi: false }
        );
        let mcs15 = TxRate::Ht {
            mcs: 15,
            sgi: false,
        };
        assert_eq!(mcs15.for_peer(Some(&one_stream)), TxRate::BASIC);
        let sgi = HtCapabilities {
            capabilities: 0x0020,
            ..one_stream
        };
        assert_eq!(ht.for_peer(Some(&sgi)), ht);
        assert_eq!(TxRate::BASIC.for_peer(None), TxRate::BASIC);
    }
}
