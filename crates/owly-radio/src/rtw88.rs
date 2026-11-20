//! rtw88's say over the data frames it's handed, through its debugfs.
//!
//! The driver takes no rate from an injected frame: a data frame for a peer
//! mac80211 has no station entry for goes at the legacy rates its own rate
//! control picks, and for one it has, at that station's. And it sends a
//! frame nobody ACKs as often as the hardware's retry limit says, whatever
//! radiotap's "no ACK" asks. `fix_rate` and the retry limit register are
//! what there is instead. The register is the hardware's, which may be set
//! afresh when the card powers up, so both are set once the session's
//! interfaces are up, and put back before they go.

use std::path::Path;

use owly_awdl::TxRate;

use crate::sys::Ops;

/// `fix_rate` at this is the driver's own choice of rate again.
pub(crate) const FIX_RATE_OFF: &str = "255";

/// The retry limit register: the short limit in bits 8-13, the long in bits
/// 0-5, 16 bits in all.
const REG_RETRY_LIMIT: &str = "0x42a";

/// The driver's code for a rate, as `fix_rate` takes it: 6 to 54 Mbit/s are
/// 4 to 11, and HT MCS 0 is 12. It has none for the short guard interval.
pub(crate) fn rate_code(rate: TxRate) -> Option<u8> {
    match rate {
        TxRate::Legacy(r) => [12, 18, 24, 36, 48, 72, 96, 108]
            .iter()
            .position(|l| *l == r)
            .map(|i| 4 + i as u8),
        TxRate::Ht { mcs, .. } => (mcs < 16).then_some(12 + mcs),
    }
}

/// What the retry limit register holds, as `write_reg` takes it.
pub(crate) fn retry_limit(ops: &dyn Ops, dir: &Path) -> Option<String> {
    ops.write(&dir.join("read_reg"), &format!("{REG_RETRY_LIMIT} 2"))
        .ok()?;
    // "reg 0x42a: 0x2020"
    let said = ops.read(&dir.join("read_reg"))?;
    let value = said.rsplit_once(": ")?.1;
    value.starts_with("0x").then(|| value.to_string())
}

/// Sets the retry limit register to `value`, as [`retry_limit`] gave it.
pub(crate) fn set_retry_limit(ops: &dyn Ops, dir: &Path, value: &str) {
    let _ = ops.write(
        &dir.join("write_reg"),
        &format!("{REG_RETRY_LIMIT} {value} 2"),
    );
}

/// The register's value for sending a frame `tries` times, short or long.
pub(crate) fn tries(tries: u8) -> String {
    let n = u16::from(tries.clamp(1, 63));
    format!("{:#06x}", n << 8 | n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_have_the_drivers_codes() {
        assert_eq!(rate_code(TxRate::parse("6").unwrap()), Some(4));
        assert_eq!(rate_code(TxRate::parse("54").unwrap()), Some(11));
        assert_eq!(rate_code(TxRate::parse("mcs0").unwrap()), Some(12));
        assert_eq!(rate_code(TxRate::parse("mcs15-sgi").unwrap()), Some(27));
        assert_eq!(rate_code(TxRate::Legacy(11)), None);
        assert_eq!(tries(4), "0x0404");
    }
}
