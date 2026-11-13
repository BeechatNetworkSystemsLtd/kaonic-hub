//! A radio's settings, applied through the driver's sysfs attributes
//! (`/sys/class/net/<iface>/rf215/`). The hub owns them and restores them after a reboot.
//!
//! Every write makes the driver reconfigure the transceiver, which takes it off
//! the air for a moment, so only values that differ are written.

use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadioSettings {
    pub frequency_hz: u64,
    pub channel: u16,
    pub channel_spacing_hz: u64,
    /// OFDM modulation and coding scheme, 0..=6.
    pub ofdm_mcs: u8,
    /// OFDM bandwidth option as the driver numbers it.
    pub ofdm_opt: u8,
    /// Transceiver TX power register, 0..=31.
    pub tx_power: u8,
}

impl RadioSettings {
    /// The sub-GHz settings fielded nodes use.
    pub fn sub_ghz_default() -> Self {
        Self { frequency_hz: 869_535_000, channel: 11, channel_spacing_hz: 200_000, ofdm_mcs: 6, ofdm_opt: 0, tx_power: 10 }
    }

    fn attributes(&self) -> [(&'static str, String); 7] {
        [
            ("frequency", self.frequency_hz.to_string()),
            ("channel_spacing", self.channel_spacing_hz.to_string()),
            ("channel", self.channel.to_string()),
            ("modulation", "ofdm".to_owned()),
            ("ofdm/mcs", self.ofdm_mcs.to_string()),
            ("ofdm/opt", self.ofdm_opt.to_string()),
            ("frontend/tx_power", self.tx_power.to_string()),
        ]
    }
}

/// IEEE 802.15.4g MR-OFDM PHY bit rates in kbit/s, by option (the driver's `opt`, 0 = option 1) and MCS.
const OFDM_KBPS: [[u32; 7]; 4] = [
    [100, 200, 400, 800, 1200, 1600, 2400],
    [50, 100, 200, 400, 600, 800, 1200],
    [0, 50, 100, 200, 300, 400, 600],
    [0, 0, 50, 100, 150, 200, 300],
];
/// Nominal occupied bandwidth by option.
const OFDM_BANDWIDTH_HZ: [u64; 4] = [1_094_000, 552_000, 281_000, 156_000];
/// Preamble (STF, LTF) and PHY header: about nine 120 µs OFDM symbols.
const OFDM_OVERHEAD_US: u64 = 1080;

impl RadioSettings {
    /// The PHY bit rate, or None for a combination the standard does not define.
    pub fn bit_rate(&self) -> Option<u32> {
        let kbps = *OFDM_KBPS.get(self.ofdm_opt as usize)?.get(self.ofdm_mcs as usize)?;
        (kbps > 0).then_some(kbps * 1000)
    }

    /// The channel's centre: the transceiver tunes to `frequency + channel × spacing`.
    pub fn centre_hz(&self) -> u64 {
        self.frequency_hz + u64::from(self.channel) * self.channel_spacing_hz
    }

    pub fn bandwidth_hz(&self) -> u64 {
        OFDM_BANDWIDTH_HZ.get(self.ofdm_opt as usize).copied().unwrap_or(0)
    }

    /// Estimated time on air of a frame of `bytes`, in microseconds.
    pub fn airtime_us(&self, bytes: usize) -> u64 {
        let Some(rate) = self.bit_rate() else { return 0 };
        OFDM_OVERHEAD_US + (bytes as u64 * 8 * 1_000_000).div_ceil(u64::from(rate))
    }
}

/// Reads what the driver has now. Fails if it is not set to OFDM.
pub fn read(dir: &Path) -> io::Result<RadioSettings> {
    let get = |name: &str| -> io::Result<String> { Ok(std::fs::read_to_string(dir.join(name))?.trim().to_owned()) };
    fn number<T: std::str::FromStr>(text: String) -> io::Result<T> {
        text.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("not a number: {text}")))
    }
    if get("modulation")? != "ofdm" {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "the radio is not set to OFDM"));
    }
    Ok(RadioSettings {
        frequency_hz: number(get("frequency")?)?,
        channel: number(get("channel")?)?,
        channel_spacing_hz: number(get("channel_spacing")?)?,
        ofdm_mcs: number(get("ofdm/mcs")?)?,
        ofdm_opt: number(get("ofdm/opt")?)?,
        tx_power: number(get("frontend/tx_power")?)?,
    })
}

/// The settings directory of a radio interface.
pub fn sysfs_dir(iface: &str) -> PathBuf {
    PathBuf::from(format!("/sys/class/net/{iface}/rf215"))
}

/// Writes every setting that differs from what the driver has. Returns the names written.
pub fn apply(dir: &Path, settings: &RadioSettings) -> io::Result<Vec<&'static str>> {
    if settings.ofdm_mcs > 6 || settings.tx_power > 31 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "radio setting out of range"));
    }
    let mut written = Vec::new();
    for (name, value) in settings.attributes() {
        let path = dir.join(name);
        let current = std::fs::read_to_string(&path)?;
        if current.trim() != value {
            std::fs::write(&path, &value).map_err(|error| io::Error::new(error.kind(), format!("{name}: {error}")))?;
            written.push(name);
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_only_what_differs() {
        let dir = std::env::temp_dir().join(format!("kaonic-mesh-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ofdm")).unwrap();
        std::fs::create_dir_all(dir.join("frontend")).unwrap();
        let want = RadioSettings::sub_ghz_default();
        for (name, value) in want.attributes() {
            std::fs::write(dir.join(name), format!("{value}\n")).unwrap();
        }
        std::fs::write(dir.join("channel"), "10\n").unwrap();

        assert_eq!(apply(&dir, &want).unwrap(), vec!["channel"]);
        assert_eq!(std::fs::read_to_string(dir.join("channel")).unwrap(), "11");
        assert!(apply(&dir, &want).unwrap().is_empty());
        assert!(apply(&dir, &RadioSettings { tx_power: 40, ..want }).is_err());
        assert_eq!(read(&dir).unwrap(), want);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn airtime_follows_the_bit_rate() {
        let fast = RadioSettings::sub_ghz_default();
        assert_eq!(fast.bit_rate(), Some(2_400_000));
        // 300 bytes at 2.4 Mbit/s is 1 ms, plus the preamble.
        assert_eq!(fast.airtime_us(300), 1000 + 1080);
        let slow = RadioSettings { ofdm_opt: 3, ofdm_mcs: 2, ..fast };
        assert_eq!(slow.bit_rate(), Some(50_000));
        assert_eq!(slow.airtime_us(100), 16_000 + 1080);
        assert_eq!(RadioSettings { ofdm_opt: 3, ofdm_mcs: 0, ..fast }.airtime_us(100), 0);
    }
}
