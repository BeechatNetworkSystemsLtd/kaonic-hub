//! Everything the `kaonic_rf215` driver lets us configure on one band, read from and
//! written to its sysfs attributes (`/sys/class/net/<iface>/rf215/`), validated against
//! the ranges the driver accepts, and saved as a small text record.
//!
//! The driver has no "off": a band is switched off by taking its interface down, which
//! the caller does. Acceleration, the 2.4 GHz antenna and the band filter belong to commd
//! (the radio front-end), not to the driver, and are not here.
//!
//! [`Switch`] is the pure state machine of a network-wide change of the mesh band: every
//! node switches at the same moment and goes back if it hears no peer afterwards.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::settings::RadioSettings;

/// Frequency ranges: the sub-GHz transceiver covers 389.5–510 and 779–1020 MHz.
pub const SUB_GHZ_RANGES: [(u64, u64); 2] = [(389_500_000, 510_000_000), (779_000_000, 1_020_000_000)];
pub const G24_RANGES: [(u64, u64); 1] = [(2_400_000_000, 2_483_500_000)];

/// Driver limits (its sysfs attributes and API).
const EDD_US_MAX: u32 = 8064;
const BACKOFF_US_MAX: u32 = 2000;
const SPACING_MAX: u32 = 6_375_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modulation {
    Off,
    /// `opt` as the driver numbers it: 0 is option 1.
    Ofdm { mcs: u8, opt: u8 },
    /// Chip rate index 0–3 (100, 200, 1000, 2000 kchip/s) and rate mode 0–4.
    Qpsk { fchip: u8, mode: u8 },
    /// Symbol rate index 0–5, modulation index 0–7, order 0 (2-FSK) / 1 (4-FSK), BT 0–3,
    /// FEC, data whitening, preamble length 1–1023.
    Fsk { srate: u8, midx: u8, mord: u8, bt: u8, fec: bool, dw: bool, preamble: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cca {
    pub enabled: bool,
    /// Energy above which the channel counts as busy, dBm (−127..4).
    pub threshold_dbm: i8,
    /// Energy detection time; 0 lets the driver pick the modulation's own.
    pub listen_us: u32,
    pub retries: u8,
    pub backoff_us: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frontend {
    pub agc_map: u8,
    pub agc_target: u8,
    pub lna_bypass: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BandConfig {
    pub frequency_hz: u64,
    pub channel: u16,
    pub channel_spacing_hz: u32,
    pub modulation: Modulation,
    /// Transceiver TX power register, 0–31.
    pub tx_power: u8,
    /// The chip appends a frame check sequence (changes the interface MTU).
    pub fcs: bool,
    pub cca: Cca,
    pub frontend: Frontend,
}

fn bool_text(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

impl BandConfig {
    /// The channel's centre: the transceiver tunes to `frequency + channel × spacing`.
    pub fn centre_hz(&self) -> u64 {
        self.frequency_hz + u64::from(self.channel) * u64::from(self.channel_spacing_hz)
    }

    /// Problems by field, empty when the driver will accept it on a band covering `ranges`.
    pub fn validate(&self, ranges: &[(u64, u64)]) -> Vec<(&'static str, String)> {
        let mut problems = Vec::new();
        let mhz = |hz: u64| format!("{:.3} MHz", hz as f64 / 1e6);
        let centre = self.centre_hz();
        if !ranges.iter().any(|(low, high)| (*low..=*high).contains(&centre)) {
            let allowed: Vec<String> = ranges.iter().map(|(low, high)| format!("{}–{}", mhz(*low), mhz(*high))).collect();
            problems.push(("frequency_hz", format!("The channel centre {} is outside this band ({}).", mhz(centre), allowed.join(" or "))));
        }
        if self.channel_spacing_hz == 0 || self.channel_spacing_hz > SPACING_MAX {
            problems.push(("channel_spacing_hz", format!("Use 1 Hz to {} kHz.", SPACING_MAX / 1000)));
        }
        if self.tx_power > 31 {
            problems.push(("tx_power", "Use 0 to 31.".into()));
        }
        match self.modulation {
            Modulation::Off => {}
            Modulation::Ofdm { mcs, opt } => {
                if mcs > 6 {
                    problems.push(("modulation.mcs", "Use MCS 0 to 6.".into()));
                }
                if opt > 3 {
                    problems.push(("modulation.option", "Use option 1 to 4.".into()));
                }
            }
            Modulation::Qpsk { fchip, mode } => {
                if fchip > 3 {
                    problems.push(("modulation.chip_rate_khz", "Use 100, 200, 1000 or 2000.".into()));
                }
                if mode > 4 {
                    problems.push(("modulation.rate_mode", "Use 0 to 4.".into()));
                }
            }
            Modulation::Fsk { srate, midx, mord, bt, preamble, .. } => {
                if srate > 5 {
                    problems.push(("modulation.symbol_rate", "Use index 0 to 5.".into()));
                }
                if midx > 7 {
                    problems.push(("modulation.modulation_index", "Use index 0 to 7.".into()));
                }
                if mord > 1 {
                    problems.push(("modulation.order", "Use 2-FSK or 4-FSK.".into()));
                }
                if bt > 3 {
                    problems.push(("modulation.bt", "Use index 0 to 3.".into()));
                }
                if !(1..=1023).contains(&preamble) {
                    problems.push(("modulation.preamble", "Use 1 to 1023.".into()));
                }
            }
        }
        if !(-127..=4).contains(&self.cca.threshold_dbm) {
            problems.push(("cca.threshold_dbm", "Use −127 to 4 dBm.".into()));
        }
        if self.cca.listen_us > EDD_US_MAX {
            problems.push(("cca.listen_us", format!("Use 0 to {EDD_US_MAX} µs.")));
        }
        if self.cca.backoff_us > BACKOFF_US_MAX {
            problems.push(("cca.backoff_us", format!("Use 0 to {BACKOFF_US_MAX} µs.")));
        }
        if self.frontend.agc_map > 2 {
            problems.push(("frontend.agc_map", "Use 0 to 2.".into()));
        }
        if self.frontend.agc_target > 7 {
            problems.push(("frontend.agc_target", "Use 0 to 7.".into()));
        }
        problems
    }

    /// The attributes in write order: the modulation and its parameters first, so the
    /// frequency is written for the PHY it will run.
    fn attributes(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        match self.modulation {
            Modulation::Off => {}
            Modulation::Ofdm { mcs, opt } => {
                out.push(("modulation", "ofdm".to_owned()));
                out.push(("ofdm/opt", opt.to_string()));
                out.push(("ofdm/mcs", mcs.to_string()));
            }
            Modulation::Qpsk { fchip, mode } => {
                out.push(("modulation", "qpsk".to_owned()));
                out.push(("qpsk/fchip", fchip.to_string()));
                out.push(("qpsk/mode", mode.to_string()));
            }
            Modulation::Fsk { srate, midx, mord, bt, fec, dw, preamble } => {
                out.push(("modulation", "fsk".to_owned()));
                out.push(("fsk/srate", srate.to_string()));
                out.push(("fsk/midx", midx.to_string()));
                out.push(("fsk/mord", mord.to_string()));
                out.push(("fsk/bt", bt.to_string()));
                out.push(("fsk/fec", bool_text(fec).to_owned()));
                out.push(("fsk/dw", bool_text(dw).to_owned()));
                out.push(("fsk/preamble", preamble.to_string()));
            }
        }
        out.push(("frequency", self.frequency_hz.to_string()));
        out.push(("channel_spacing", self.channel_spacing_hz.to_string()));
        out.push(("channel", self.channel.to_string()));
        out.push(("frontend/tx_power", self.tx_power.to_string()));
        out.push(("fcs", bool_text(self.fcs).to_owned()));
        out.push(("cca/enable", bool_text(self.cca.enabled).to_owned()));
        out.push(("cca/threshold", self.cca.threshold_dbm.to_string()));
        out.push(("cca/listen_us", self.cca.listen_us.to_string()));
        out.push(("cca/retries", self.cca.retries.to_string()));
        out.push(("cca/backoff", self.cca.backoff_us.to_string()));
        out.push(("frontend/agc_map", self.frontend.agc_map.to_string()));
        out.push(("frontend/agc_target", self.frontend.agc_target.to_string()));
        out.push(("frontend/lna_bypass", bool_text(self.frontend.lna_bypass).to_owned()));
        out
    }

    /// The mesh's view (bit rate, airtime, centre), for OFDM bands.
    pub fn to_settings(&self) -> Option<RadioSettings> {
        let Modulation::Ofdm { mcs, opt } = self.modulation else { return None };
        Some(RadioSettings {
            frequency_hz: self.frequency_hz,
            channel: self.channel,
            channel_spacing_hz: u64::from(self.channel_spacing_hz),
            ofdm_mcs: mcs,
            ofdm_opt: opt,
            tx_power: self.tx_power,
        })
    }

    /// The defaults of a band the driver has not been asked about (the emulator).
    pub fn default_for(sub_ghz: bool) -> Self {
        Self {
            frequency_hz: if sub_ghz { 869_535_000 } else { 2_450_000_000 },
            channel: if sub_ghz { 11 } else { 5 },
            channel_spacing_hz: 200_000,
            modulation: Modulation::Ofdm { mcs: 6, opt: 0 },
            tx_power: if sub_ghz { 10 } else { 6 },
            fcs: false,
            cca: Cca { enabled: true, threshold_dbm: -80, listen_us: 0, retries: 96, backoff_us: 500 },
            frontend: Frontend { agc_map: 2, agc_target: 3, lna_bypass: !sub_ghz },
        }
    }

    /// A one-line record for the settings store: `key=value` pairs separated by `;`.
    pub fn encode(&self) -> String {
        let mut fields: Vec<(&str, String)> = self.attributes().into_iter().collect();
        if self.modulation == Modulation::Off {
            fields.insert(0, ("modulation", "off".to_owned()));
        }
        fields.iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join(";")
    }

    pub fn decode(text: &str) -> Option<Self> {
        let get = |key: &str| text.split(';').find_map(|pair| pair.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v.trim()));
        from_lookup(&|key: &str| get(key).map(str::to_owned), get("modulation") == Some("off"))
    }
}

fn number<T: std::str::FromStr>(value: Option<String>, name: &str) -> io::Result<T> {
    let text = value.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} missing")))?;
    text.trim().parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{name}: not a number: {text}")))
}

fn from_lookup(get: &dyn Fn(&str) -> Option<String>, off: bool) -> Option<BandConfig> {
    from_lookup_io(get, off).ok()
}

fn from_lookup_io(get: &dyn Fn(&str) -> Option<String>, off: bool) -> io::Result<BandConfig> {
    let flag = |name: &str| -> io::Result<bool> { Ok(number::<u8>(get(name), name)? != 0) };
    let modulation = if off {
        Modulation::Off
    } else {
        match get("modulation").as_deref().map(str::trim) {
            Some("ofdm") => Modulation::Ofdm { mcs: number(get("ofdm/mcs"), "ofdm/mcs")?, opt: number(get("ofdm/opt"), "ofdm/opt")? },
            Some("qpsk") => Modulation::Qpsk { fchip: number(get("qpsk/fchip"), "qpsk/fchip")?, mode: number(get("qpsk/mode"), "qpsk/mode")? },
            Some("fsk") => Modulation::Fsk {
                srate: number(get("fsk/srate"), "fsk/srate")?,
                midx: number(get("fsk/midx"), "fsk/midx")?,
                mord: number(get("fsk/mord"), "fsk/mord")?,
                bt: number(get("fsk/bt"), "fsk/bt")?,
                fec: flag("fsk/fec")?,
                dw: flag("fsk/dw")?,
                preamble: number(get("fsk/preamble"), "fsk/preamble")?,
            },
            other => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown modulation {other:?}"))),
        }
    };
    Ok(BandConfig {
        frequency_hz: number(get("frequency"), "frequency")?,
        channel: number(get("channel"), "channel")?,
        channel_spacing_hz: number(get("channel_spacing"), "channel_spacing")?,
        modulation,
        tx_power: number(get("frontend/tx_power"), "frontend/tx_power")?,
        fcs: flag("fcs")?,
        cca: Cca {
            enabled: flag("cca/enable")?,
            threshold_dbm: number(get("cca/threshold"), "cca/threshold")?,
            listen_us: number(get("cca/listen_us"), "cca/listen_us")?,
            retries: number(get("cca/retries"), "cca/retries")?,
            backoff_us: number(get("cca/backoff"), "cca/backoff")?,
        },
        frontend: Frontend {
            agc_map: number(get("frontend/agc_map"), "frontend/agc_map")?,
            agc_target: number(get("frontend/agc_target"), "frontend/agc_target")?,
            lna_bypass: flag("frontend/lna_bypass")?,
        },
    })
}

/// Reads a band from its sysfs directory. `up` is whether its interface is up (down reads as Off).
pub fn read(dir: &Path, up: bool) -> io::Result<BandConfig> {
    let get = |name: &str| std::fs::read_to_string(dir.join(name)).ok().map(|text| text.trim().to_owned());
    from_lookup_io(&get, !up)
}

/// Writes every attribute that differs from what the driver has; returns the names
/// written. Off is not written here (the caller takes the interface down).
pub fn apply(dir: &Path, config: &BandConfig) -> io::Result<Vec<&'static str>> {
    let mut written = Vec::new();
    for (name, value) in config.attributes() {
        let path = dir.join(name);
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current.trim() != value {
            std::fs::write(&path, &value).map_err(|error| io::Error::new(error.kind(), format!("{name} = {value}: {error}")))?;
            written.push(name);
        }
    }
    Ok(written)
}

/// The mux control message that carries a network-wide change of the mesh band:
/// `"KRC1" | seconds until the switch u16 | the band record`.
pub const SWITCH_MAGIC: &[u8; 4] = b"KRC1";

pub fn encode_switch(in_secs: u16, config: &BandConfig) -> Vec<u8> {
    let mut out = SWITCH_MAGIC.to_vec();
    out.extend_from_slice(&in_secs.to_be_bytes());
    out.extend_from_slice(config.encode().as_bytes());
    out
}

pub fn decode_switch(data: &[u8]) -> Option<(u16, BandConfig)> {
    let rest = data.strip_prefix(SWITCH_MAGIC)?;
    let (secs, record) = rest.split_first_chunk::<2>()?;
    let config = BandConfig::decode(std::str::from_utf8(record).ok()?)?;
    Some((u16::from_be_bytes(*secs), config))
}

/// How long after switching a node waits to hear a peer before it goes back.
pub const SWITCH_CONFIRM: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchStep {
    /// Not yet time.
    Wait,
    /// Apply the new configuration now.
    Apply(BandConfig),
    /// Switched and a peer was heard: done.
    Keep,
    /// Switched and nobody was heard in time: put the old configuration back.
    Revert(BandConfig),
}

/// A scheduled change of the mesh band.
#[derive(Clone, Copy, Debug)]
pub struct Switch {
    pub previous: BandConfig,
    pub next: BandConfig,
    pub at: Instant,
    switched_at: Option<Instant>,
}

impl Switch {
    pub fn new(previous: BandConfig, next: BandConfig, at: Instant) -> Self {
        Self { previous, next, at, switched_at: None }
    }

    /// A change already applied at `now` (on this node only): watched like a scheduled one.
    pub fn applied(previous: BandConfig, next: BandConfig, now: Instant) -> Self {
        Self { previous, next, at: now, switched_at: Some(now) }
    }

    pub fn switched_at(&self) -> Option<Instant> {
        self.switched_at
    }

    /// `heard_since` is the last time a peer was heard, if any.
    pub fn tick(&mut self, now: Instant, heard_since: Option<Instant>) -> SwitchStep {
        match self.switched_at {
            None if now < self.at => SwitchStep::Wait,
            None => {
                self.switched_at = Some(now);
                SwitchStep::Apply(self.next)
            }
            Some(switched) => {
                if heard_since.is_some_and(|heard| heard > switched) {
                    SwitchStep::Keep
                } else if now.duration_since(switched) >= SWITCH_CONFIRM {
                    SwitchStep::Revert(self.previous)
                } else {
                    SwitchStep::Wait
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BandConfig {
        BandConfig::default_for(true)
    }

    #[test]
    fn defaults_are_valid_and_out_of_band_is_refused() {
        assert!(sample().validate(&SUB_GHZ_RANGES).is_empty());
        assert!(BandConfig::default_for(false).validate(&G24_RANGES).is_empty());
        let mut wrong = sample();
        wrong.frequency_hz = 600_000_000;
        let problems = wrong.validate(&SUB_GHZ_RANGES);
        assert_eq!(problems[0].0, "frequency_hz");
        // The channel moves the centre: base in range, centre past the top.
        let mut far = sample();
        far.frequency_hz = 1_019_000_000;
        far.channel = 10;
        assert!(!far.validate(&SUB_GHZ_RANGES).is_empty());
        let mut bad = sample();
        bad.modulation = Modulation::Fsk { srate: 6, midx: 8, mord: 2, bt: 4, fec: false, dw: true, preamble: 0 };
        bad.cca.threshold_dbm = 10;
        bad.cca.backoff_us = 5000;
        bad.tx_power = 40;
        let fields: Vec<&str> = bad.validate(&SUB_GHZ_RANGES).into_iter().map(|(field, _)| field).collect();
        for expected in ["tx_power", "modulation.symbol_rate", "modulation.preamble", "cca.threshold_dbm", "cca.backoff_us"] {
            assert!(fields.contains(&expected), "{expected} in {fields:?}");
        }
    }

    #[test]
    fn record_round_trips_for_every_modulation() {
        for modulation in [
            Modulation::Off,
            Modulation::Ofdm { mcs: 3, opt: 2 },
            Modulation::Qpsk { fchip: 3, mode: 4 },
            Modulation::Fsk { srate: 2, midx: 3, mord: 1, bt: 2, fec: true, dw: false, preamble: 64 },
        ] {
            let config = BandConfig { modulation, ..sample() };
            assert_eq!(BandConfig::decode(&config.encode()), Some(config), "{modulation:?}");
        }
        assert_eq!(BandConfig::decode("frequency=1"), None);
    }

    #[test]
    fn sysfs_read_and_apply_write_only_changes_modulation_first() {
        let dir = std::env::temp_dir().join(format!("kaonic-mesh-band-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["ofdm", "qpsk", "fsk", "cca", "frontend"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        // What the board showed for rf09_b, plus the FSK/QPSK defaults.
        let fsk = Modulation::Fsk { srate: 3, midx: 3, mord: 0, bt: 0, fec: false, dw: true, preamble: 8 };
        let with_fsk = BandConfig { modulation: fsk, ..sample() };
        let with_qpsk = BandConfig { modulation: Modulation::Qpsk { fchip: 0, mode: 0 }, ..sample() };
        for (name, value) in with_fsk.attributes().into_iter().chain(with_qpsk.attributes()) {
            std::fs::write(dir.join(name), format!("{value}\n")).unwrap();
        }
        std::fs::write(dir.join("modulation"), "ofdm\n").unwrap();
        std::fs::write(dir.join("ofdm/mcs"), "6\n").unwrap();
        std::fs::write(dir.join("ofdm/opt"), "0\n").unwrap();
        assert_eq!(read(&dir, true).unwrap(), sample());
        assert_eq!(read(&dir, false).unwrap().modulation, Modulation::Off);

        let mut next = sample();
        next.modulation = Modulation::Ofdm { mcs: 4, opt: 1 };
        next.channel = 3;
        let written = apply(&dir, &next).unwrap();
        assert_eq!(written, vec!["ofdm/opt", "ofdm/mcs", "channel"]);
        assert!(apply(&dir, &next).unwrap().is_empty());
        assert_eq!(read(&dir, true).unwrap(), next);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn switch_message_round_trips() {
        let config = BandConfig { channel: 7, ..sample() };
        assert_eq!(decode_switch(&encode_switch(10, &config)), Some((10, config)));
        assert_eq!(decode_switch(b"KRC1\x00"), None);
        assert_eq!(decode_switch(b"XXXX\x00\x0afrequency=1"), None);
    }

    #[test]
    fn switch_applies_at_its_time_and_reverts_without_a_peer() {
        let start = Instant::now();
        let previous = sample();
        let next = BandConfig { channel: 3, ..sample() };
        let mut switch = Switch::new(previous, next, start + Duration::from_secs(10));
        assert_eq!(switch.tick(start, None), SwitchStep::Wait);
        assert_eq!(switch.tick(start + Duration::from_secs(10), None), SwitchStep::Apply(next));
        assert_eq!(switch.tick(start + Duration::from_secs(30), Some(start)), SwitchStep::Wait, "heard before the switch does not count");
        assert_eq!(switch.tick(start + Duration::from_secs(70), None), SwitchStep::Revert(previous));

        let mut kept = Switch::new(previous, next, start);
        kept.tick(start, None);
        assert_eq!(kept.tick(start + Duration::from_secs(5), Some(start + Duration::from_secs(4))), SwitchStep::Keep);
    }
}
