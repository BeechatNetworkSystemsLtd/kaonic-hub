//! Push-to-talk to every node at once: the parts with no I/O.
//!
//! - [`packet`]: the voice packet inside the encrypted GROUP data, and the admin's signature.
//! - [`relay`]: re-sending each new packet once, after a random delay, unless enough
//!   neighbours already did (counter-based flooding), so voice reaches nodes several hops away.
//! - [`floor`]: one talker per group; the admin preempts members.
//! - [`jitter`]: playout of a burst, in order, every 20 ms, with lost frames concealed.
//! - [`packer`]: our own burst into packets of a few frames, sized to the LDPC blocks
//!   ([`airtime`]) like the kaonic-audio-ptt plugin.
//! - [`squelch`]: the plugin's level gate in front of the encoder (how the hardware PTT
//!   button, which only unmutes the microphone, keys the radio).
//!
//! Time and randomness are passed in, so all of it is deterministic and tested here. The hub
//! does the audio, the codec and the GROUP destination.

pub mod airtime;
pub mod floor;
pub mod gate;
pub mod jitter;
pub mod packer;
pub mod packet;
pub mod relay;
pub mod replay;
pub mod squelch;

pub use gate::{Gate, Verdict};
pub use floor::{Busy, Floor, FloorEvent, FloorState, KeyedBurst, Talker, recheck_delay};
pub use jitter::{Jitter, JitterStats, Playout};
pub use packer::Packer;
pub use packet::{MAX_FRAMES, Packet, VERSION, admin_signed_bytes, codec, flags, sign_admin, verify_admin};
pub use relay::{Heard, Relay, RelayConfig, RelayStats};
pub use replay::Replay;
pub use squelch::{Squelch, SquelchConfig, SquelchDecision, frame_level_dbfs};

/// Audio frame length.
pub const FRAME_MS: u64 = 20;

#[cfg(test)]
mod flooding;
