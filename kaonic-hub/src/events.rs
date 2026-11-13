//! The hub's event bus: every live change, for the events WebSocket and for subsystems.

use serde::Serialize;
use tokio::sync::broadcast;

use crate::clock;

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub topic: &'static str,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub ts_ms: i64,
    pub data: serde_json::Value,
}

#[derive(Clone)]
pub struct Bus {
    sender: broadcast::Sender<Event>,
}

impl Bus {
    pub fn new() -> Self {
        // Slow sockets that fall this far behind are told to resync, not waited for.
        Self {
            sender: broadcast::channel(256).0,
        }
    }

    pub fn publish(&self, topic: &'static str, kind: &'static str, data: impl Serialize) {
        let data = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
        // No subscribers is fine.
        let _ = self.sender.send(Event {
            topic,
            kind,
            ts_ms: clock::now_ms(),
            data,
        });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    /// How many are listening (sockets and internal tasks).
    pub fn receivers(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}
