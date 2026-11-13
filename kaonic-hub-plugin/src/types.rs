//! What the hub answers. Every field has a default, so a newer hub that adds or drops one
//! does not break an older plugin.

use std::collections::BTreeMap;

use serde::Deserialize;

/// This plugin and the node it runs on (`GET /self`).
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Me {
    /// This plugin's id.
    pub plugin: String,
    pub version: String,
    /// What the admin granted: `audio`, `realtime`, `mesh`, `network`, `root`.
    pub permissions: Vec<String>,
    /// This node's id; None where the hub runs no mesh.
    pub node: Option<String>,
    pub codename: String,
    pub hub_version: String,
    pub limits: Limits,
}

impl Me {
    pub fn has(&self, permission: &str) -> bool {
        self.permissions.iter().any(|granted| granted == permission)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Largest message to a node, in bytes (one link packet).
    pub max_message: usize,
    /// Largest broadcast, in bytes.
    pub max_broadcast: usize,
    /// This plugin's share of the channel, 0-1.
    pub airtime_share: f64,
    /// Messages that may wait; more drop the oldest.
    pub queue: usize,
    pub store: StoreLimits,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct StoreLimits {
    pub max_value: usize,
    /// Keys and values together.
    pub max_bytes: usize,
    pub max_keys: usize,
}

/// A trusted node (`GET /nodes`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Node {
    pub id: String,
    /// As it announces itself; empty if not heard yet.
    pub codename: String,
    /// The network's admin.
    pub admin: bool,
    pub link: Link,
    /// The same plugin runs there (as last heard).
    pub runs_plugin: bool,
    /// dBm, of its last announce.
    pub rssi: Option<i32>,
    pub rtt_ms: Option<u64>,
    /// Unix seconds.
    pub last_heard: Option<i64>,
}

/// The hub's link to a node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Link {
    Up,
    Connecting,
    #[default]
    Down,
    /// A state this SDK does not know yet.
    #[serde(other)]
    Other,
}

/// A message the hub took (`202`): `sent` or `dropped` events follow with this `id`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Queued {
    pub id: u64,
    /// How many nodes it goes to (1 for a node or a broadcast; may be 0 for all).
    pub nodes: usize,
}

/// This plugin's use of the mesh since the hub started (`GET /stats`).
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    pub dropped: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Time on air used (estimated).
    pub airtime_ms: u64,
    /// Messages waiting now.
    pub queue: usize,
    /// Its budget, 0-1.
    pub airtime_share: f64,
    pub per_node: BTreeMap<String, Counts>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Counts {
    pub sent: u64,
    pub received: u64,
    pub dropped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_new_fields_are_fine() {
        let node: Node = serde_json::from_str(r#"{"id":"ab","link":"warming_up","color":"red","rssi":-70}"#).unwrap();
        assert_eq!((node.id.as_str(), node.link, node.rssi, node.runs_plugin), ("ab", Link::Other, Some(-70), false));
        let me: Me = serde_json::from_str(r#"{"plugin":"echo","permissions":["mesh","telepathy"],"node":null}"#).unwrap();
        assert!(me.has("mesh") && !me.has("root"));
        assert_eq!(me.limits.max_message, 0);
        let stats: Stats = serde_json::from_str(r#"{"per_node":{"ab":{"sent":2}}}"#).unwrap();
        assert_eq!(stats.per_node["ab"].sent, 2);
    }
}
