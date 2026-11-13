//! The event socket (`/events`): what the hub tells the plugin, and messages sent on it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kaonic_hub_common::base64;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::ws::{self, Incoming, Reader, Writer};

/// Something the hub says. Matches should end with `_ => {}`: newer hubs and SDKs add more.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// A message from this plugin on another node.
    Received {
        from: String,
        channel: u8,
        data: Vec<u8>,
        /// Heard on the group channel: `from` is as the sender says, not proved.
        broadcast: bool,
        rssi: Option<i32>,
    },
    /// A link to a node came up.
    NodeUp { node: String },
    NodeDown { node: String },
    /// This plugin started on a node.
    PluginUp { node: String },
    PluginDown { node: String },
    /// A queued message went on air (once per node for a message to all).
    Sent { id: u64, node: Option<String> },
    /// A queued message was dropped.
    Dropped { id: u64, reason: DropReason, node: Option<String> },
    /// How busy the channel is, 0-1; sent when it crosses 0.7 either way. Slow down above.
    Congestion { level: f64 },
    /// The hub took a message sent on this socket; `reference` is what
    /// [`Events::send`] returned.
    Queued { reference: Option<u64>, id: u64, nodes: usize },
    /// The hub refused a message sent on this socket; `code` as the API's errors.
    Refused { reference: Option<u64>, code: String, message: String },
    /// An event this SDK does not know, as JSON.
    Other(serde_json::Value),
}

/// Why a message was dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropReason {
    /// The plugin's queue was full: the oldest message went.
    QueueFull,
    TooLarge,
    /// No link to the node.
    NoLink,
    /// It waited too long for the plugin's airtime budget.
    OverBudget,
    /// The plugin does not run there.
    NotRunning,
    Other(String),
}

impl DropReason {
    fn parse(text: &str) -> Self {
        match text {
            "queue_full" => Self::QueueFull,
            "too_large" => Self::TooLarge,
            "no_link" => Self::NoLink,
            "over_budget" => Self::OverBudget,
            "not_running" => Self::NotRunning,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// Where a message on the socket goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// This plugin on one node.
    Node(String),
    /// This plugin on every linked node that runs it.
    All,
    /// One transmission heard by every neighbour (one hop), on the group channel.
    Broadcast,
}

impl Target {
    fn wire(&self) -> &str {
        match self {
            Target::Node(node) => node,
            Target::All => "*",
            Target::Broadcast => "broadcast",
        }
    }
}

impl Event {
    /// An event from its JSON text.
    pub fn parse(text: &str) -> Result<Event> {
        let value: serde_json::Value = serde_json::from_str(text).map_err(|error| Error::Protocol(format!("event: {error}")))?;
        Ok(Self::from_json(value))
    }

    fn from_json(value: serde_json::Value) -> Event {
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct Raw {
            #[serde(rename = "type")]
            kind: String,
            from: String,
            channel: u8,
            data: String,
            broadcast: bool,
            rssi: Option<i32>,
            node: Option<String>,
            id: u64,
            reason: String,
            level: f64,
            #[serde(rename = "ref")]
            reference: Option<serde_json::Value>,
            nodes: usize,
            code: String,
            message: String,
        }
        let Ok(raw) = Raw::deserialize(&value) else { return Event::Other(value) };
        let node = || raw.node.clone().unwrap_or_default();
        let reference = raw.reference.as_ref().and_then(serde_json::Value::as_u64);
        match raw.kind.as_str() {
            "received" => match base64::decode(&raw.data) {
                Some(data) => Event::Received { from: raw.from, channel: raw.channel, data, broadcast: raw.broadcast, rssi: raw.rssi },
                None => Event::Other(value),
            },
            "node_up" => Event::NodeUp { node: node() },
            "node_down" => Event::NodeDown { node: node() },
            "plugin_up" => Event::PluginUp { node: node() },
            "plugin_down" => Event::PluginDown { node: node() },
            "sent" => Event::Sent { id: raw.id, node: raw.node },
            "dropped" => Event::Dropped { id: raw.id, reason: DropReason::parse(&raw.reason), node: raw.node },
            "congestion" => Event::Congestion { level: raw.level },
            "queued" => Event::Queued { reference, id: raw.id, nodes: raw.nodes },
            "refused" => Event::Refused { reference, code: raw.code, message: raw.message },
            _ => Event::Other(value),
        }
    }
}

/// The event socket. While it is open the plugin counts as running on the mesh: other
/// nodes hear `plugin_up`, and messages for it are delivered.
///
/// It ends when the hub closes it (the token was replaced, the hub restarts) or the
/// connection breaks; [`Events::next`] then gives None. Reconnecting is the plugin's
/// choice: call [`crate::Hub::events`] again, after a pause. Events while it was closed
/// are not kept.
pub struct Events {
    reader: Reader,
    sender: Sender,
    ended: bool,
}

/// Sends messages on an event socket, from any task. Cheap to clone.
#[derive(Clone)]
pub struct Sender {
    writer: Arc<Mutex<Writer>>,
    next_ref: Arc<AtomicU64>,
}

impl Events {
    pub(crate) fn new(reader: Reader, writer: Writer) -> Self {
        Self { reader, sender: Sender { writer: Arc::new(Mutex::new(writer)), next_ref: Arc::new(AtomicU64::new(1)) }, ended: false }
    }

    /// The next event; None once the socket has closed. Cancel-safe (may be used in
    /// `tokio::select!`).
    pub async fn next(&mut self) -> Option<Event> {
        self.try_next().await.ok().flatten()
    }

    /// As [`Events::next`], with why it ended: `Ok(None)` when the hub closed it properly.
    pub async fn try_next(&mut self) -> Result<Option<Event>> {
        while !self.ended {
            let incoming = match self.reader.next().await {
                Ok(incoming) => incoming,
                Err(error) => {
                    self.ended = true;
                    return Err(error.into());
                }
            };
            match incoming {
                Incoming::Text(text) => match Event::parse(&text) {
                    Ok(event) => return Ok(Some(event)),
                    Err(error) => {
                        self.ended = true;
                        return Err(error);
                    }
                },
                Incoming::Ping(payload) => {
                    let mut writer = self.sender.writer.lock().await;
                    if !writer.closed() {
                        writer.send(ws::PONG, &payload).await?;
                    }
                }
                Incoming::Close(code) => {
                    self.ended = true;
                    let mut writer = self.sender.writer.lock().await;
                    if !writer.closed() {
                        let _ = writer.send(ws::CLOSE, &code.unwrap_or(1000).to_be_bytes()).await;
                    }
                }
                Incoming::Binary(_) | Incoming::Pong => {}
            }
        }
        Ok(None)
    }

    /// Sends a message on the socket; see [`Sender::send`].
    pub async fn send(&self, to: Target, channel: u8, data: &[u8]) -> Result<u64> {
        self.sender.send(to, channel, data).await
    }

    /// A handle to send on this socket from other tasks.
    pub fn sender(&self) -> Sender {
        self.sender.clone()
    }

    /// Closes the socket: the plugin no longer counts as running on the mesh.
    pub async fn close(mut self) -> Result<()> {
        self.sender.writer.lock().await.send(ws::CLOSE, &1000u16.to_be_bytes()).await?;
        // Wait briefly for the hub's close.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async { while let Ok(Some(_)) = self.try_next().await {} }).await;
        Ok(())
    }
}

impl Sender {
    /// Sends a message, as the POSTs do but without a round trip each. Returns the
    /// reference the answer will carry: [`Event::Queued`] (with the message's id) or
    /// [`Event::Refused`]. Do not cancel it half way: the frame would be cut.
    pub async fn send(&self, to: Target, channel: u8, data: &[u8]) -> Result<u64> {
        let reference = self.next_ref.fetch_add(1, Ordering::Relaxed);
        let text = serde_json::json!({ "to": to.wire(), "channel": channel, "data": base64::encode(data), "ref": reference }).to_string();
        self.writer.lock().await.send(ws::TEXT, text.as_bytes()).await?;
        Ok(reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_from_the_hub() {
        let parse = |text: &str| Event::parse(text).unwrap();
        assert_eq!(
            parse(r#"{"type":"received","from":"00112233445566778899aabbccddeeff","channel":9,"data":"aGk=","broadcast":false,"rssi":-70}"#),
            Event::Received { from: "00112233445566778899aabbccddeeff".into(), channel: 9, data: b"hi".to_vec(), broadcast: false, rssi: Some(-70) }
        );
        assert_eq!(parse(r#"{"type":"node_up","node":"ab"}"#), Event::NodeUp { node: "ab".into() });
        assert_eq!(parse(r#"{"type":"plugin_down","node":"ab"}"#), Event::PluginDown { node: "ab".into() });
        assert_eq!(parse(r#"{"type":"sent","id":4,"node":null}"#), Event::Sent { id: 4, node: None });
        assert_eq!(parse(r#"{"type":"dropped","id":5,"node":"ab","reason":"no_link"}"#), Event::Dropped { id: 5, reason: DropReason::NoLink, node: Some("ab".into()) });
        assert_eq!(parse(r#"{"type":"dropped","id":5,"reason":"solar_flare"}"#), Event::Dropped { id: 5, reason: DropReason::Other("solar_flare".into()), node: None });
        assert_eq!(parse(r#"{"type":"congestion","level":0.95}"#), Event::Congestion { level: 0.95 });
        assert_eq!(parse(r#"{"type":"queued","ref":3,"id":7,"nodes":1}"#), Event::Queued { reference: Some(3), id: 7, nodes: 1 });
        assert_eq!(
            parse(r#"{"type":"refused","ref":null,"code":"bad_request","message":"no"}"#),
            Event::Refused { reference: None, code: "bad_request".into(), message: "no".into() }
        );
        // Newer hubs: unknown events and fields.
        assert!(matches!(parse(r#"{"type":"weather","sunny":true}"#), Event::Other(_)));
        assert_eq!(parse(r#"{"type":"node_down","node":"ab","why":"gone"}"#), Event::NodeDown { node: "ab".into() });
        assert!(matches!(parse(r#"{"type":"received","data":"not base64!"}"#), Event::Other(_)));
        assert!(matches!(parse(r#"{"type":"congestion","level":"high"}"#), Event::Other(_)));
        assert!(Event::parse("not json").is_err());
    }
}
