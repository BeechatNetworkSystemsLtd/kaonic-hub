//! Remote management: the Kaonic Admin asks a node for its state, changes its settings and
//! opens a shell on it, over the node's authenticated link (`proto` for the messages).
//!
//! A node takes orders only from its own admin's link; the admin takes answers only from the
//! node it asked. Requests are retried until answered and a node answers a repeat from its
//! cache, so an operation runs once even when the radio loses the first answer.

pub mod admin;
mod node;
pub mod proto;
mod pty;
pub mod stream;

use std::collections::VecDeque;
use std::time::Duration;

use kaonic_mux::{Kind, Message as MuxMessage};

use crate::app::App;
use proto::Message;

/// What fits one radio frame between two hubs.
const MAX_PACKET: usize = 799;

/// Sends one message to `peer` over its authenticated link; false if there is none.
pub(crate) async fn send(app: &App, peer: &str, message: &Message) -> bool {
    let mut queue = VecDeque::from([MuxMessage { kind: Kind::Control, stream: proto::STREAM, payload: message.encode() }]);
    let (Some(packet), _) = kaonic_mux::pack(&mut queue, MAX_PACKET) else { return false };
    match app.links.get() {
        Some(links) => links.send(peer, &packet).await,
        None => false,
    }
}

/// Routes remote-management messages from the links to the admin's or the node's side.
pub fn spawn(app: App) {
    std::sync::LazyLock::force(&node::STARTED);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let mut received = app.links.get().map(|links| links.subscribe());
        loop {
            tokio::select! {
                message = async {
                    match &mut received {
                        Some(received) => received.recv().await,
                        None => std::future::pending().await,
                    }
                } => match message {
                    Ok(message) => on_packet(&app, &message.peer, &message.packet).await,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => received = None,
                },
                _ = tick.tick() => {
                    if received.is_none() {
                        received = app.links.get().map(|links| links.subscribe());
                    }
                }
            }
        }
    });
}

async fn on_packet(app: &App, peer: &str, packet: &[u8]) {
    let Ok(frames) = kaonic_mux::parse(packet) else { return };
    for frame in frames {
        if frame.kind != Kind::Control || frame.stream != proto::STREAM {
            continue;
        }
        let Some(message) = Message::decode(frame.payload) else {
            log::debug!("remote: dropped a malformed message from {peer}");
            continue;
        };
        // Answers for what this admin asked go to the admin's side; everything else is an
        // order, which only our admin may give.
        if admin::on_message(peer, &message) || node::on_session_message(peer, &message) {
            continue;
        }
        // (On the admin device our admin is this device itself, never a peer.)
        if crate::api::our_admin(app).await.ok().flatten().as_deref() != Some(peer) {
            // Late traffic for a shell or request already over is expected; an order is not.
            if matches!(message, Message::Request { .. } | Message::Open { .. } | Message::Resize { .. }) {
                static NOTED: crate::clock::Every = crate::clock::Every::secs(crate::clock::LOG_EVERY);
                if NOTED.due() {
                    log::warn!("remote: ignored an order from {peer}, which is not our admin");
                } else {
                    log::debug!("remote: ignored an order from {peer}, which is not our admin");
                }
            } else {
                log::debug!("remote: dropped late remote-management traffic from {peer}");
            }
            continue;
        }
        node::on_message(app, peer, message).await;
    }
}
