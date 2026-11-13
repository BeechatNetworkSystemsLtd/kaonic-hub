//! Reticulum links for request/response exchanges between two nodes
//! (provisioning, later AUTH and the mux).
//!
//! The opening side holds an [`OutLink`]: the link to one peer's destination,
//! with that link's own events. The answering side sees [`Incoming`] messages
//! on its destination and answers on the same link with [`Mesh::reply`].

use std::io;
use std::sync::Arc;
use std::time::Duration;

use reticulum::destination::link::{LinkEvent, LinkEventData, LinkId, LinkStatus};
use reticulum::hash::AddressHash;
use reticulum::transport::Transport;
use tokio::sync::broadcast;

use crate::node::{Mesh, hex};

/// A link this node opened to a peer.
pub struct OutLink {
    id: LinkId,
    destination: AddressHash,
    events: broadcast::Receiver<LinkEventData>,
    transport: Arc<tokio::sync::Mutex<Transport>>,
}

/// A message that arrived on a link another node opened to this one.
#[derive(Clone, Debug)]
pub struct Incoming {
    pub link: LinkId,
    pub data: Vec<u8>,
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, what.to_owned())
}

impl OutLink {
    /// The link's id: both ends know it, so it binds a message to this link.
    pub fn id(&self) -> &LinkId {
        &self.id
    }

    pub async fn send(&self, payload: &[u8]) {
        self.transport.lock().await.send_to_out_links(&self.destination, payload).await;
    }

    /// The next message on this link, or an error if it closes or `timeout` passes.
    pub async fn recv(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let event = tokio::time::timeout_at(deadline, self.events.recv()).await.map_err(|_| timed_out("no answer on the link"))?;
            match event {
                Ok(event) if event.id == self.id => match event.event {
                    LinkEvent::Data(payload) => return Ok(payload.as_slice().to_vec()),
                    LinkEvent::Closed => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "the link closed")),
                    _ => {}
                },
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "the transport stopped")),
            }
        }
    }

    pub async fn close(self) {
        let _ = self.transport.lock().await.link_close(self.id).await;
    }
}

impl Mesh {
    /// Opens (or reuses) a link to the peer `id` and waits until it is active.
    pub async fn open_link(&self, id: &str, timeout: Duration) -> io::Result<OutLink> {
        let desc = self.destination_of(id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "this node has not been heard announcing"))?;
        let transport = self.transport().clone();
        // Subscribe first: the activation must not slip past.
        let mut events = transport.lock().await.out_link_events();
        let link = transport.lock().await.link(desc).await;
        let (link_id, active) = {
            let link = link.lock().await;
            (*link.id(), link.status() == LinkStatus::Active)
        };
        if !active && let Err(error) = wait_active(&mut events, link_id, timeout).await {
            // A pending link would be handed out again by the next attempt and never come up.
            let _ = transport.lock().await.link_close(link_id).await;
            return Err(error);
        }
        log::debug!("mesh: link {} to {id} is up", hex(&link_id));
        Ok(OutLink { id: link_id, destination: desc.address_hash, events, transport })
    }

    /// Messages arriving on links other nodes opened to this one.
    pub async fn incoming(&self) -> broadcast::Receiver<LinkEventData> {
        self.transport().lock().await.in_link_events()
    }

    /// Answers on exactly the link a message came in on.
    pub async fn reply(&self, link: &LinkId, payload: &[u8]) -> io::Result<()> {
        let transport = self.transport().lock().await;
        let link = transport.find_in_link(link).await.ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "the link is gone"))?;
        let packet = link.lock().await.data_packet(payload).map_err(|error| io::Error::other(format!("{error:?}")))?;
        transport.send_packet(packet).await;
        Ok(())
    }
}

/// Waits for Reticulum to activate the link `id`.
async fn wait_active(events: &mut broadcast::Receiver<LinkEventData>, id: LinkId, timeout: Duration) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv()).await.map_err(|_| timed_out("the link did not come up"))?;
        match event {
            Ok(event) if event.id == id => match event.event {
                LinkEvent::Activated => return Ok(()),
                LinkEvent::Closed => return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "the link closed while opening")),
                _ => {}
            },
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "the transport stopped")),
        }
    }
}

/// The data of a link event, if it is a message.
pub fn message(event: &LinkEventData) -> Option<Incoming> {
    match &event.event {
        LinkEvent::Data(payload) => Some(Incoming { link: event.id, data: payload.as_slice().to_vec() }),
        _ => None,
    }
}
