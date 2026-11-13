//! The event socket's WebSocket, on [`kaonic_hub_common::ws`].

use std::time::Duration;

pub use kaonic_hub_common::ws::{CLOSE, Incoming, PONG, TEXT};
use kaonic_hub_common::ws::{self as common, Limits};
use tokio::io::{ReadHalf, WriteHalf};

use crate::error::{Error, Result};
use crate::http::{Endpoint, Io};

/// The largest message taken from the hub (its events are well under 4 KiB).
pub const MAX_MESSAGE: usize = 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const LIMITS: Limits = Limits { max_head: 16 * 1024, max_message: MAX_MESSAGE, refusal_wait: Duration::from_secs(2) };

pub type Reader = common::Reader<ReadHalf<Box<dyn Io>>>;
pub type Writer = common::Writer<WriteHalf<Box<dyn Io>>>;

/// Opens a WebSocket at `path` of the API. An answer other than 101 is the API's error.
pub async fn connect(endpoint: &Endpoint, path: &str, token: &str) -> Result<(Reader, Writer)> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(endpoint, path, token))
        .await
        .map_err(|_| Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "the hub did not open the event socket in time")))?
}

async fn handshake(endpoint: &Endpoint, path: &str, token: &str) -> Result<(Reader, Writer)> {
    let stream = endpoint.connect().await?;
    let target = format!("{}{path}", endpoint.base);
    let bearer = format!("Bearer {token}");
    Ok(common::handshake(stream, &target, &endpoint.authority, &[("authorization", &bearer)], LIMITS).await?)
}
