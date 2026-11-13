//! The one error of the SDK.

use serde::Deserialize;

/// What went wrong.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Not run by the installer (`KAONIC_HUB_API` or `KAONIC_PLUGIN_TOKEN` missing), or a
    /// hub address that is neither `unix:<path>` nor `http://host:port`.
    Config(String),
    /// 401: the token is wrong, or was replaced (the plugin was reinstalled or rolled back)
    /// or removed. The installer restarts the plugin with the new one.
    Unauthorized,
    /// 403: the plugin lacks a permission (`missing_permission`: add it to `[service]
    /// permissions` in its manifest).
    Forbidden { code: String, message: String },
    /// 404: no such trusted node.
    NotFound,
    /// 413: a message larger than `limits.max_message` (`too_large`), or the store is full
    /// (`store_full`).
    TooLarge { code: String },
    /// 429 `busy`: the message could not be queued.
    QueueFull,
    /// 429 `too_many_sockets`: this plugin has 4 event sockets open already.
    TooManySockets,
    /// 409 `ambiguous_name`: another plugin on this node has the same mesh name (the first
    /// 8 bytes of sha256 of the id), so the mesh is off for both. Not fixed by retrying.
    AmbiguousName,
    /// Any other answer of the hub that is not a success.
    Hub { status: u16, code: String, message: String },
    /// A bad argument, caught before it was sent (a store key), or a stored value that is
    /// not of the type asked for.
    Invalid(String),
    /// The hub could not be reached (no socket yet, see [`crate::Hub::wait`]), closed the
    /// connection unanswered, or the connection broke.
    Io(std::io::Error),
    /// The hub answered something that is not HTTP, JSON or WebSocket as expected.
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// The hub's error code, if it answered with one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Forbidden { code, .. } | Error::TooLarge { code } | Error::Hub { code, .. } => Some(code),
            Error::QueueFull => Some("busy"),
            Error::TooManySockets => Some("too_many_sockets"),
            Error::AmbiguousName => Some("ambiguous_name"),
            _ => None,
        }
    }

    /// The error for a hub answer that is not 2xx.
    pub(crate) fn from_answer(status: u16, body: &[u8]) -> Self {
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct Body {
            code: String,
            message: String,
        }
        let body: Body = serde_json::from_slice(body).unwrap_or_default();
        match status {
            401 => Error::Unauthorized,
            403 => Error::Forbidden { code: body.code, message: body.message },
            404 => Error::NotFound,
            413 => Error::TooLarge { code: body.code },
            409 if body.code == "ambiguous_name" => Error::AmbiguousName,
            429 if body.code == "too_many_sockets" => Error::TooManySockets,
            429 => Error::QueueFull,
            _ => Error::Hub { status, code: body.code, message: body.message },
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Config(why) => write!(f, "{why}"),
            Error::Unauthorized => f.write_str("the hub refused this plugin's token (replaced or removed)"),
            Error::Forbidden { code, message } => write!(f, "forbidden ({code}): {message}"),
            Error::NotFound => f.write_str("not found"),
            Error::TooLarge { code } => write!(f, "too large ({code})"),
            Error::QueueFull => f.write_str("the hub could not queue the message"),
            Error::TooManySockets => f.write_str("this plugin has 4 event sockets open already"),
            Error::AmbiguousName => f.write_str("another plugin on this node has the same mesh name: the mesh is off for both"),
            Error::Hub { status, code, message } => write!(f, "the hub answered {status} ({code}): {message}"),
            Error::Invalid(why) => write!(f, "{why}"),
            Error::Io(error) => write!(f, "talking to the hub: {error}"),
            Error::Protocol(why) => write!(f, "the hub answered wrongly: {why}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

/// An answer the hub did not give at all is retried by the caller before it gets here.
impl From<kaonic_hub_common::http::Error> for Error {
    fn from(error: kaonic_hub_common::http::Error) -> Self {
        use kaonic_hub_common::http::Error as Http;
        match error {
            Http::Io(error) | Http::Unanswered(Some(error)) => Error::Io(error),
            Http::Unanswered(None) => Error::Io(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "the hub closed the connection unanswered")),
            Http::Protocol(why) => Error::Protocol(why),
        }
    }
}

impl From<kaonic_hub_common::ws::Error> for Error {
    fn from(error: kaonic_hub_common::ws::Error) -> Self {
        use kaonic_hub_common::ws::Error as Ws;
        match error {
            Ws::Io(error) => Error::Io(error),
            // Over the hub's connection cap, or not this plugin's user.
            Ws::Unanswered => Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "the hub closed the event socket unanswered (over its 16 connections per plugin, or not this plugin's user)",
            )),
            Ws::Refused { status, body } => Error::from_answer(status, &body),
            Ws::Closed => Error::Io(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the hub closed the event socket")),
            Ws::CloseSent => Error::Io(std::io::Error::new(std::io::ErrorKind::NotConnected, "the event socket is closed")),
            Ws::Protocol(why) => Error::Protocol(format!("websocket: {why}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_map_to_errors() {
        assert!(matches!(Error::from_answer(401, b""), Error::Unauthorized));
        let forbidden = Error::from_answer(403, br#"{"code":"missing_permission","message":"needs mesh","details":{}}"#);
        assert_eq!(forbidden.code(), Some("missing_permission"));
        assert!(matches!(Error::from_answer(404, b"not json"), Error::NotFound));
        assert_eq!(Error::from_answer(413, br#"{"code":"store_full"}"#).code(), Some("store_full"));
        assert!(matches!(Error::from_answer(429, b"{}"), Error::QueueFull));
        assert!(matches!(Error::from_answer(429, br#"{"code":"busy"}"#), Error::QueueFull));
        assert!(matches!(Error::from_answer(429, br#"{"code":"too_many_sockets","message":"4 open"}"#), Error::TooManySockets));
        assert!(matches!(Error::from_answer(409, br#"{"code":"ambiguous_name","message":"same name"}"#), Error::AmbiguousName));
        assert!(matches!(Error::from_answer(409, br#"{"code":"conflict","message":"no group key"}"#), Error::Hub { status: 409, .. }));
    }
}
