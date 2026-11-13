//! A minimal HTTP/1.1 client, one request per connection (`connection: close`): request
//! heads, bodies of a known length, and answers by `Content-Length`, in chunks or to the
//! close. Over any tokio stream; limits are the caller's, and so are timeouts.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// A connection: a Unix socket, TCP, or anything else that reads and writes.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// What went wrong.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The other end closed, or the connection broke, before a byte of the answer: it may
    /// not have read the request. With the read error, if there was one.
    Unanswered(Option<std::io::Error>),
    /// The answer is not HTTP as expected, or over a limit.
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;

fn protocol(why: &str) -> Error {
    Error::Protocol(why.to_owned())
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(error) | Error::Unanswered(Some(error)) => write!(f, "{error}"),
            Error::Unanswered(None) => f.write_str("closed before answering"),
            Error::Protocol(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

/// `Unanswered` without an error and `Protocol` are `InvalidData`.
impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Io(error) | Error::Unanswered(Some(error)) => error,
            Error::Unanswered(None) => std::io::Error::new(std::io::ErrorKind::InvalidData, "closed before answering"),
            Error::Protocol(why) => std::io::Error::new(std::io::ErrorKind::InvalidData, why),
        }
    }
}

/// Where a server listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    Unix(PathBuf),
    /// A host (no brackets around an IPv6 address) and port.
    Tcp(String, u16),
}

impl Address {
    /// Connects; TCP without Nagle's delay.
    pub async fn connect(&self) -> std::io::Result<Box<dyn Io>> {
        match self {
            Address::Unix(path) => Ok(Box::new(UnixStream::connect(path).await?)),
            Address::Tcp(host, port) => {
                let stream = TcpStream::connect((host.as_str(), *port)).await?;
                let _ = stream.set_nodelay(true);
                Ok(Box::new(stream))
            }
        }
    }
}

/// Connects to a Unix socket within `timeout` (`TimedOut`), and only if `uid` serves it
/// (`PermissionDenied`, before anything is sent).
pub async fn connect_unix_as(path: &Path, uid: u32, timeout: Duration) -> std::io::Result<UnixStream> {
    let stream = tokio::time::timeout(timeout, UnixStream::connect(path))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
    let peer = crate::peer_uid(&stream).ok();
    if peer != Some(uid) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("{} is served by user {peer:?}, not user {uid}", path.display())));
    }
    Ok(stream)
}

/// A request line and headers, in the order given, and the blank line.
pub fn request_head(method: &str, target: &str, headers: &[(&str, &str)]) -> String {
    let mut head = format!("{method} {target} HTTP/1.1\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    head
}

/// Writes a request head and a body held in memory, and flushes.
pub async fn write_request(stream: &mut (impl AsyncWrite + Unpin), head: &str, body: &[u8]) -> std::io::Result<()> {
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Copies exactly `length` bytes of `body` (a file, say) to `stream`, in pieces, and
/// flushes; a body that ends sooner is `UnexpectedEof`, one that is longer is cut.
pub async fn write_body(stream: &mut (impl AsyncWrite + Unpin), body: &mut (impl AsyncRead + Unpin), length: u64) -> std::io::Result<()> {
    let mut chunk = vec![0u8; 64 * 1024];
    let mut sent = 0u64;
    while sent < length {
        let read = body.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the body is shorter than it was"));
        }
        let read = read.min((length - sent) as usize);
        stream.write_all(&chunk[..read]).await?;
        sent += read as u64;
    }
    stream.flush().await
}

/// Reads an answer until it is whole by its length, or the other end closes; more than
/// `max` bytes is an error.
pub async fn read_answer(stream: &mut (impl AsyncRead + Unpin), max: usize) -> Result<Vec<u8>> {
    let mut answer = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(read) => read,
            Err(error) if answer.is_empty() => return Err(Error::Unanswered(Some(error))),
            Err(error) => return Err(Error::Io(error)),
        };
        if read == 0 {
            break;
        }
        answer.extend_from_slice(&chunk[..read]);
        if answer.len() > max {
            return Err(protocol("answer too large"));
        }
        if complete(&answer) {
            break;
        }
    }
    if answer.is_empty() {
        return Err(Error::Unanswered(None));
    }
    Ok(answer)
}

/// Reads into `buffer` until the head of an answer is there, and parses it; what came
/// after the head stays in `buffer`, from `Head::length`. A head over `max_head` bytes is
/// an error.
pub async fn read_head(stream: &mut (impl AsyncRead + Unpin), buffer: &mut Vec<u8>, max_head: usize) -> Result<Head> {
    loop {
        if let Some(head) = head(buffer)? {
            return Ok(head);
        }
        if buffer.len() > max_head {
            return Err(protocol("answer head too large"));
        }
        buffer.reserve(4096);
        match stream.read_buf(buffer).await {
            Ok(1..) => {}
            Ok(_) if buffer.is_empty() => return Err(Error::Unanswered(None)),
            Err(error) if buffer.is_empty() => return Err(Error::Unanswered(Some(error))),
            Ok(_) => return Err(protocol("closed before answering")),
            Err(error) => return Err(Error::Io(error)),
        }
    }
}

/// An answer's head: status, headers (names in lower case, values trimmed) and its length
/// in bytes, the blank line included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub length: usize,
}

impl Head {
    /// The first header of this name (in lower case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }
}

/// The head, once all of it has arrived.
pub fn head(answer: &[u8]) -> Result<Option<Head>> {
    let Some(end) = answer.windows(4).position(|window| window == b"\r\n\r\n") else { return Ok(None) };
    let text = std::str::from_utf8(&answer[..end]).map_err(|_| protocol("answer head is not text"))?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.").and_then(|rest| rest.split(' ').nth(1)))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| protocol("bad status line"))?;
    let headers = lines.filter_map(|line| line.split_once(':')).map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned())).collect();
    Ok(Some(Head { status, headers, length: end + 4 }))
}

/// Whether a whole answer has arrived by its length (or it has no body); otherwise only
/// the close ends it.
pub fn complete(answer: &[u8]) -> bool {
    let Ok(Some(head)) = head(answer) else { return false };
    if head.status == 204 || head.status == 304 {
        return true;
    }
    let length = head.header("content-length").and_then(|value| value.parse::<usize>().ok());
    length.is_some_and(|length| answer.len() >= head.length + length)
}

/// The status and body of a whole answer (by length, chunked or to the end).
pub fn parse(answer: &[u8]) -> Result<(u16, Vec<u8>)> {
    let head = head(answer)?.ok_or_else(|| protocol("no answer head"))?;
    let body = &answer[head.length..];
    if head.header("transfer-encoding").is_some_and(|value| value.to_ascii_lowercase().contains("chunked")) {
        return dechunk(body).ok_or_else(|| protocol("bad chunked body")).map(|body| (head.status, body));
    }
    match head.header("content-length").map(|value| value.parse::<usize>()) {
        Some(Ok(length)) if body.len() >= length => Ok((head.status, body[..length].to_vec())),
        Some(Ok(_)) => Err(protocol("answer cut short")),
        Some(Err(_)) => Err(protocol("bad content-length")),
        None => Ok((head.status, body.to_vec())),
    }
}

/// A chunked body put together; trailers are ignored.
pub fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|window| window == b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_answers_by_length_chunks_and_close() {
        assert_eq!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(), (200, b"{}".to_vec()));
        assert_eq!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}EXTRA").unwrap(), (200, b"{}".to_vec()));
        assert_eq!(parse(b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n1\r\nd\r\n0\r\n\r\n").unwrap(), (404, b"abcd".to_vec()));
        assert_eq!(parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n2;x=y\r\nab\r\n0\r\n\r\n").unwrap(), (200, b"ab".to_vec()));
        assert_eq!(parse(b"HTTP/1.0 200 OK\r\n\r\nto the close").unwrap(), (200, b"to the close".to_vec()));
        assert_eq!(parse(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap(), (204, Vec::new()));
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab").is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\nab").is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab").is_err());
        assert!(parse(b"garbage\r\n\r\n").is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}") && !complete(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}"));
        assert!(complete(b"HTTP/1.1 204 No Content\r\n\r\n") && complete(b"HTTP/1.1 304 Not Modified\r\n\r\n"));
        assert!(!complete(b"HTTP/1.1 200 OK\r\n\r\nuntil the close") && !complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"));
    }

    #[test]
    fn heads_parse_once_whole() {
        assert_eq!(head(b"HTTP/1.1 200 OK\r\nX-A: 1").unwrap(), None);
        let answer = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nX-Empty:\r\nno colon\r\n\r\nframes";
        let parsed = head(answer).unwrap().unwrap();
        assert_eq!(parsed.status, 101);
        assert_eq!(parsed.header("upgrade"), Some("WebSocket"));
        assert_eq!(parsed.header("x-empty"), Some(""));
        assert_eq!(parsed.headers.len(), 2);
        assert_eq!(&answer[parsed.length..], b"frames");
        assert!(head(b"HTTP/2 200\r\n\r\n").is_err());
        assert!(head(b"HTTP/1.1 abc\r\n\r\n").is_err());
        assert!(head(b"HTTP/1.1 200 \xff\r\n\r\n").is_err());
    }

    #[test]
    fn request_heads_keep_the_order_given() {
        let head = request_head("POST", "/v1/x?y=1", &[("host", "localhost"), ("content-length", "2"), ("connection", "close")]);
        assert_eq!(head, "POST /v1/x?y=1 HTTP/1.1\r\nhost: localhost\r\ncontent-length: 2\r\nconnection: close\r\n\r\n");
        assert_eq!(request_head("GET", "/", &[]), "GET / HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn answers_are_read_whole_within_the_limit() {
        let mut answer = &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"[..];
        assert_eq!(read_answer(&mut answer, 1024).await.unwrap(), b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        let mut closed = &b"HTTP/1.1 200 OK\r\n\r\nall of it"[..];
        assert_eq!(parse(&read_answer(&mut closed, 1024).await.unwrap()).unwrap().1, b"all of it");
        let mut large = &[b'x'; 2048][..];
        assert!(matches!(read_answer(&mut large, 1024).await, Err(Error::Protocol(_))));
        let mut nothing = &b""[..];
        assert!(matches!(read_answer(&mut nothing, 1024).await, Err(Error::Unanswered(None))));
    }

    #[tokio::test]
    async fn heads_are_read_with_what_follows() {
        let mut stream = &b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x02hi"[..];
        let mut buffer = Vec::new();
        let head = read_head(&mut stream, &mut buffer, 1024).await.unwrap();
        assert_eq!((head.status, &buffer[head.length..]), (101, &b"\x81\x02hi"[..]));
        let mut nothing = &b""[..];
        assert!(matches!(read_head(&mut nothing, &mut Vec::new(), 1024).await, Err(Error::Unanswered(None))));
        let mut cut = &b"HTTP/1.1 200 OK\r\n"[..];
        assert!(matches!(read_head(&mut cut, &mut Vec::new(), 1024).await, Err(Error::Protocol(_))));
        let mut endless = &[b'x'; 8192][..];
        assert!(matches!(read_head(&mut endless, &mut Vec::new(), 1024).await, Err(Error::Protocol(_))));
    }

    #[tokio::test]
    async fn bodies_are_sent_at_their_length() {
        let mut out = Vec::new();
        write_body(&mut out, &mut &b"abcdef"[..], 4).await.unwrap();
        assert_eq!(out, b"abcd");
        let error = write_body(&mut Vec::new(), &mut &b"ab"[..], 4).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_unix_socket_must_be_served_by_the_user_asked() {
        let dir = std::path::Path::new("/tmp").join(format!("khc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let _listener = tokio::net::UnixListener::bind(&path).unwrap();
        // SAFETY: getuid cannot fail.
        let me = unsafe { libc::getuid() };
        assert!(connect_unix_as(&path, me, Duration::from_secs(3)).await.is_ok());
        let error = connect_unix_as(&path, me.wrapping_add(1), Duration::from_secs(3)).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(Address::Unix(path.clone()).connect().await.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
