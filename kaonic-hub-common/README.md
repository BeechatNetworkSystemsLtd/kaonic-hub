# kaonic-hub-common

Small pieces shared by `kaonic-hub`, `kaonic-hub-installer` and `kaonic-hub-plugin`, so
there is one copy of each. Only tokio, `sha1` (RustCrypto, for the WebSocket accept key)
and `libc`.

```rust
use kaonic_hub_common::{base64, http, ws};

// One request to the installer, on its Unix socket, served by root.
let mut stream = http::connect_unix_as(socket, 0, Duration::from_secs(3)).await?;
let head = http::request_head("GET", "/v1/health", &[("host", "localhost"), ("connection", "close")]);
http::write_request(&mut stream, &head, &[]).await?;
let (status, body) = http::parse(&http::read_answer(&mut stream, 4 << 20).await?)?;

// A WebSocket on any connected stream.
let limits = ws::Limits { max_head: 16 << 10, max_message: 1 << 20, refusal_wait: Duration::from_secs(2) };
let (mut reader, mut writer) = ws::handshake(stream, "/events", "localhost", &[("authorization", "Bearer …")], limits).await?;
writer.send(ws::TEXT, b"hello").await?;
let incoming = reader.next().await?;
```

## What is here

- **`base64`.** `encode` (standard, padded) and `encode_url` (URL-safe, unpadded). Four
  decoders, each as strict as its callers: `decode` (padded, nothing else),
  `decode_canonical` (also refuses set unused bits, so every value has one spelling: the
  plugin API), `decode_loose` (whitespace skipped, padding optional: PEM bodies) and
  `decode_url` (plugin tokens).
- **`http`.** A client for one request per connection: request heads in the order given,
  bodies from memory or copied at their exact length from a file, answers read whole by
  `Content-Length`, in chunks or to the close, within a size limit. `read_head` reads just
  the head and keeps what came after it (for streaming or upgrades). `Address` connects to
  a Unix socket or TCP; `connect_unix_as` refuses a socket another user serves before
  anything is sent. Errors tell an unanswered request (safe to send again) from a broken
  one and from a bad answer.
- **`ws`.** RFC 6455 for clients: the handshake (checks `Sec-WebSocket-Accept`, refuses
  extensions; another status comes back with its body), masked frames, fragments put
  together, ping, pong and close. The reader is cancel-safe. No extensions.
- **`peer_uid`.** The uid at the other end of a Unix socket (`SO_PEERCRED` on Linux,
  `getpeereid` elsewhere).

Timeouts are the caller's, apart from those passed in (`connect_unix_as`, the wait for a
refused handshake's body).
