# kaonic-hub-plugin

The SDK for Kaonic plugins: a small async client (tokio) for the hub's plugin API
(`docs/api/plugin-api.yaml`). A plugin asks who it is, sees the trusted nodes, sends
messages to its own copies on other nodes, hears events, and keeps a key/value store. The
hub owns the radio and the links; there is no radio or Reticulum code here.

```rust
use kaonic_hub_plugin::{Event, Hub, Target};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), kaonic_hub_plugin::Error> {
    let hub = Hub::connect().await?;                 // from what the installer sets
    let me = hub.me().await?;
    println!("{} {} on {:?}", me.plugin, me.version, me.node);
    for node in hub.nodes().await? {
        if node.runs_plugin {
            hub.send(&node.id, 1, b"hello").await?;  // to that node's copy of us
        }
    }
    hub.store().set("favourites", &["b4o0cvts"]).await?;

    let mut events = hub.events().await?;            // a WebSocket
    while let Some(event) = events.next().await {
        match event {
            Event::Received { from, channel, data, .. } => {
                events.send(Target::Node(from), channel, &data).await?;
            }
            Event::Congestion { level } => println!("channel {level} busy: send less"),
            _ => {}
        }
    }
    Ok(())                                           // closed: reconnecting is up to you
}
```

`examples/echo.rs` is a whole plugin; `examples/page.rs` is one with a web page.

## Running

The installer runs each plugin with:

| Variable | |
|---|---|
| `KAONIC_HUB_API` | `unix:/run/kaonic-hub/plugins/<id>.sock`, the plugin's own API socket |
| `KAONIC_PLUGIN_TOKEN` | the file with its token, `kpt1.…` |
| `KAONIC_PLUGIN_ID`, `KAONIC_PLUGIN_DIR` | its id and directory (only `data/` in it is writable) |
| `KAONIC_PLUGIN_PAGE_SOCKET` | with `page = true`: `<plugins>/<id>/run/page.sock`, where it serves its page |

`Hub::connect` reads them. A reinstall or rollback writes a new token: the SDK reads the
file again after a 401.

**Transport.** Plain HTTP/1.1 on the Unix socket, one request per connection, with
`Authorization: Bearer <token>`; the event socket is a WebSocket on the same socket. The
hub answers only the plugin's own user there, and only its token. `Hub::connect_to(api,
token)` takes the same `unix:<path>`, or `http://host:port` for a hub serving the API on
TCP during development.

**Starting before the hub.** The hub makes the socket when it sees the plugin installed
(at once after an install through the hub, otherwise within 30 s), so a plugin may start
first. `Hub::connect` waits for it, for at most 60 s (`CONNECT_WAIT`), trying again with a
pause growing from 0.1 s to 2 s on a missing socket or a refused connection; then it is
`Error::Io`. `hub.wait(duration)` does the same later, for after a hub restart.

**Limits.** The hub's, per plugin:

- At most 16 connections at once; more are closed unanswered. The SDK makes at most 8
  requests at once (`MAX_REQUESTS`; the rest wait their turn), and sends a request again
  if the hub closed it unanswered.
- Request headers within 20 s, a whole request within 30 s.
- At most 4 event sockets: a fifth is `Error::TooManySockets` (`429 too_many_sockets`).
- Message sizes, the queue and the store's limits are in `me.limits` (a message is one
  link packet, 777 B today): read them, do not hard-code them.

**Messages.**

- Messages, broadcasts and the event socket need `permissions = "mesh"`; without it they
  answer `Error::Forbidden` with code `missing_permission`.
- They are best effort and small (`me.limits.max_message`). The answer is a `Queued` id;
  `Sent` or `Dropped` follow as events. A full queue is `Error::QueueFull`; another plugin
  here with the same mesh name is `Error::AmbiguousName` (`409 ambiguous_name`: the mesh is
  off for both until one is removed).
- While the event socket is open the plugin counts as running on the mesh. It ends when
  the hub restarts or closes it; open it again after a pause.

## A web page

With `page = true` in `[kaonic-plugin]`, the hub shows the plugin's page at
`/apps/<id>/` to signed-in users, proxied to `KAONIC_PLUGIN_PAGE_SOCKET`. The optional
helper serves it:

```rust
use kaonic_hub_plugin::page::{self, Response};

page::serve(|request| async move {
    match request.path.as_str() {
        "/" => Response::html("<a href=\"stats\">stats</a>"),   // relative: keeps the prefix
        "/stats" => Response::new(200, "application/json", "{}"),
        _ => Response::text(404, "no such page"),
    }
})
.await?;
```

`page::serve` removes a socket left by an earlier run, binds and serves each request on
its own task (at most 32 at once). The handler gets the method, the path and query, the
headers and the body, and returns a status, headers (`Content-Type` first) and a body; the
helper adds `Content-Length` and closes. `page::bind` and `page::serve_on` split those
steps. What the hub does, and so what a page must:

- **Relative URLs.** The browser sees the page under `/apps/<id>/~<ticket>/`; requests
  arrive without that prefix (`/stats`). It is in `X-Forwarded-Prefix`
  (`request.prefix()`), for absolute URLs.
- **The path arrives still percent-encoded.** Split it at `/` first, then `page::decode`
  each piece (an encoded `%2F` or `..` is data).
- **One request per connection**, HTTP/1.0 with `Connection: close` and a
  `Content-Length`, bodies at most 1 MiB. Answers have a length, never chunks; the head
  within 25 s.
- **Only some answer headers reach the browser**: `content-type`, `-length`, `-encoding`,
  `-language`, `-disposition`, `cache-control`, `etag`, `last-modified`, `expires`,
  `vary`, `accept-ranges`, `content-range`, `content-security-policy`. No cookies. A
  `Location` stays only if relative without `..`, or under the page's prefix:
  `Response::redirect("stats")` makes one that does.
- **WebSockets** come as HTTP/1.1 upgrades; the helper answers them 501. A page that needs
  one serves its socket itself.

## Packaging

A plugin is a tar of:

```text
kaonic-plugin.toml   the manifest
SHA256SUMS           sha256sum of every other file
bin/<id>             the program
files/...            anything else, such as files/icon.png
```

```toml
[kaonic-plugin]
format = 2
id = "echo"
name = "Echo"
version = "0.1.0"
developer = "You"
icon = "files/icon.png"

page = true                # only for a plugin with a page

[service]
permissions = "mesh"
```

```sh
cargo build --release --example echo --target armv7-unknown-linux-gnueabihf
mkdir -p pkg/bin pkg/files && cp target/armv7-unknown-linux-gnueabihf/release/examples/echo pkg/bin/echo
cp kaonic-plugin.toml pkg/ && cp icon.png pkg/files/
cd pkg && sha256sum kaonic-plugin.toml bin/echo files/icon.png > SHA256SUMS && tar cf ../echo.tar *
```

See `kaonic-hub-installer/src/manifest.rs` for every manifest key, and `docs/plugins.md`
for the design.

## Tests

```sh
cargo test -p kaonic-hub-plugin
```

The tests run the hub's real plugin API on each plugin's own Unix socket, with an
in-process installer on its socket issuing the tokens, and a page served through the hub's
proxy.
