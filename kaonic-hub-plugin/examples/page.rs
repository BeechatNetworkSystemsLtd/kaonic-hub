//! A tiny status page: who this plugin is and its use of the mesh, at `/apps/<id>/` in the
//! hub's UI. Needs `page = true` in `[kaonic-plugin]` of its manifest.
//!
//! On a device the installer runs it; for development, with a page socket of your own:
//!
//! ```sh
//! KAONIC_HUB_API=unix:/run/kaonic-hub/plugins/status.sock KAONIC_PLUGIN_TOKEN=/path/to/token \
//!     KAONIC_PLUGIN_PAGE_SOCKET=/tmp/status.sock cargo run -p kaonic-hub-plugin --example page
//! curl --unix-socket /tmp/status.sock http://localhost/
//! ```

use kaonic_hub_plugin::page::{self, Request, Response};
use kaonic_hub_plugin::{Error, Hub};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let hub = Hub::connect().await?;
    println!("page: serving on {}", std::env::var(kaonic_hub_plugin::ENV_PAGE_SOCKET).unwrap_or_default());
    page::serve(move |request| answer(hub.clone(), request)).await
}

async fn answer(hub: Hub, request: Request) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET" | "HEAD", "/") => match (hub.me().await, hub.stats().await) {
            (Ok(me), Ok(stats)) => Response::html(format!(
                "<!doctype html><meta charset=utf-8><title>{id}</title>\
                 <h1>{id} {version}</h1>\
                 <p>Node {node}, hub {hub_version}. Messages at most {max} bytes.</p>\
                 <p>Sent {sent}, received {received}, dropped {dropped}; {airtime} ms on air.</p>\
                 <p><a href=\"stats.json\">as JSON</a></p>",
                id = escape(&me.plugin),
                version = escape(&me.version),
                node = escape(me.node.as_deref().unwrap_or("-")),
                hub_version = escape(&me.hub_version),
                max = me.limits.max_message,
                sent = stats.sent,
                received = stats.received,
                dropped = stats.dropped,
                airtime = stats.airtime_ms,
            ))
            .header("cache-control", "no-store"),
            (Err(error), _) | (_, Err(error)) => Response::text(503, format!("the hub: {error}")),
        },
        // A relative link from the page: stays under its prefix.
        ("GET" | "HEAD", "/stats.json") => match hub.stats().await {
            Ok(stats) => Response::new(
                200,
                "application/json",
                format!("{{\"sent\":{},\"received\":{},\"dropped\":{},\"airtime_ms\":{}}}", stats.sent, stats.received, stats.dropped, stats.airtime_ms),
            ),
            Err(error) => Response::text(503, format!("the hub: {error}")),
        },
        (_, "/" | "/stats.json") => Response::text(405, "GET only"),
        _ => Response::text(404, "no such page"),
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
