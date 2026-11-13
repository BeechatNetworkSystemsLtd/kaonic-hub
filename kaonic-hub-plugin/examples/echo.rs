//! An echo plugin: sends every message on channel 1 back to the node it came from, and
//! counts them in its store. Needs `permissions = "mesh"` in its manifest.
//!
//! On a device the installer runs it; for development, against a hub:
//!
//! ```sh
//! KAONIC_HUB_API=unix:/run/kaonic-hub/plugins/echo.sock KAONIC_PLUGIN_TOKEN=/path/to/token cargo run -p kaonic-hub-plugin --example echo
//! ```

use std::time::Duration;

use kaonic_hub_plugin::{Error, Event, Hub, Target};

const CHANNEL: u8 = 1;
const COUNTER: &str = "echoed";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let hub = Hub::connect().await?;
    let me = hub.me().await?;
    println!("echo: {} {} on node {} ({}), hub {}", me.plugin, me.version, me.node.as_deref().unwrap_or("-"), me.codename, me.hub_version);
    if !me.has("mesh") {
        eprintln!("echo: no mesh permission; add permissions = \"mesh\" to [service] in kaonic-plugin.toml");
    }
    let mut echoed: u64 = hub.store().get(COUNTER).await?.unwrap_or(0);
    println!("echo: {echoed} messages echoed so far");

    // The socket ends when the hub restarts or the link to it breaks: open it again after
    // a pause. A refused token means a new one was issued; the installer restarts us.
    loop {
        let mut events = match hub.events().await {
            Ok(events) => events,
            Err(error @ (Error::Unauthorized | Error::Forbidden { .. })) => return Err(error),
            Err(error) => {
                eprintln!("echo: {error}; trying again in 5 s");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        println!("echo: listening");
        while let Some(event) = events.next().await {
            match event {
                Event::Received { from, channel: CHANNEL, data, broadcast, .. } => {
                    println!("echo: {} bytes from {from}{}", data.len(), if broadcast { " (broadcast)" } else { "" });
                    if events.send(Target::Node(from), CHANNEL, &data).await.is_err() {
                        break;
                    }
                    echoed += 1;
                    if let Err(error) = hub.store().set(COUNTER, &echoed).await {
                        eprintln!("echo: keeping the counter: {error}");
                    }
                }
                Event::Refused { code, message, .. } => eprintln!("echo: not sent ({code}): {message}"),
                Event::Dropped { id, reason, node } => eprintln!("echo: message {id} to {node:?} dropped: {reason:?}"),
                Event::Congestion { level } => println!("echo: channel {:.0} % busy{}", level * 100.0, if level > 0.7 { ", slowing down" } else { "" }),
                Event::PluginUp { node } => println!("echo: {node} runs echo"),
                Event::PluginDown { node } => println!("echo: {node} stopped echo"),
                _ => {}
            }
        }
        eprintln!("echo: event socket closed; opening it again in 5 s");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
