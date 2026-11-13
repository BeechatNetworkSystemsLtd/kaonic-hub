//! The hub's side of the secure links (`kaonic_mesh::links`) and the VPN on top of them:
//! credentials and trust from the keystore, allowlists peers hand over stored back, and
//! the links told whenever provisioning or revocation changes what this node trusts.

use std::sync::Arc;

use kaonic_mesh::links::{Auth, Links};
use kaonic_handshake::Credentials;
use kaonic_trust::Allowlist;

use crate::api::TRUST_ALLOWLIST;
use crate::app::App;
use crate::provision;

/// This node's credentials and trust, if it is provisioned (or the admin).
pub async fn auth(app: &App) -> Option<Auth> {
    let trust = provision::trust(app).await?;
    let identity = provision::own_identity(app).await?;
    let credentials = Credentials { identity: identity.public(), key: identity.signing_key().clone(), cert: trust.own().clone() };
    Some(Auth { credentials, trust })
}

/// Starts the link manager on the mesh. Unprovisioned, it waits for `refresh`.
pub async fn start_links(app: &App) -> Option<Arc<Links>> {
    let mesh = app.mesh.clone()?;
    let store_app = app.clone();
    let store: kaonic_mesh::links::AllowlistSink = Box::new(move |bytes: Vec<u8>| {
        let app = store_app.clone();
        tokio::spawn(async move {
            // Lists can arrive close together and these tasks run in any order: keep the newest.
            let stored = app.secrets(move |keys| {
                let seq = Allowlist::seq_of(&bytes);
                let held = keys.get(TRUST_ALLOWLIST).and_then(|held| Allowlist::seq_of(held.expose()));
                if held.is_some_and(|held| Some(held) >= seq) {
                    return Ok(false);
                }
                keys.set(TRUST_ALLOWLIST, bytes).map(|()| true)
            });
            if let Ok(true) = stored.await {
                provision::announce_change(&app).await;
            }
        });
    });
    let links = Links::start(mesh, auth(app).await, store).await;
    let _ = app.links.set(links.clone());
    Some(links)
}

/// After this node's trust changed: the links take the new credentials, and links to peers
/// no longer trusted close.
pub async fn refresh(app: &App) {
    if let Some(links) = app.links.get() {
        links.set_auth(auth(app).await).await;
    }
}

/// Opens the push-to-talk GROUP channel (once this node holds the group key) and listens for
/// keys on the links. Call after `start_links`.
pub async fn start_group(app: &App) {
    crate::group_key::start(app).await;
}

/// Starts the VPN on the links, if it is turned on.
pub async fn start_vpn(app: &App, config: kaonic_vpn::VpnConfig) {
    let (Some(links), Some(mesh)) = (app.links.get().cloned(), app.mesh.clone()) else { return };
    match kaonic_vpn::Vpn::start(links, mesh.identity_hash(), config).await {
        Ok(vpn) => {
            let _ = app.vpn.set(vpn);
        }
        Err(error) => {
            log::error!("vpn: cannot start: {error}");
            let _ = app.vpn_error.set(error.to_string());
        }
    }
}
