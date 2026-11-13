//! First-boot setup and the UI password: `/setup*` and `/auth/*`.

use axum::Extension;
use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use kaonic_store::{account, sessions, settings};
use kaonic_pki::Certificate;
use kaonic_trust::Allowlist;
use serde::{Deserialize, Serialize};

use super::{Json, Peer, client, no_store};
use crate::app::App;
use crate::auth::{self, Admin, Role, Viewer};
use crate::error::{ApiError, ApiResult};
use crate::identity::NodeIdentity;
use crate::{clock, random};

/// Keystore names for identity and trust.
pub const BOOT_IDENTITY: &str = "identity/boot";
pub const NODE_IDENTITY: &str = "identity/node";
pub const TRUST_ROOT: &str = "trust/root";
pub const TRUST_OWN: &str = "trust/own";
pub const TRUST_ALLOWLIST: &str = "trust/allowlist";

/// Settings keys.
pub const CODENAME: &str = "device.codename";
pub const ROLE: &str = "device.role";

/// Refused outright: the passwords tried first by anyone guessing.
const COMMON: &[&str] = &[
    "12345678",
    "123456789",
    "1234567890",
    "password",
    "password1",
    "qwertyuiop",
    "11111111",
    "00000000",
    "abcd1234",
    "iloveyou",
    "admin123",
    "kaonic123",
    "kaonickaonic",
    "letmein1",
    "welcome1",
    "passw0rd",
    "changeme",
    "87654321",
    "qwerty123",
    "1q2w3e4r",
];

#[derive(Serialize)]
pub struct AuthState {
    setup_required: bool,
    authenticated: bool,
    role: Option<&'static str>,
    csrf_token: Option<String>,
}

/// The identity hash (hex) of the admin this node trusts: its own as the admin, the root's as a
/// provisioned member, None before provisioning.
pub async fn our_admin(app: &App) -> ApiResult<Option<String>> {
    let root = app
        .secrets(|keys| Ok(keys.get(TRUST_ROOT).map(|secret| secret.expose().to_vec())))
        .await?;
    Ok(root
        .and_then(|der| Certificate::from_der(&der).ok())
        .map(|root| root.identity_hash().to_hex()))
}

/// What this node announces about itself.
pub async fn node_info(app: &App) -> ApiResult<kaonic_mesh::announce::NodeInfo> {
    let (codename, role) = app
        .store
        .call(|c| Ok((settings::get(c, CODENAME)?, settings::get(c, ROLE)?)))
        .await?;
    let admin_id = our_admin(app).await?.and_then(|hex| {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
            .collect();
        <[u8; 16]>::try_from(bytes).ok()
    });
    Ok(kaonic_mesh::announce::NodeInfo {
        codename: codename.unwrap_or_default(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        is_admin: role.as_deref() == Some("admin"),
        admin_id,
    })
}

async fn is_set_up(app: &App) -> ApiResult<bool> {
    Ok(app.store.call(|c| account::is_set_up(c)).await?)
}

fn check_new_password(password: &str, field: &'static str) -> ApiResult<()> {
    if password.chars().count() < 8 || password.len() > 256 {
        return Err(ApiError::field(field, "Use 8 to 256 characters."));
    }
    if COMMON.contains(&password.to_lowercase().as_str()) {
        return Err(ApiError::field(
            field,
            "This password is too common. Choose another.",
        ));
    }
    Ok(())
}

fn check_seed(seed: &str) -> ApiResult<()> {
    if seed.chars().count() < 16 || seed.len() > 256 {
        return Err(ApiError::field(
            "seed_password",
            "Use at least 16 characters: the admin key is only as strong as this.",
        ));
    }
    if COMMON
        .iter()
        .any(|common| seed.to_lowercase().contains(common))
    {
        return Err(ApiError::field(
            "seed_password",
            "This contains a common password. Choose another.",
        ));
    }
    Ok(())
}

fn valid_codename(codename: &str) -> bool {
    codename.len() == 8
        && codename
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// Setup answers only on the device's own networks (hotspot and USB), never on one it joined.
///
/// Both ends must be on a setup interface's subnets, which need not be the same one: a client
/// with an address of the node's own network of the mesh (10.78.x.0/24, served by DHCP on the
/// same wire) may ask for 192.168.10.1. The local address alone is not enough:
/// Linux accepts a packet for the hotspot's address on any interface (the weak host model),
/// so a host on a network the device joined could route to 192.168.10.1 through it. Its
/// replies go out of the setup interface by the routing table, so a source address spoofed
/// into that subnet never completes the TCP handshake.
fn check_setup_reachable(app: &App, peer: Option<Extension<Peer>>) -> ApiResult<()> {
    if app.config.dev {
        return Ok(());
    }
    let Some(Extension(peer)) = peer else {
        return Ok(());
    };
    let allowed = setup_reachable(&app.config.setup_interfaces, peer.local.ip(), peer.remote.ip(), crate::system::interface_networks);
    if allowed {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "forbidden",
            "Set the device up from its own hotspot or USB.",
        ))
    }
}

fn setup_reachable(
    interfaces: &[String],
    local: std::net::IpAddr,
    remote: std::net::IpAddr,
    networks: impl Fn(&str) -> Vec<crate::system::InterfaceNetwork>,
) -> bool {
    let (std::net::IpAddr::V4(local), std::net::IpAddr::V4(remote)) = (local, remote) else {
        return false;
    };
    interfaces.iter().any(|interface| {
        let networks = networks(interface);
        networks.iter().any(|network| network.address == local) && networks.iter().any(|network| network.contains(remote))
    })
}

async fn before_setup(app: &App, peer: Option<Extension<Peer>>) -> ApiResult<()> {
    if is_set_up(app).await? {
        return Err(ApiError::conflict("This device is already set up."));
    }
    check_setup_reachable(app, peer)
}

#[derive(Serialize)]
pub struct SetupIdentity {
    identity_hash: String,
    public_identity: String,
}

pub async fn setup_identity(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
) -> ApiResult<Response> {
    before_setup(&app, peer).await?;
    let identity = app
        .secrets(|keys| {
            Ok(keys
                .get(BOOT_IDENTITY)
                .map(|secret| secret.expose().to_vec()))
        })
        .await?
        .ok_or_else(ApiError::internal)?;
    let identity =
        NodeIdentity::from_bytes(&identity.try_into().map_err(|_| ApiError::internal())?).public();
    Ok(no_store(axum::Json(SetupIdentity {
        identity_hash: identity.hash().to_hex(),
        public_identity: random::hex(&identity.to_bytes()),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedBody {
    seed_password: String,
}

/// Runs a slow derivation with the shared Argon2 permit and the login limiter.
async fn derive(app: &App, ip: std::net::IpAddr, seed: String) -> ApiResult<NodeIdentity> {
    // Each derivation costs 64 MiB and seconds of CPU: count it like a login try (and
    // never forgive it: a seed is not a password to be right about).
    let _attempt = app.limiter.begin(ip)?;
    let _permit = app.argon.try_acquire().map_err(|_| auth::busy())?;
    tokio::task::spawn_blocking(move || NodeIdentity::from_seed(&seed))
        .await
        .map_err(|_| ApiError::internal())
}

#[derive(Serialize)]
pub struct Derived {
    identity_hash: String,
}

pub async fn derive_identity(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
    Json(body): Json<SeedBody>,
) -> ApiResult<Response> {
    before_setup(&app, peer).await?;
    check_seed(&body.seed_password)?;
    let identity = derive(&app, client(peer), body.seed_password).await?;
    Ok(no_store(axum::Json(Derived {
        identity_hash: identity.public().hash().to_hex(),
    })))
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SetupInput {
    Member {
        password: String,
        codename: String,
    },
    Admin {
        password: String,
        codename: String,
        seed_password: String,
    },
}

pub async fn setup(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
    Json(input): Json<SetupInput>,
) -> ApiResult<Response> {
    before_setup(&app, peer).await?;
    let (password, codename, seed) = match input {
        SetupInput::Member { password, codename } => (password, codename, None),
        SetupInput::Admin {
            password,
            codename,
            seed_password,
        } => (password, codename, Some(seed_password)),
    };
    let mut problems = Vec::new();
    if let Err(error) = check_new_password(&password, "password") {
        problems.extend(
            error
                .fields
                .into_values()
                .map(|message| ("password", message)),
        );
    }
    if !valid_codename(&codename) {
        problems.push((
            "codename",
            "Use exactly 8 lowercase letters or digits.".to_owned(),
        ));
    }
    if let Some(seed) = &seed
        && let Err(error) = check_seed(seed)
    {
        problems.extend(
            error
                .fields
                .into_values()
                .map(|message| ("seed_password", message)),
        );
    }
    if !problems.is_empty() {
        return Err(ApiError::invalid(problems));
    }

    let ip = client(peer);
    let admin = match seed {
        Some(seed) => Some(derive(&app, ip, seed).await?),
        None => None,
    };
    let hash = {
        let _permit = app
            .argon
            .acquire()
            .await
            .map_err(|_| ApiError::internal())?;
        tokio::task::spawn_blocking(move || auth::hash_password(&password))
            .await
            .map_err(|_| ApiError::internal())??
    };

    // Secrets first, the account last: until the account exists the device is still in setup,
    // so a crash in between is repaired by doing setup again.
    let role = if admin.is_some() { "admin" } else { "member" };
    let now = clock::now() as u64;
    app.secrets(move |keys| {
        match admin {
            Some(identity) => {
                let public = identity.public();
                let root = Certificate::new_root(&public, identity.signing_key(), now)
                    .map_err(|error| kaonic_keystore::Error::Provider(error.to_string()))?;
                let allowlist = Allowlist::sign(identity.signing_key(), 1, [])
                    .map_err(|error| kaonic_keystore::Error::Provider(error.to_string()))?;
                keys.set(NODE_IDENTITY, identity.to_bytes().as_slice())?;
                keys.set(TRUST_ROOT, root.der())?;
                keys.set(TRUST_OWN, root.der())?;
                keys.set(TRUST_ALLOWLIST, allowlist.as_bytes())?;
            }
            None => {
                let boot = keys
                    .get(BOOT_IDENTITY)
                    .map(|secret| secret.expose().to_vec())
                    .ok_or(kaonic_keystore::Error::Corrupt(
                        "the boot identity is missing",
                    ))?;
                keys.set(NODE_IDENTITY, boot)?;
            }
        }
        Ok(())
    })
    .await?;
    let now = clock::now();
    app.store
        .call(move |c| {
            settings::set(c, CODENAME, &codename)?;
            settings::set(c, ROLE, role)?;
            kaonic_store::audit::record(c, now, "setup", "device.setup", role)?;
            account::set_password_hash(c, &hash, now)
        })
        .await?;
    app.limiter.succeeded(ip);
    log::info!("set up as {role}");
    // The codename and role go into the next announces. An admin's identity changed with
    // setup; the mesh takes it up when the hub next starts.
    if let Some(mesh) = &app.mesh {
        mesh.set_info(node_info(&app).await?);
        if role == "admin" {
            // The admin's identity came from its seed; the mesh still speaks as the boot identity.
            // Restart (systemd brings the hub back) so it announces as the admin.
            log::info!("restarting to take up the admin identity on the mesh");
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                std::process::exit(0);
            });
        }
    }
    signed_in(&app, Role::Admin).await
}

async fn signed_in(app: &App, role: Role) -> ApiResult<Response> {
    let (cookie, csrf) = auth::start_session(app, role).await?;
    let state = AuthState {
        setup_required: false,
        authenticated: true,
        role: Some(role.as_str()),
        csrf_token: Some(csrf),
    };
    let mut response = no_store(axum::Json(state));
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

pub async fn state(State(app): State<App>, headers: HeaderMap) -> ApiResult<Response> {
    let setup_required = !is_set_up(&app).await?;
    let caller = auth::current(&app, &headers).await?;
    Ok(no_store(axum::Json(AuthState {
        setup_required,
        authenticated: caller.is_some(),
        role: caller.as_ref().map(|caller| caller.role.as_str()),
        csrf_token: caller.map(|caller| caller.csrf_token),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordBody {
    pub password: String,
}

pub async fn login(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> ApiResult<Response> {
    auth::check_origin(&headers)?;
    let ip = client(peer);
    // Counted before anything is awaited: concurrent requests cannot all pass the check.
    let attempt = app.limiter.begin(ip)?;
    // One Argon2 hash at a time, and nobody waits in line for it: a queue of guesses
    // would hold the permit for hours.
    let permit = app.argon.try_acquire().map_err(|_| auth::busy())?;
    let hash = app
        .store
        .call(|c| account::password_hash(c))
        .await?
        .ok_or_else(|| ApiError::conflict("This device is not set up yet."))?;
    let password = body.password;
    let good = tokio::task::spawn_blocking(move || {
        password.len() <= 256 && auth::verify_password(&password, &hash)
    })
    .await
    .map_err(|_| ApiError::internal())?;
    if !good {
        return Err(ApiError::unauthenticated("Wrong password."));
    }
    attempt.succeeded();
    drop(permit);
    signed_in(&app, Role::Admin).await
}

pub async fn logout(State(app): State<App>, Viewer(caller): Viewer) -> ApiResult<Response> {
    let hash = caller.token_hash;
    app.store.call(move |c| sessions::delete(c, &hash)).await?;
    let mut response = no_store(axum::http::StatusCode::NO_CONTENT);
    response
        .headers_mut()
        .insert(header::SET_COOKIE, auth::clear_cookie());
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePassword {
    current: String,
    new: String,
}

pub async fn change_password(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
    Admin(_): Admin,
    Json(body): Json<ChangePassword>,
) -> ApiResult<impl IntoResponse> {
    auth::reconfirm(&app, client(peer), &body.current, "current").await?;
    check_new_password(&body.new, "new")?;
    let new = body.new;
    let hash = {
        let _permit = app
            .argon
            .acquire()
            .await
            .map_err(|_| ApiError::internal())?;
        tokio::task::spawn_blocking(move || auth::hash_password(&new))
            .await
            .map_err(|_| ApiError::internal())??
    };
    let now = clock::now();
    app.store
        .call(move |c| {
            account::set_password_hash(c, &hash, now)?;
            // Every session ends, this one too: the UI signs in again with the new password.
            sessions::delete_all(c)?;
            kaonic_store::audit::record(c, now, "admin", "auth.password", "")
        })
        .await?;
    let mut response = no_store(axum::http::StatusCode::NO_CONTENT);
    response
        .headers_mut()
        .insert(header::SET_COOKIE, auth::clear_cookie());
    Ok(response)
}

/* ── forgotten password: factory reset from the sign-in page ── */

/// The methods this connection may use to erase the device without its password.
#[derive(Serialize)]
pub struct ForgotMethods {
    /// The client is on the USB cable (usb0): the serial number and ERASE are enough.
    usb: bool,
    /// This is the Kaonic Admin device: its seed password proves the owner.
    seed: bool,
    /// Nothing to reset before setup.
    set_up: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum ForgotMethod {
    Seed,
    Usb,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgotBody {
    method: String,
    seed_password: Option<String>,
    serial: Option<String>,
    confirm: String,
}

/// Physical presence: both ends of the connection on the USB link.
fn usb_reachable(app: &App, peer: Option<Extension<Peer>>) -> bool {
    if app.config.dev {
        return true;
    }
    let Some(Extension(peer)) = peer else {
        return false;
    };
    if setup_reachable(&["usb0".to_owned()], peer.local.ip(), peer.remote.ip(), crate::system::interface_networks) {
        return true;
    }
    // usb0 bridged (client sharing puts it in br0 with the hotspot): the bridge's address
    // answers, so the client must have been learned on the usb0 port itself, not on Wi-Fi.
    let (Some(bridge), std::net::IpAddr::V4(remote)) = (crate::system::bridge_of("usb0"), peer.remote.ip()) else {
        return false;
    };
    setup_reachable(std::slice::from_ref(&bridge), peer.local.ip(), peer.remote.ip(), crate::system::interface_networks)
        && crate::system::bridge_port_has(&bridge, "usb0", remote)
}

/// Which method a request may use, before any slow check. Pure, so the rules are tested alone.
fn check_forgot(body: &ForgotBody, usb: bool, seed: bool, serial: &str) -> ApiResult<ForgotMethod> {
    if body.confirm != "ERASE" {
        return Err(ApiError::field("confirm", "Type ERASE to confirm."));
    }
    match body.method.as_str() {
        "seed" => {
            if !seed {
                return Err(ApiError::forbidden(
                    "seed_unavailable",
                    "Only the Kaonic Admin device is reset with a seed password. Connect a computer to this device by USB cable to reset it.",
                ));
            }
            match body.seed_password.as_deref() {
                Some(seed) if !seed.is_empty() && seed.len() <= 256 => Ok(ForgotMethod::Seed),
                _ => Err(ApiError::field("seed_password", "Enter the admin's seed password.")),
            }
        }
        "usb" => {
            if !usb {
                return Err(ApiError::forbidden(
                    "usb_required",
                    "From the hotspot this device can only be reset with the admin's seed password. Connect a computer by USB cable and try again.",
                ));
            }
            let given = body.serial.as_deref().map(str::trim).unwrap_or_default();
            // An unreadable serial never matches: "unknown" is not a secret anyone lacks.
            if serial == "unknown" || given.is_empty() || given != serial {
                return Err(ApiError::field("serial", "This is not this device's serial number (on its label and on the System page)."));
            }
            Ok(ForgotMethod::Usb)
        }
        _ => Err(ApiError::field("method", "Use seed or usb.")),
    }
}

/// `GET /auth/forgot`: what the sign-in page may offer on this connection.
pub async fn forgot_methods(State(app): State<App>, peer: Option<Extension<Peer>>) -> ApiResult<Response> {
    let set_up = is_set_up(&app).await?;
    let usb = set_up && usb_reachable(&app, peer);
    let seed = set_up && crate::provision::is_admin_device(&app).await;
    Ok(no_store(axum::Json(ForgotMethods { usb, seed, set_up })))
}

/// `POST /auth/forgot/factory-reset`: erase the device without its password.
pub async fn forgot_reset(State(app): State<App>, peer: Option<Extension<Peer>>, Json(body): Json<ForgotBody>) -> ApiResult<Response> {
    if !is_set_up(&app).await? {
        return Err(ApiError::conflict("This device is not set up: there is nothing to reset."));
    }
    let usb = usb_reachable(&app, peer);
    let seed = crate::provision::is_admin_device(&app).await;
    let ip = client(peer);
    match check_forgot(&body, usb, seed, &app.device.serial()) {
        Ok(ForgotMethod::Seed) => {
            // Counted like a login and never forgiven; one Argon2 at a time.
            let derived = derive(&app, ip, body.seed_password.clone().unwrap_or_default()).await?;
            let stored = app.secrets(|keys| Ok(keys.get(NODE_IDENTITY).map(|secret| secret.expose().to_vec()))).await?;
            let matches = stored
                .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
                .is_some_and(|bytes| NodeIdentity::from_bytes(&bytes).public().hash() == derived.public().hash());
            if !matches {
                return Err(ApiError::field("seed_password", "This is not the seed password of this device's admin."));
            }
            super::device::schedule_factory_reset(&app, &format!("the admin's seed password, from {ip}"));
        }
        Ok(ForgotMethod::Usb) => {
            let _attempt = app.limiter.begin(ip)?;
            super::device::schedule_factory_reset(&app, &format!("the serial number over USB, from {ip}"));
        }
        Err(error) => {
            // A wrong serial is a guess like a wrong password: count it.
            if body.method == "usb" && usb {
                let _attempt = app.limiter.begin(ip)?;
            }
            return Err(error);
        }
    }
    Ok(no_store(axum::http::StatusCode::ACCEPTED))
}

#[cfg(test)]
mod setup_tests {
    use super::{ForgotBody, ForgotMethod, check_forgot, setup_reachable};
    use crate::error::ApiResult;
    use crate::system::InterfaceNetwork;

    fn networks(interface: &str) -> Vec<InterfaceNetwork> {
        match interface {
            "br0" => vec![InterfaceNetwork { address: "192.168.10.1".parse().unwrap(), prefix_len: 24 }, InterfaceNetwork { address: "10.78.7.1".parse().unwrap(), prefix_len: 24 }],
            "wlan0" => vec![InterfaceNetwork { address: "10.0.0.7".parse().unwrap(), prefix_len: 24 }],
            _ => Vec::new(),
        }
    }

    #[test]
    fn setup_needs_both_ends_on_a_setup_network() {
        let setup = ["br0".to_owned(), "usb0".to_owned()];
        let hotspot = "192.168.10.1".parse().unwrap();
        // A phone on the hotspot.
        assert!(setup_reachable(&setup, hotspot, "192.168.10.23".parse().unwrap(), networks));
        // A phone with a lease of the node's own network of the mesh, at either address.
        assert!(setup_reachable(&setup, hotspot, "10.78.7.23".parse().unwrap(), networks));
        assert!(setup_reachable(&setup, "10.78.7.1".parse().unwrap(), "10.78.7.23".parse().unwrap(), networks));
        // A client of another node, through the mesh.
        assert!(!setup_reachable(&setup, "10.78.7.1".parse().unwrap(), "10.78.9.23".parse().unwrap(), networks));
        // A host on the site Wi-Fi the device joined, routing to the hotspot address through it.
        assert!(!setup_reachable(&setup, hotspot, "10.0.0.5".parse().unwrap(), networks));
        // The joined network's own address.
        assert!(!setup_reachable(&setup, "10.0.0.7".parse().unwrap(), "10.0.0.5".parse().unwrap(), networks));
        assert!(!setup_reachable(&setup, "::1".parse().unwrap(), "::1".parse().unwrap(), networks));
    }

    fn forgot(method: &str, seed: Option<&str>, serial: Option<&str>, confirm: &str) -> ForgotBody {
        ForgotBody { method: method.into(), seed_password: seed.map(Into::into), serial: serial.map(Into::into), confirm: confirm.into() }
    }

    #[test]
    fn forgotten_password_reset_needs_usb_and_the_serial_or_the_admin_seed() {
        let code = |result: ApiResult<ForgotMethod>| result.err().map(|error| error.code.to_string());
        // From the hotspot (no USB) a member can't be erased at all.
        assert_eq!(code(check_forgot(&forgot("usb", None, Some("K1S-1"), "ERASE"), false, false, "K1S-1")).as_deref(), Some("usb_required"));
        assert_eq!(code(check_forgot(&forgot("seed", Some("x"), None, "ERASE"), false, false, "K1S-1")).as_deref(), Some("seed_unavailable"));
        // Over USB: the serial must match exactly; "unknown" never does.
        assert_eq!(check_forgot(&forgot("usb", None, Some(" K1S-1 "), "ERASE"), true, false, "K1S-1").ok(), Some(ForgotMethod::Usb));
        assert!(check_forgot(&forgot("usb", None, Some("K1S-2"), "ERASE"), true, false, "K1S-1").is_err());
        assert!(check_forgot(&forgot("usb", None, Some("unknown"), "ERASE"), true, false, "unknown").is_err());
        assert!(check_forgot(&forgot("usb", None, None, "ERASE"), true, false, "K1S-1").is_err());
        // The word ERASE, exactly.
        assert!(check_forgot(&forgot("usb", None, Some("K1S-1"), "erase"), true, false, "K1S-1").is_err());
        // The admin's seed works from anywhere the device answers (it is checked by derivation afterwards).
        assert_eq!(check_forgot(&forgot("seed", Some("a long admin seed"), None, "ERASE"), false, true, "K1S-1").ok(), Some(ForgotMethod::Seed));
        assert!(check_forgot(&forgot("seed", Some(""), None, "ERASE"), false, true, "K1S-1").is_err());
        assert!(check_forgot(&forgot("other", None, None, "ERASE"), true, true, "K1S-1").is_err());
    }
}
