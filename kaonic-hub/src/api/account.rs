//! First-boot setup and the UI password: `/setup*` and `/auth/*`.
//!
//! The password is optional and off by default. Without one, `GET /auth/state` signs the
//! caller in as admin, and operations that ask for the password again go ahead.

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
use crate::mnemonic::{self, PhraseError};
use crate::{clock, random};
use zeroize::Zeroizing;

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
    password_set: bool,
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

const CODENAME_ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Gives a fresh device a random codename at first boot, so it is named on the mesh before
/// anyone sets it up.
pub async fn ensure_codename(app: &App) -> ApiResult<()> {
    if app.store.call(|c| settings::get(c, CODENAME)).await?.is_some() {
        return Ok(());
    }
    let mut codename = String::with_capacity(8);
    while codename.len() < 8 {
        for byte in random::bytes::<16>()? {
            // 252 is the largest multiple of 36 below 256: above it the first characters would win.
            if byte < 252 && codename.len() < 8 {
                codename.push(char::from(CODENAME_ALPHABET[usize::from(byte % 36)]));
            }
        }
    }
    log::info!("named {codename} at first boot");
    app.store.call(move |c| settings::set(c, CODENAME, &codename)).await?;
    Ok(())
}

/// A device provisioned by an admin over the air is set up as a member of its network, with
/// no password: nobody has to open its UI.
pub async fn become_member(app: &App) {
    let now = clock::now();
    let result = app
        .store
        .call(move |c| {
            if settings::get(c, ROLE)?.is_some() {
                return Ok(false);
            }
            kaonic_store::audit::record(c, now, "admin", "device.setup", "member, provisioned over the air")?;
            settings::set(c, ROLE, "member")?;
            Ok(true)
        })
        .await;
    match result {
        Ok(true) => log::info!("set up as member by the admin's provisioning"),
        Ok(false) => {}
        Err(error) => log::warn!("could not save the member role: {error}"),
    }
}

/// Setup is done once the role is saved; devices set up before the password became optional
/// have a password instead.
async fn is_set_up(app: &App) -> ApiResult<bool> {
    Ok(app.store.call(|c| Ok(settings::get(c, ROLE)?.is_some() || account::has_password(c)?)).await?)
}

async fn has_password(app: &App) -> ApiResult<bool> {
    Ok(app.store.call(|c| account::has_password(c)).await?)
}

/// An empty password means none.
fn given(password: Option<String>) -> Option<String> {
    password.filter(|password| !password.is_empty())
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

/// The seed phrase the admin keys are derived from, checked and normalised.
fn admin_seed(phrase: Option<String>) -> ApiResult<Zeroizing<String>> {
    let Some(phrase) = phrase.map(Zeroizing::new).filter(|text| !text.trim().is_empty()) else {
        return Err(ApiError::field("seed_phrase", "Enter the seed phrase."));
    };
    mnemonic::parse(&phrase).map_err(|error| {
        let message = match error {
            PhraseError::Length(_) => "Enter all 12 or 24 words.".to_owned(),
            PhraseError::Unknown(at) => {
                let at: Vec<String> = at.iter().map(usize::to_string).collect();
                format!("Not on the word list: word {}.", at.join(", "))
            }
            PhraseError::Checksum => "These words do not fit together: one is mistyped or out of order.".to_owned(),
            PhraseError::Example => "This is a published example phrase: anyone could make its keys. Use the words this device made.".to_owned(),
        };
        ApiError::field("seed_phrase", message)
    })
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
    #[serde(default)]
    seed_phrase: Option<String>,
}

/// Derives the admin identity of a checked phrase, under the login limiter.
async fn derive(app: &App, ip: std::net::IpAddr, phrase: Zeroizing<String>) -> ApiResult<NodeIdentity> {
    // Counted like a login try and never forgiven: a phrase is not a password to be right about.
    let _attempt = app.limiter.begin(ip)?;
    tokio::task::spawn_blocking(move || NodeIdentity::from_phrase(&phrase))
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
    let seed = admin_seed(body.seed_phrase)?;
    let identity = derive(&app, client(peer), seed).await?;
    Ok(no_store(axum::Json(Derived {
        identity_hash: identity.public().hash().to_hex(),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhraseRequest {
    words: usize,
}

#[derive(Serialize)]
pub struct Phrase<'a> {
    words: Vec<&'a str>,
}

/// `POST /setup/seed-phrase`: a new admin's phrase, from the kernel's random source. The
/// hub keeps nothing: the phrase comes back with setup, and the identity is derived from it.
pub async fn new_seed_phrase(State(app): State<App>, peer: Option<Extension<Peer>>, Json(body): Json<PhraseRequest>) -> ApiResult<Response> {
    before_setup(&app, peer).await?;
    if body.words != 12 && body.words != 24 {
        return Err(ApiError::field("words", "Use 12 or 24."));
    }
    let phrase = mnemonic::generate(body.words)?;
    // The words are borrowed from the phrase, which is wiped when it goes.
    Ok(no_store(axum::Json(Phrase { words: phrase.split(' ').collect() })))
}

/// `GET /setup/wordlist`: the words a seed phrase is made of, for typing one in.
pub async fn wordlist() -> Response {
    axum::Json(mnemonic::wordlist()).into_response()
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SetupInput {
    Member {
        #[serde(default)]
        password: Option<String>,
        codename: String,
    },
    Admin {
        #[serde(default)]
        password: Option<String>,
        codename: String,
        /// 12 or 24 words from `POST /setup/seed-phrase`, or typed to recover an admin.
        #[serde(default)]
        seed_phrase: Option<String>,
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
            seed_phrase,
        } => (password, codename, Some(seed_phrase)),
    };
    let password = given(password);
    let mut problems = Vec::new();
    if let Some(password) = &password
        && let Err(error) = check_new_password(password, "password")
    {
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
    let seed = match seed.map(admin_seed) {
        Some(Ok(seed)) => Some(seed),
        Some(Err(error)) => {
            problems.extend(error.fields.into_values().map(|message| ("seed_phrase", message)));
            None
        }
        None => None,
    };
    if !problems.is_empty() {
        return Err(ApiError::invalid(problems));
    }

    let ip = client(peer);
    let admin = match seed {
        Some(seed) => Some(derive(&app, ip, seed).await?),
        None => None,
    };
    let hash = match password {
        Some(password) => Some(hash_new(&app, password).await?),
        None => None,
    };

    // Secrets first, the role last: until the role is saved the device is still in setup, so
    // a crash in between is repaired by doing setup again.
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
            if let Some(hash) = &hash {
                account::set_password_hash(c, hash, now)?;
            }
            settings::set(c, CODENAME, &codename)?;
            kaonic_store::audit::record(c, now, "setup", "device.setup", role)?;
            settings::set(c, ROLE, role)
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

async fn hash_new(app: &App, password: String) -> ApiResult<String> {
    let _permit = app.argon.acquire().await.map_err(|_| ApiError::internal())?;
    tokio::task::spawn_blocking(move || auth::hash_password(&password)).await.map_err(|_| ApiError::internal())?
}

async fn signed_in(app: &App, role: Role) -> ApiResult<Response> {
    let (cookie, csrf) = auth::start_session(app, role).await?;
    let state = AuthState {
        setup_required: false,
        password_set: has_password(app).await?,
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
    let password_set = has_password(&app).await?;
    let caller = auth::current(&app, &headers).await?;
    if !setup_required && !password_set && caller.is_none() {
        return signed_in(&app, Role::Admin).await;
    }
    Ok(no_store(axum::Json(AuthState {
        setup_required,
        password_set,
        authenticated: caller.is_some(),
        role: caller.as_ref().map(|caller| caller.role.as_str()),
        csrf_token: caller.map(|caller| caller.csrf_token),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordBody {
    #[serde(default)]
    pub password: String,
}

pub async fn login(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> ApiResult<Response> {
    auth::check_origin(&headers)?;
    if is_set_up(&app).await? && !has_password(&app).await? {
        return signed_in(&app, Role::Admin).await;
    }
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
    /// Needed while a password is set.
    #[serde(default)]
    current: String,
    /// None or empty turns the password off.
    #[serde(default)]
    new: Option<String>,
}

pub async fn change_password(
    State(app): State<App>,
    peer: Option<Extension<Peer>>,
    Admin(_): Admin,
    Json(body): Json<ChangePassword>,
) -> ApiResult<impl IntoResponse> {
    auth::reconfirm(&app, client(peer), &body.current, "current").await?;
    let new = given(body.new);
    if let Some(new) = &new {
        check_new_password(new, "new")?;
    }
    let hash = match new {
        Some(new) => Some(hash_new(&app, new).await?),
        None => None,
    };
    let now = clock::now();
    app.store
        .call(move |c| {
            let detail = match &hash {
                Some(hash) => {
                    account::set_password_hash(c, hash, now)?;
                    "set"
                }
                None => {
                    account::clear_password(c)?;
                    "off"
                }
            };
            // Every session ends, this one too: the UI signs in again.
            sessions::delete_all(c)?;
            kaonic_store::audit::record(c, now, "admin", "auth.password", detail)
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
    /// This is the Kaonic Admin device: its seed phrase proves the owner.
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
    #[serde(default)]
    seed_phrase: Option<String>,
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
                    "Only the Kaonic Admin device is reset with a seed phrase. Connect a computer to this device by USB cable to reset it.",
                ));
            }
            if body.seed_phrase.as_deref().is_some_and(|text| !text.trim().is_empty() && text.len() <= 512) {
                Ok(ForgotMethod::Seed)
            } else {
                Err(ApiError::field("seed_phrase", "Enter the admin's seed phrase."))
            }
        }
        "usb" => {
            if !usb {
                return Err(ApiError::forbidden(
                    "usb_required",
                    "From the hotspot this device can only be reset with the admin's seed phrase. Connect a computer by USB cable and try again.",
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
pub async fn forgot_reset(State(app): State<App>, peer: Option<Extension<Peer>>, Json(mut body): Json<ForgotBody>) -> ApiResult<Response> {
    if !is_set_up(&app).await? {
        return Err(ApiError::conflict("This device is not set up: there is nothing to reset."));
    }
    let usb = usb_reachable(&app, peer);
    let seed = crate::provision::is_admin_device(&app).await;
    let ip = client(peer);
    match check_forgot(&body, usb, seed, &app.device.serial()) {
        Ok(ForgotMethod::Seed) => {
            // Counted like a login and never forgiven; one Argon2 at a time.
            let seed = admin_seed(body.seed_phrase.take())?;
            let derived = derive(&app, ip, seed).await?;
            let stored = app.secrets(|keys| Ok(keys.get(NODE_IDENTITY).map(|secret| secret.expose().to_vec()))).await?;
            let matches = stored
                .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
                .is_some_and(|bytes| NodeIdentity::from_bytes(&bytes).public().hash() == derived.public().hash());
            if !matches {
                return Err(ApiError::field("seed_phrase", "This is not the seed phrase of this device's admin."));
            }
            super::device::schedule_factory_reset(&app, &format!("the admin's seed phrase, from {ip}"));
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
        ForgotBody { method: method.into(), seed_phrase: seed.map(Into::into), serial: serial.map(Into::into), confirm: confirm.into() }
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
