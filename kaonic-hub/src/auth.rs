//! Who is calling, and whether they may.
//!
//! - Passwords: Argon2id PHC strings; one hash at a time ([`App::argon`]), so the
//!   512 MB board cannot be pushed out of memory by parallel logins.
//! - Sessions: a 256-bit token in the `__Host-kaonic_session` cookie; the store
//!   keeps its SHA-256. The CSRF token is per session and travels in `AuthState`.
//! - Writes made with the cookie need `X-Kaonic-CSRF`, a same-origin `Origin`
//!   (when sent) and no cross-site `Sec-Fetch-Site`.
//! - Failed passwords slow down per client address, then lock it out for a while.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, header};
use kaonic_store::sessions;
use sha2::{Digest, Sha256};

use crate::app::App;
use crate::error::{ApiError, ApiResult};
use crate::{clock, random};

pub const SESSION_COOKIE: &str = "__Host-kaonic_session";
pub const CSRF_HEADER: &str = "x-kaonic-csrf";

/// Argon2id for the UI password: 64 MiB, 3 passes, 1 lane.
fn argon2() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(64 * 1024, 3, 1, None).expect("valid Argon2 parameters"),
    )
}

pub fn hash_password(password: &str) -> ApiResult<String> {
    let salt = SaltString::encode_b64(&random::bytes::<16>()?).map_err(|_| ApiError::internal())?;
    Ok(argon2()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ApiError::internal())?
        .to_string())
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .is_ok_and(|hash| argon2().verify_password(password.as_bytes(), &hash).is_ok())
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Constant-time equality for secrets.
pub fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |diff, (x, y)| diff | (x ^ y))
            == 0
}

/* ── throttling ── */

/// Failed passwords per client address. Five are free; then each waits twice
/// as long as the one before, up to 15 minutes.
///
/// An attempt counts as failed the moment it starts ([`Limiter::begin`]) and is
/// forgiven only when it succeeds, so requests sent all at once cannot all slip
/// past the check before the first failure is recorded. One attempt per address
/// runs at a time.
#[derive(Default)]
pub struct Limiter {
    clients: Mutex<HashMap<IpAddr, (u32, u64)>>,
    running: Mutex<std::collections::HashSet<IpAddr>>,
}

/// A password check in progress for one address; ends when dropped.
pub struct Attempt<'a> {
    limiter: &'a Limiter,
    client: IpAddr,
}

impl Attempt<'_> {
    /// The password was right: forget the address's failures.
    pub fn succeeded(self) {
        self.limiter.succeeded(self.client);
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        self.limiter.running.lock().expect("limiter lock").remove(&self.client);
    }
}

/// Another password check holds the one Argon2 permit (each takes 64 MiB and seconds).
pub fn busy() -> ApiError {
    let mut error = ApiError::new(
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "busy",
        "Another password check is running. Try again in a moment.",
    );
    error.retry_after = Some(2);
    error
}

const FREE_TRIES: u32 = 5;
const MAX_WAIT: u64 = 15 * 60;

impl Limiter {
    /// Err with the seconds left while the address must wait.
    pub fn check(&self, client: IpAddr) -> ApiResult<()> {
        let clients = self.clients.lock().expect("limiter lock");
        match clients.get(&client) {
            Some((_, until)) if *until > clock::mono() => {
                Err(ApiError::rate_limited(*until - clock::mono()))
            }
            _ => Ok(()),
        }
    }

    pub fn failed(&self, client: IpAddr) {
        let mut clients = self.clients.lock().expect("limiter lock");
        // Forget addresses that have been quiet: the map must not grow without bound.
        if clients.len() > 1024 {
            let now = clock::mono();
            clients.retain(|_, (_, until)| *until + MAX_WAIT > now);
        }
        let entry = clients.entry(client).or_insert((0, 0));
        entry.0 += 1;
        if entry.0 > FREE_TRIES {
            let wait = 1u64
                .checked_shl(entry.0 - FREE_TRIES)
                .unwrap_or(MAX_WAIT)
                .min(MAX_WAIT);
            entry.1 = clock::mono() + wait;
        }
    }

    pub fn succeeded(&self, client: IpAddr) {
        self.clients.lock().expect("limiter lock").remove(&client);
    }

    /// Starts a password check for `client`: refused while it must wait or has one
    /// running; otherwise counted as a failure until [`Attempt::succeeded`].
    /// Synchronous, so it is decided before the caller awaits anything.
    pub fn begin(&self, client: IpAddr) -> ApiResult<Attempt<'_>> {
        self.check(client)?;
        if !self.running.lock().expect("limiter lock").insert(client) {
            return Err(busy());
        }
        self.failed(client);
        Ok(Attempt { limiter: self, client })
    }
}

/* ── sessions ── */

/// A signed-in caller.
#[derive(Clone, Debug)]
pub struct Caller {
    pub role: Role,
    pub csrf_token: String,
    pub token_hash: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin,
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Viewer => "viewer",
        }
    }
}

/// The session token from the cookie header, if any.
pub fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == SESSION_COOKIE
                && value.len() == 64
                && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| value.to_owned())
        })
}

/// The caller's session, or None.
pub async fn current(app: &App, headers: &HeaderMap) -> ApiResult<Option<Caller>> {
    let Some(token) = session_token(headers) else {
        return Ok(None);
    };
    let hash = token_hash(&token);
    let lookup = hash.clone();
    let now = clock::now();
    let session = app
        .store
        .call(move |c| sessions::find_and_touch(c, &lookup, now))
        .await?;
    Ok(session.map(|session| Caller {
        role: if session.role == "admin" {
            Role::Admin
        } else {
            Role::Viewer
        },
        csrf_token: session.csrf_token,
        token_hash: hash,
    }))
}

/// Starts a session; returns the `Set-Cookie` value and the CSRF token.
pub async fn start_session(app: &App, role: Role) -> ApiResult<(HeaderValue, String)> {
    let token = random::token()?;
    let csrf = random::token()?;
    let hash = token_hash(&token);
    let csrf_stored = csrf.clone();
    let now = clock::now();
    app.store
        .call(move |c| sessions::create(c, &hash, &csrf_stored, role.as_str(), now))
        .await?;
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
        sessions::MAX_SECS
    );
    Ok((
        HeaderValue::from_str(&cookie).map_err(|_| ApiError::internal())?,
        csrf,
    ))
}

pub fn clear_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "__Host-kaonic_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
    )
}

/// Refuses requests another site could have made in the user's name.
pub fn check_origin(headers: &HeaderMap) -> ApiResult<()> {
    if headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        == Some("cross-site")
    {
        return Err(ApiError::forbidden(
            "forbidden",
            "Requests from other sites are not accepted.",
        ));
    }
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let origin_host = origin.split_once("://").map_or("", |(_, rest)| rest);
        if origin == "null" || origin_host != host {
            return Err(ApiError::forbidden(
                "forbidden",
                "Requests from other sites are not accepted.",
            ));
        }
    }
    Ok(())
}

/// An extractor for handlers that need a signed-in caller of at least the given role.
/// Writes also pass the CSRF and origin checks here.
pub struct Viewer(pub Caller);
pub struct Admin(pub Caller);

async fn authorize(parts: &Parts, app: &App, admin: bool) -> ApiResult<Caller> {
    let caller = current(app, &parts.headers)
        .await?
        .ok_or_else(|| ApiError::unauthenticated("Sign in to continue."))?;
    if parts.method != Method::GET && parts.method != Method::HEAD {
        check_origin(&parts.headers)?;
        let sent = parts
            .headers
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !same(sent, &caller.csrf_token) {
            return Err(ApiError::forbidden(
                "csrf_failed",
                "This page is out of date. Reload it and try again.",
            ));
        }
    }
    if admin && caller.role != Role::Admin {
        return Err(ApiError::forbidden("forbidden", "This needs an admin."));
    }
    Ok(caller)
}

impl<S: Send + Sync> FromRequestParts<S> for Viewer
where
    App: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(authorize(parts, &App::from_ref(state), false).await?))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Admin
where
    App: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(authorize(parts, &App::from_ref(state), true).await?))
    }
}

/// Checks the UI password again for a dangerous operation. A wrong one is a field error, never a 401.
pub async fn reconfirm(
    app: &App,
    client: IpAddr,
    password: &str,
    field: &'static str,
) -> ApiResult<()> {
    let attempt = app.limiter.begin(client)?;
    let _permit = app.argon.try_acquire().map_err(|_| busy())?;
    let hash = app
        .store
        .call(|c| kaonic_store::account::password_hash(c))
        .await?
        .ok_or_else(ApiError::internal)?;
    let password = password.to_owned();
    let good = tokio::task::spawn_blocking(move || {
        password.len() <= 256 && verify_password(&password, &hash)
    })
    .await
    .map_err(|_| ApiError::internal())?;
    if good {
        attempt.succeeded();
        Ok(())
    } else {
        Err(ApiError::field(field, "Wrong password."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_hash_and_verify() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert!(verify_password("correct-horse", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(!verify_password("correct-horse", "not a hash"));
    }

    #[test]
    fn the_limiter_lets_five_tries_through_then_waits_longer_each_time() {
        let limiter = Limiter::default();
        let client: IpAddr = "192.168.10.20".parse().unwrap();
        for _ in 0..FREE_TRIES {
            limiter.check(client).unwrap();
            limiter.failed(client);
        }
        limiter.check(client).unwrap();
        limiter.failed(client);
        let error = limiter.check(client).unwrap_err();
        assert_eq!((error.code, error.retry_after), ("rate_limited", Some(2)));
        limiter.succeeded(client);
        limiter.check(client).unwrap();
    }

    #[test]
    fn an_attempt_counts_before_it_finishes_and_one_runs_at_a_time() {
        let limiter = Limiter::default();
        let client: IpAddr = "192.168.10.9".parse().unwrap();
        // Requests sent at once: each begin is counted before any of them is answered.
        let mut started = 0;
        for _ in 0..100 {
            if let Ok(attempt) = limiter.begin(client) {
                started += 1;
                drop(attempt);
            }
        }
        assert_eq!(started, FREE_TRIES as usize + 1, "only the free tries (and the one that sets the wait) start");
        let other: IpAddr = "192.168.10.10".parse().unwrap();
        let first = limiter.begin(other).unwrap();
        assert_eq!(limiter.begin(other).err().map(|error| error.code), Some("busy"));
        first.succeeded();
        // Success forgets the failures, including the one counted at the start.
        let again = limiter.begin(other).unwrap();
        again.succeeded();
        assert!(limiter.clients.lock().unwrap().get(&other).is_none());
    }

    #[test]
    fn origin_must_be_this_device() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut map = HeaderMap::new();
            for (name, value) in pairs {
                map.insert(*name, HeaderValue::from_static(value));
            }
            map
        };
        assert!(check_origin(&headers(&[("host", "192.168.10.1")])).is_ok());
        assert!(
            check_origin(&headers(&[
                ("host", "192.168.10.1"),
                ("origin", "https://192.168.10.1")
            ]))
            .is_ok()
        );
        assert!(
            check_origin(&headers(&[
                ("host", "192.168.10.1"),
                ("origin", "https://evil.example")
            ]))
            .is_err()
        );
        assert!(check_origin(&headers(&[("host", "192.168.10.1"), ("origin", "null")])).is_err());
        assert!(
            check_origin(&headers(&[
                ("host", "192.168.10.1"),
                ("sec-fetch-site", "cross-site")
            ]))
            .is_err()
        );
    }

    #[test]
    fn only_a_well_formed_session_cookie_is_read() {
        let mut headers = HeaderMap::new();
        let token = "a".repeat(64);
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=1; {SESSION_COOKIE}={token}")).unwrap(),
        );
        assert_eq!(session_token(&headers), Some(token));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-kaonic_session=short"),
        );
        assert_eq!(session_token(&headers), None);
    }
}
