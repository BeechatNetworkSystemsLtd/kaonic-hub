//! The installer's HTTP API, for the hub only.
//!
//! HTTP/1.1 on a Unix socket ([`crate::Paths::socket`], 0600 in a 0700 directory). Every
//! connection is checked before anything is read: the peer's uid (`SO_PEERCRED`) must be in
//! the allowed set, root by default. No secret, no TCP: a plugin cannot reach the API, and
//! cannot pose as the installer to the hub (the hub checks this side's uid the same way).
//!
//! ```text
//! GET    /v1/plugins                      every plugin
//! GET    /v1/plugins/{id}
//! POST   /v1/plugins[?allow_downgrade=1]  install or upgrade; the body is the package
//! POST   /v1/packages/check               check a package without installing it
//! POST   /v1/plugins/{id}/start|stop|restart|rollback
//! DELETE /v1/plugins/{id}[?keep_data=1]
//! GET    /v1/policy, PUT /v1/policy       {"require_signed": bool}; GET adds "release_key": bool
//! GET    /v1/token-key                    {"public": hex}: checks plugin tokens
//! GET    /v1/health                       {"version"}
//! GET    /v1/history[?id=&limit=]         what happened, newest first
//! GET    /v1/core                         the hub and the installer: updated copies
//! POST   /v1/core/kaonic-hub[?allow_downgrade=1]  update the hub (202, a job)
//! GET    /v1/core/kaonic-hub/job          the last hub update
//! POST   /v1/core/kaonic-hub/ready        {"version"}: the hub says it is up
//! ```
//! Package bodies (install, check, hub update) are streamed into a file in the installer's
//! staging, at most [`MAX_PACKAGE`] bytes (413 beyond), and unpacked from there. An `{id}`
//! must be a plugin or core id (422 otherwise). An `X-Kaonic-Actor` header (the admin's
//! name, from the hub) is written into the history. Errors are `{"code", "message"}` with a
//! matching status.

use std::future::Future;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::{Body, HttpBody};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};

use crate::installer::{Action, Installer};
use crate::records::{Policy, Record};
use crate::{Error, Kind};

/// The largest package accepted.
pub const MAX_PACKAGE: usize = 64 << 20;
/// The largest JSON body accepted.
const MAX_JSON: usize = 64 << 10;

/// Binds the API socket at `path`: its directory made 0700, a stale socket replaced, the
/// socket 0600. Call it before [`Installer::restore`], then [`serve`].
pub fn bind(path: &FsPath) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} is not a socket", path.display()))),
        Err(_) => {}
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves the API on `listener` to peers whose uid is in `allowed` (`[0]` on a device),
/// until `shutdown` completes. Other peers are dropped before anything is read.
pub async fn serve(listener: UnixListener, allowed: Vec<u32>, installer: Arc<Installer>, shutdown: impl Future<Output = ()> + Send + 'static) -> std::io::Result<()> {
    axum::serve(Guarded { listener, allowed }, router(installer)).with_graceful_shutdown(shutdown).await
}

/// A Unix listener that hands out only connections from allowed uids.
struct Guarded {
    listener: UnixListener,
    allowed: Vec<u32>,
}

impl axum::serve::Listener for Guarded {
    type Io = UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    log::warn!("installer: accept: {error}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            match crate::peer_uid(&stream) {
                Ok(uid) if self.allowed.contains(&uid) => return (stream, address),
                Ok(uid) => log::warn!("installer: refused a connection from uid {uid}"),
                Err(error) => log::warn!("installer: refused a connection: {error}"),
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// The routes. Serve them with [`serve`] only: the peer check is in its listener.
pub fn router(installer: Arc<Installer>) -> Router {
    Router::new()
        .route("/v1/plugins", get(list).post(install))
        .route("/v1/packages/check", post(check))
        .route("/v1/plugins/{id}", get(one).delete(remove))
        .route("/v1/plugins/{id}/{action}", post(act))
        .route("/v1/policy", get(policy).put(set_policy))
        .route("/v1/token-key", get(token_key))
        .route("/v1/health", get(health))
        .route("/v1/history", get(history))
        .route("/v1/core", get(core_status))
        .route("/v1/core/kaonic-hub", post(update_hub))
        .route("/v1/core/kaonic-hub/job", get(hub_job))
        .route("/v1/core/kaonic-hub/ready", post(hub_ready))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_JSON))
        .with_state(installer)
}

type Shared = Arc<Installer>;

/// A package received into staging; the file goes when this is dropped.
struct Upload(PathBuf);

impl Drop for Upload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl Upload {
    fn open(&self) -> Result<std::fs::File, Error> {
        std::fs::File::open(&self.0).map_err(Error::io("reading the upload"))
    }
}

fn too_large() -> Box<Response> {
    let message = format!("the package is larger than {} MiB", MAX_PACKAGE >> 20);
    Box::new((StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({ "code": "too_large", "message": message }))).into_response())
}

/// Streams a request body into a new file in the installer's staging, at most [`MAX_PACKAGE`] bytes.
async fn receive(installer: &Installer, headers: &HeaderMap, mut body: Body) -> Result<Upload, Box<Response>> {
    let length = headers.get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()?.parse::<u64>().ok());
    if length.is_some_and(|length| length > MAX_PACKAGE as u64) {
        return Err(too_large());
    }
    let fail = |error: Error| Box::new(Failure(error).into_response());
    let dir = installer.paths().state.join("staging");
    tokio::fs::create_dir_all(&dir).await.map_err(|error| fail(Error::io("making the staging directory")(error)))?;
    let name = crate::hex(&crate::random::<8>().map_err(|error| fail(Error::io("random")(error)))?);
    let upload = Upload(dir.join(format!("upload-{name}")));
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&upload.0)
        .await
        .map_err(|error| fail(Error::io("making the upload file")(error)))?;
    let mut total = 0usize;
    while let Some(frame) = std::future::poll_fn(|context| std::pin::Pin::new(&mut body).poll_frame(context)).await {
        let frame = frame.map_err(|error| fail(Error::invalid(format!("reading the package: {error}"))))?;
        let Ok(data) = frame.into_data() else { continue };
        total += data.len();
        if total > MAX_PACKAGE {
            return Err(too_large());
        }
        file.write_all(&data).await.map_err(|error| fail(Error::io("writing the upload")(error)))?;
    }
    file.flush().await.map_err(|error| fail(Error::io("writing the upload")(error)))?;
    Ok(upload)
}

/// An `{id}` from the path: a plugin or core id, before it names anything.
fn checked(id: &str) -> Result<(), Failure> {
    crate::names::path_id(id).map(|_| ()).map_err(Failure)
}

/// A plugin as the hub sees it.
#[derive(Serialize)]
struct View {
    #[serde(flatten)]
    record: Record,
    running: bool,
}

fn view(installer: &Installer, record: Record) -> View {
    let running = installer.is_running(&record.manifest.id);
    View { record, running }
}

struct Failure(Error);

impl Failure {
    fn into_response_with(self, status: StatusCode) -> Response {
        let code = match self.0.kind {
            Kind::Invalid => "invalid",
            Kind::NotFound => "not_found",
            Kind::Conflict => "conflict",
            Kind::Downgrade => "downgrade",
            Kind::Forbidden => "forbidden",
            Kind::Failed => "failed",
        };
        (status, Json(serde_json::json!({ "code": code, "message": self.0.message }))).into_response()
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status = match self.0.kind {
            Kind::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
            Kind::NotFound => StatusCode::NOT_FOUND,
            Kind::Conflict | Kind::Downgrade => StatusCode::CONFLICT,
            Kind::Forbidden => StatusCode::FORBIDDEN,
            Kind::Failed => StatusCode::INTERNAL_SERVER_ERROR,
        };
        self.into_response_with(status)
    }
}

type Answer<T> = Result<Json<T>, Failure>;

/// Runs installer work off the async runtime.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> Result<T, Error> + Send + 'static) -> Result<T, Failure> {
    tokio::task::spawn_blocking(work).await.map_err(|_| Failure(Error::failed("the installer task stopped")))?.map_err(Failure)
}

async fn list(State(shared): State<Shared>) -> Answer<Vec<View>> {
    let installer = shared.clone();
    blocking(move || Ok(installer.list().into_iter().map(|record| view(&installer, record)).collect())).await.map(Json)
}

async fn one(State(shared): State<Shared>, Path(id): Path<String>) -> Answer<View> {
    checked(&id)?;
    let installer = shared.clone();
    blocking(move || installer.get(&id).map(|record| view(&installer, record))).await.map(Json)
}

#[derive(Deserialize)]
struct InstallQuery {
    #[serde(default)]
    allow_downgrade: Option<String>,
}

fn yes(value: &Option<String>) -> bool {
    matches!(value.as_deref(), Some("1" | "true" | "yes"))
}

/// Who asked, as the hub says: printable, at most 64 characters.
fn actor(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("x-kaonic-actor")?.to_str().ok()?.trim();
    (!value.is_empty()).then(|| value.chars().filter(|c| !c.is_control()).take(64).collect())
}

async fn install(State(shared): State<Shared>, Query(query): Query<InstallQuery>, headers: HeaderMap, body: Body) -> Response {
    let upload = match receive(&shared, &headers, body).await {
        Ok(upload) => upload,
        Err(response) => return *response,
    };
    let installer = shared.clone();
    let allow_downgrade = yes(&query.allow_downgrade);
    let actor = actor(&headers);
    blocking(move || installer.install_as(&mut upload.open()?, allow_downgrade, actor.as_deref()).map(|record| view(&installer, record)))
        .await
        .map(Json)
        .into_response()
}

#[derive(Serialize)]
struct Checked {
    manifest: crate::manifest::Manifest,
    signed: bool,
}

async fn check(State(shared): State<Shared>, headers: HeaderMap, body: Body) -> Response {
    let upload = match receive(&shared, &headers, body).await {
        Ok(upload) => upload,
        Err(response) => return *response,
    };
    let installer = shared.clone();
    blocking(move || installer.check(&mut upload.open()?).map(|package| Checked { manifest: package.manifest, signed: package.signed }))
        .await
        .map(Json)
        .into_response()
}

async fn act(State(shared): State<Shared>, Path((id, action)): Path<(String, String)>, headers: HeaderMap) -> Answer<View> {
    checked(&id)?;
    let installer = shared.clone();
    let actor = actor(&headers);
    blocking(move || {
        let actor = actor.as_deref();
        let record = match action.as_str() {
            "start" => installer.control_as(&id, Action::Start, actor)?,
            "stop" => installer.control_as(&id, Action::Stop, actor)?,
            "restart" => installer.control_as(&id, Action::Restart, actor)?,
            "rollback" => installer.rollback_as(&id, actor)?,
            _ => return Err(Error::not_found(format!("no action {action}"))),
        };
        Ok(view(&installer, record))
    })
    .await
    .map(Json)
}

#[derive(Deserialize)]
struct RemoveQuery {
    #[serde(default)]
    keep_data: Option<String>,
}

async fn remove(State(shared): State<Shared>, Path(id): Path<String>, Query(query): Query<RemoveQuery>, headers: HeaderMap) -> Result<StatusCode, Failure> {
    checked(&id)?;
    let installer = shared.clone();
    let keep_data = yes(&query.keep_data);
    let actor = actor(&headers);
    blocking(move || installer.remove_as(&id, keep_data, actor.as_deref())).await.map(|_| StatusCode::NO_CONTENT)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }))
}

#[derive(Deserialize)]
struct HistoryQuery {
    id: Option<String>,
    limit: Option<usize>,
}

async fn history(State(shared): State<Shared>, Query(query): Query<HistoryQuery>) -> Answer<Vec<crate::history::Event>> {
    let installer = shared.clone();
    let limit = query.limit.unwrap_or(100).min(crate::history::KEEP);
    blocking(move || Ok(installer.history(query.id.as_deref(), limit))).await.map(Json)
}

async fn core_status(State(shared): State<Shared>) -> Json<Vec<crate::core::CoreStatus>> {
    Json(crate::names::CORE.iter().map(|id| shared.core().status(id)).collect())
}

async fn update_hub(State(shared): State<Shared>, Query(query): Query<InstallQuery>, headers: HeaderMap, body: Body) -> Response {
    let upload = match receive(&shared, &headers, body).await {
        Ok(upload) => upload,
        Err(response) => return *response,
    };
    let installer = shared.clone();
    let allow_downgrade = yes(&query.allow_downgrade);
    let actor = actor(&headers);
    blocking(move || installer.update_hub(&mut upload.open()?, allow_downgrade, actor.as_deref()))
        .await
        .map(|job| (StatusCode::ACCEPTED, Json(job)))
        .into_response()
}

async fn hub_job(State(shared): State<Shared>) -> Answer<crate::installer::HubJob> {
    shared.hub_job().map(Json).ok_or_else(|| Failure(Error::not_found("no hub update yet")))
}

#[derive(Deserialize)]
struct Ready {
    version: String,
}

async fn hub_ready(State(shared): State<Shared>, Json(ready): Json<Ready>) -> StatusCode {
    shared.hub_ready(&ready.version);
    StatusCode::NO_CONTENT
}

async fn token_key(State(shared): State<Shared>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "public": crate::hex(&shared.token_public_key()) }))
}

async fn policy(State(shared): State<Shared>) -> Json<serde_json::Value> {
    let policy = shared.policy();
    Json(serde_json::json!({ "require_signed": policy.require_signed, "release_key": shared.has_release_key() }))
}

async fn set_policy(State(shared): State<Shared>, Json(policy): Json<Policy>) -> Answer<Policy> {
    let installer = shared.clone();
    blocking(move || installer.set_policy(&policy).map(|_| policy)).await.map(Json)
}
