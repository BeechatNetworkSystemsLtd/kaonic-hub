//! `/system/boot*`: the A/B boot slots, the boot switch and kernel install
//! (`crate::boot`). Admin only for anything that changes the board;
//! switching slots and installing a kernel also need the password again.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};

use super::{Json, Peer, client, jobs, no_store};
use crate::app::App;
use crate::auth::{self, Admin, Viewer};
use crate::boot::{self, BootState, ImageInfo, Mode, Prepare, Slot};
use crate::clock;
use crate::error::{ApiError, ApiResult};

/// Reading the slots mounts partitions: done at most this often unless asked.
const STATUS_FRESH: Duration = Duration::from_secs(60);
/// A staged file (a kernel is up to 24 MiB of RAM) is dropped after this long unused.
const STAGED_TTL: Duration = Duration::from_secs(30 * 60);
/// How often staged files are checked for expiry while any are held.
const STAGED_SWEEP: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct Staged {
    data: Bytes,
    info: ImageInfo,
    uploaded_ts: i64,
    /// Last uploaded or installed from.
    used: Instant,
}

#[derive(Default)]
struct Store {
    status: Option<(Instant, BootState)>,
    kernel: Option<Staged>,
    dtb: Option<Staged>,
    installing: bool,
    /// Whether the expiry task is running.
    sweeping: bool,
}

impl Store {
    /// Drops staged files unused for [`STAGED_TTL`]; true while any remain.
    fn expire(&mut self, now: Instant) -> bool {
        for staged in [&mut self.kernel, &mut self.dtb] {
            if staged.as_ref().is_some_and(|file| now.saturating_duration_since(file.used) >= STAGED_TTL) {
                log::info!("boot: dropped a staged {} that was not installed", staged.as_ref().map_or("", |file| file.info.kind));
                *staged = None;
            }
        }
        self.kernel.is_some() || self.dtb.is_some()
    }
}

/// Expires staged files in the background until none are left.
fn sweep_staged() {
    if with_store(|store| std::mem::replace(&mut store.sweeping, true)) {
        return;
    }
    tokio::spawn(async {
        loop {
            tokio::time::sleep(STAGED_SWEEP).await;
            let held = with_store(|store| {
                let held = store.expire(Instant::now());
                store.sweeping = held;
                held
            });
            if !held {
                return;
            }
        }
    });
}

/// One hub per process: the staged files (in RAM, gone on restart) and the cached status.
static STORE: Mutex<Option<Store>> = Mutex::new(None);

fn with_store<T>(work: impl FnOnce(&mut Store) -> T) -> T {
    let mut store = STORE.lock().expect("boot store lock");
    work(store.get_or_insert_with(Store::default))
}

async fn audit(app: &App, action: &'static str, detail: String) {
    let now = clock::now();
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "admin", action, &detail)).await;
}

pub(crate) async fn read_status(app: &App, refresh: bool) -> ApiResult<BootState> {
    if !refresh && let Some((at, state)) = with_store(|store| store.status.clone()) && at.elapsed() < STATUS_FRESH {
        return Ok(state);
    }
    let run_dir = app.config.run_dir.clone();
    let state = tokio::task::spawn_blocking(move || boot::status(boot::board(), &run_dir))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(|error| ApiError::unavailable("boot_unavailable", format!("Cannot read the boot slots: {error}")))?;
    with_store(|store| store.status = Some((Instant::now(), state.clone())));
    Ok(state)
}

fn forget_status() {
    with_store(|store| store.status = None);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusQuery {
    refresh: Option<bool>,
}

/// `GET /system/boot`
pub async fn get(State(app): State<App>, _: Viewer, Query(query): Query<StatusQuery>) -> ApiResult<Response> {
    Ok(no_store(axum::Json(read_status(&app, query.refresh.unwrap_or(false)).await?)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextBody {
    slot: String,
    mode: String,
    password: String,
}

/// `PUT /system/boot/next`
pub async fn set_next(State(app): State<App>, peer: Option<Extension<Peer>>, _: Admin, Json(body): Json<NextBody>) -> ApiResult<Response> {
    let slot = Slot::parse(&body.slot).ok_or_else(|| ApiError::field("slot", "Use a or b."))?;
    let mode = match body.mode.as_str() {
        "once" => Mode::Once,
        "permanent" => Mode::Permanent,
        _ => return Err(ApiError::field("mode", "Use once or permanent.")),
    };
    auth::reconfirm(&app, client(peer), &body.password, "password").await?;
    let state = read_status(&app, true).await?;
    tokio::task::spawn_blocking(move || boot::set_next(boot::board(), &state, slot, mode))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(|why| ApiError::new(StatusCode::CONFLICT, "slot_not_bootable", why))?;
    log::warn!("boot: slot {} boots next ({})", slot.letter(), body.mode);
    audit(&app, "boot.next", format!("{} {}", slot.letter(), body.mode)).await;
    Ok(no_store(axum::Json(read_status(&app, true).await?)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadQuery {
    kind: String,
}

/// `POST /system/boot/kernel/upload?kind=kernel|dtb`: raw bytes, checked and kept in RAM.
pub async fn upload(State(app): State<App>, _: Admin, Query(query): Query<UploadQuery>, body: Bytes) -> ApiResult<Response> {
    let kind = query.kind;
    let data = body.clone();
    let checked = tokio::task::spawn_blocking(move || match kind.as_str() {
        "kernel" => Ok(boot::check_kernel(&data)),
        "dtb" => Ok(boot::check_dtb(&data)),
        _ => Err(()),
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| ApiError::field("kind", "Use kernel or dtb."))?;
    let info = checked.map_err(|why| ApiError::field("file", format!("This file cannot be installed: {why}.")))?;
    let staged = Staged { data: body, info: info.clone(), uploaded_ts: clock::now(), used: Instant::now() };
    with_store(|store| if info.kind == "kernel" { store.kernel = Some(staged) } else { store.dtb = Some(staged) });
    sweep_staged();
    audit(&app, "boot.upload", format!("{} {} bytes {}", info.kind, info.size, info.name.clone().unwrap_or_default())).await;
    Ok(no_store(axum::Json(info)))
}

#[derive(Serialize)]
struct StagedView {
    info: ImageInfo,
    uploaded_ts: i64,
}

#[derive(Serialize)]
struct StagedFiles {
    kernel: Option<StagedView>,
    dtb: Option<StagedView>,
}

/// `GET /system/boot/kernel/staged`
pub async fn staged(State(_app): State<App>, _: Admin) -> ApiResult<Response> {
    let view = |staged: &Option<Staged>| staged.as_ref().map(|staged| StagedView { info: staged.info.clone(), uploaded_ts: staged.uploaded_ts });
    let files = with_store(|store| StagedFiles { kernel: view(&store.kernel), dtb: view(&store.dtb) });
    Ok(no_store(axum::Json(files)))
}

/// `DELETE /system/boot/kernel/staged`
pub async fn discard(State(_app): State<App>, _: Admin) -> ApiResult<Response> {
    with_store(|store| {
        store.kernel = None;
        store.dtb = None;
    });
    Ok(no_store(StatusCode::NO_CONTENT))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallBody {
    password: String,
    /// Defaults to the slot that is not running.
    slot: Option<String>,
    prepare: Option<String>,
    #[serde(default)]
    allow_missing_modules: bool,
}

/// `POST /system/boot/kernel/install`: a job that writes the staged files into the other slot.
pub async fn install(State(app): State<App>, peer: Option<Extension<Peer>>, _: Admin, Json(body): Json<InstallBody>) -> ApiResult<Response> {
    let prepare = match body.prepare.as_deref().unwrap_or("auto") {
        "auto" => Prepare::Auto,
        "always" => Prepare::Always,
        "never" => Prepare::Never,
        _ => return Err(ApiError::field("prepare", "Use auto, always or never.")),
    };
    auth::reconfirm(&app, client(peer), &body.password, "password").await?;
    let state = read_status(&app, true).await?;
    let current = state.current.ok_or_else(|| ApiError::unavailable("boot_unavailable", "The running slot is unknown."))?;
    let target = match body.slot.as_deref() {
        Some(text) => Slot::parse(text).ok_or_else(|| ApiError::field("slot", "Use a or b."))?,
        None => current.other(),
    };
    let (kernel, dtb) = with_store(|store| {
        for staged in [&mut store.kernel, &mut store.dtb].into_iter().flatten() {
            staged.used = Instant::now();
        }
        (store.kernel.clone(), store.dtb.clone())
    });
    if kernel.is_none() && dtb.is_none() {
        return Err(ApiError::conflict("Upload a kernel or a device tree first."));
    }
    if !with_store(|store| !std::mem::replace(&mut store.installing, true)) {
        return Err(ApiError::conflict("An install is already running."));
    }
    let job = match jobs::create(&app, "kernel_install", "Starting") {
        Ok(job) => job,
        Err(error) => {
            with_store(|store| store.installing = false);
            return Err(error);
        }
    };
    log::warn!("boot: installing into slot {}", target.letter());
    audit(&app, "boot.install", format!("slot {}", target.letter())).await;
    let worker_app = app.clone();
    let running = job.clone();
    let run_dir = app.config.run_dir.clone();
    let allow_missing_modules = body.allow_missing_modules;
    tokio::spawn(async move {
        let progress_app = worker_app.clone();
        let progress_job = running.clone();
        let handle = tokio::runtime::Handle::current();
        let outcome = tokio::task::spawn_blocking(move || {
            let report = |done: f32, detail: &str| {
                let (app, job, detail) = (progress_app.clone(), progress_job.clone(), detail.to_owned());
                handle.spawn(async move { jobs::progress(&app, &job, done, &detail) });
            };
            let request = boot::Install {
                kernel: kernel.as_ref().map(|staged| (&staged.data[..], staged.info.clone())),
                dtb: dtb.as_ref().map(|staged| &staged.data[..]),
                target,
                prepare,
                allow_missing_modules,
            };
            boot::install(boot::board(), &run_dir, &state, &request, &report)
        })
        .await;
        with_store(|store| store.installing = false);
        forget_status();
        match outcome {
            Ok(Ok(report)) => {
                with_store(|store| {
                    store.kernel = None;
                    store.dtb = None;
                });
                log::warn!("boot: installed into slot {}", target.letter());
                jobs::finish(&worker_app, &running, serde_json::to_value(report).unwrap_or_default());
            }
            Ok(Err(why)) => {
                log::warn!("boot: install failed: {why}");
                jobs::fail(&worker_app, &running, "install_failed", &why);
            }
            Err(_) => {
                jobs::fail(&worker_app, &running, "internal", "The install stopped unexpectedly.");
            }
        }
    });
    Ok(no_store((StatusCode::ACCEPTED, axum::Json(job))))
}

/// At start-up: completes a one-time boot (the previous slot order comes back).
pub fn after_start() {
    tokio::task::spawn_blocking(|| {
        if let Some(done) = boot::after_start(boot::board()) {
            log::info!("boot: {done}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(kind: &'static str, used: Instant) -> Option<Staged> {
        let info = ImageInfo { kind, format: "raw", size: 4, name: None, version: None, load_address: None, entry_address: None, built_ts: None };
        Some(Staged { data: Bytes::from_static(b"data"), info, uploaded_ts: 0, used })
    }

    #[test]
    fn staged_files_unused_for_the_ttl_are_dropped() {
        let now = Instant::now() + STAGED_TTL + Duration::from_secs(1);
        let mut store = Store { kernel: staged("kernel", Instant::now()), dtb: staged("dtb", now), ..Store::default() };
        assert!(store.expire(now), "the recently used device tree stays");
        assert!(store.kernel.is_none(), "the old kernel is gone");
        assert!(store.dtb.is_some());
        assert!(!store.expire(now + STAGED_TTL), "nothing left to sweep");
        assert!(store.dtb.is_none());
    }
}
