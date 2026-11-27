//! `/system/os*`: updating the operating system from a release bundle (`crate::osupdate`).
//! The bundle is uploaded to userfs, checked in a job, then installed into the slot that is
//! not running, which boots from the next restart on (falling back if it does not start).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use axum::Extension;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use super::{Json, Peer, boot as boot_api, client, jobs, no_store};
use crate::app::App;
use crate::auth::{self, Admin, Viewer};
use crate::boot::{self, Mode, Slot};
use crate::error::{ApiError, ApiResult};
use crate::osupdate::{self, Checked, Target};
use crate::clock;

/// The largest bundle taken; release bundles are about 160 MB.
const MAX_BUNDLE: u64 = 1024 * 1024 * 1024;
/// Room left on userfs after the bundle is stored.
const SPARE: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
enum Stage {
    Uploading,
    Checking { job: String },
    Ready(Checked),
    Invalid(String),
    Installing { job: String, checked: Checked, slot: Slot },
    Installed { checked: Checked, slot: Slot },
}

#[derive(Clone)]
struct Upload {
    stage: Stage,
    size: u64,
    uploaded_ts: i64,
}

#[derive(Default)]
struct Store {
    upload: Option<Upload>,
    /// Whether leftovers of an earlier run were cleared.
    cleared: bool,
}

static STORE: Mutex<Option<Store>> = Mutex::new(None);

fn with_store<T>(work: impl FnOnce(&mut Store) -> T) -> T {
    let mut store = STORE.lock().expect("os store lock");
    work(store.get_or_insert_with(Store::default))
}

fn dir(app: &App) -> PathBuf {
    app.config.state_dir.join("os-update")
}

fn bundle_path(app: &App) -> PathBuf {
    dir(app).join("bundle.tar.gz")
}

/// A bundle left by an earlier run is forgotten: its check is gone with the process.
fn clear_once(app: &App) {
    if !with_store(|store| std::mem::replace(&mut store.cleared, true)) {
        let _ = std::fs::remove_dir_all(dir(app));
    }
}

fn free_space(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs(3) fills `stat` for a NUL-terminated path.
    (unsafe { libc::statvfs(name.as_ptr(), &mut stat) } == 0).then(|| stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[derive(Serialize)]
struct UpdateView {
    state: &'static str,
    size: u64,
    uploaded_ts: i64,
    job_id: Option<String>,
    version: Option<String>,
    built: Option<String>,
    /// Compared with the running image: `newer`, `same` or `older`.
    compared: Option<&'static str>,
    error: Option<String>,
    slot: Option<Slot>,
}

#[derive(Serialize)]
struct OsView {
    /// The Kaonic image version, when the image records it.
    version: Option<String>,
    os: String,
    machine: Option<String>,
    slot: Option<Slot>,
    update: Option<UpdateView>,
}

fn compared(new: &str, running: Option<&str>) -> Option<&'static str> {
    running.map(|running| match osupdate::compare_versions(new, running) {
        std::cmp::Ordering::Greater => "newer",
        std::cmp::Ordering::Equal => "same",
        std::cmp::Ordering::Less => "older",
    })
}

async fn view(app: &App) -> OsView {
    let version = app.device.image_version();
    let slot = boot_api::read_status(app, false).await.ok().and_then(|state| state.current);
    let update = with_store(|store| store.upload.clone()).map(|upload| {
        let mut view = UpdateView { state: "", size: upload.size, uploaded_ts: upload.uploaded_ts, job_id: None, version: None, built: None, compared: None, error: None, slot: None };
        let describe = |checked: &Checked, view: &mut UpdateView| {
            view.version = Some(checked.version.clone());
            view.built = checked.built.clone();
            view.compared = compared(&checked.version, version.as_deref());
        };
        match &upload.stage {
            Stage::Uploading => view.state = "uploading",
            Stage::Checking { job } => {
                view.state = "checking";
                view.job_id = Some(job.clone());
            }
            Stage::Ready(checked) => {
                view.state = "ready";
                describe(checked, &mut view);
            }
            Stage::Invalid(why) => {
                view.state = "invalid";
                view.error = Some(why.clone());
            }
            Stage::Installing { job, checked, slot } => {
                view.state = "installing";
                view.job_id = Some(job.clone());
                view.slot = Some(*slot);
                describe(checked, &mut view);
            }
            Stage::Installed { checked, slot } => {
                view.state = "installed";
                view.slot = Some(*slot);
                describe(checked, &mut view);
            }
        }
        view
    });
    OsView { version, os: app.device.os_version(), machine: app.device.machine(), slot, update }
}

/// `GET /system/os`
pub async fn get(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    clear_once(&app);
    Ok(no_store(axum::Json(view(&app).await)))
}

fn busy(stage: &Stage) -> bool {
    matches!(stage, Stage::Uploading | Stage::Checking { .. } | Stage::Installing { .. })
}

/// `POST /system/os/upload`: the bundle as the raw body. Stored on userfs, then checked in a
/// job; the answer is the job.
pub async fn upload(State(app): State<App>, _: Admin, headers: HeaderMap, mut body: Body) -> ApiResult<Response> {
    clear_once(&app);
    let length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .ok_or_else(|| ApiError::new(StatusCode::LENGTH_REQUIRED, "length_required", "Send the file with its length."))?;
    if length > MAX_BUNDLE {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", "This file is too large to be a Kaonic image."));
    }
    if length == 0 {
        return Err(ApiError::field("file", "The file is empty."));
    }
    let claimed = with_store(|store| {
        if store.upload.as_ref().is_some_and(|upload| busy(&upload.stage)) {
            return false;
        }
        store.upload = Some(Upload { stage: Stage::Uploading, size: length, uploaded_ts: clock::now() });
        true
    });
    if !claimed {
        return Err(ApiError::conflict("An update is already being uploaded, checked or installed."));
    }
    let forget = || with_store(|store| store.upload = None);
    let path = bundle_path(&app);
    let _ = std::fs::remove_file(&path);
    if let Err(error) = std::fs::create_dir_all(dir(&app)) {
        forget();
        log::error!("os: cannot make the update directory: {error}");
        return Err(ApiError::internal());
    }
    if let Some(free) = free_space(&dir(&app))
        && free < length + SPARE
    {
        forget();
        return Err(ApiError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "no_space",
            format!("Not enough free storage for the update: it needs {} MB, {} MB are free.", (length + SPARE) >> 20, free >> 20),
        ));
    }
    let stored = async {
        let mut file = tokio::fs::File::create(&path).await?;
        let mut received = 0u64;
        while let Some(frame) = std::future::poll_fn(|cx| http_body::Body::poll_frame(std::pin::Pin::new(&mut body), cx)).await {
            let frame = frame.map_err(|error| std::io::Error::other(error.to_string()))?;
            let Ok(data) = frame.into_data() else { continue };
            received += data.len() as u64;
            if received > length {
                return Err(std::io::Error::other("the upload is longer than announced"));
            }
            file.write_all(&data).await?;
        }
        file.sync_all().await?;
        if received != length {
            return Err(std::io::Error::other("the upload was cut off"));
        }
        Ok::<_, std::io::Error>(())
    }
    .await;
    if let Err(error) = stored {
        forget();
        let _ = std::fs::remove_file(&path);
        log::warn!("os: upload failed: {error}");
        return Err(ApiError::bad_request(format!("The upload did not complete ({error}). Try again.")));
    }
    let job = match jobs::create(&app, "os_check", "Checking the image") {
        Ok(job) => job,
        Err(error) => {
            forget();
            return Err(error);
        }
    };
    with_store(|store| store.upload = Some(Upload { stage: Stage::Checking { job: job.id.clone() }, size: length, uploaded_ts: clock::now() }));
    log::info!("os: an update of {length} bytes was uploaded; checking it");
    let (worker_app, running, machine) = (app.clone(), job.clone(), app.device.machine());
    tokio::spawn(async move {
        let (progress_app, progress_job) = (worker_app.clone(), running.clone());
        let handle = tokio::runtime::Handle::current();
        let path = bundle_path(&worker_app);
        let outcome = tokio::task::spawn_blocking(move || {
            let report = |done: f32| {
                let (app, job) = (progress_app.clone(), progress_job.clone());
                handle.spawn(async move { jobs::progress(&app, &job, done, "Checking the image") });
            };
            osupdate::check(&path, machine.as_deref(), &report)
        })
        .await
        .unwrap_or_else(|_| Err("the check stopped unexpectedly".into()));
        let stage = match outcome {
            Ok(checked) => {
                log::info!("os: the update is image {} for {}", checked.version, checked.machine);
                jobs::finish(&worker_app, &running, serde_json::to_value(&checked).unwrap_or_default());
                Stage::Ready(checked)
            }
            Err(why) => {
                log::warn!("os: the update was refused: {why}");
                let _ = std::fs::remove_file(bundle_path(&worker_app));
                jobs::fail(&worker_app, &running, "invalid_image", &capitalized(&why));
                Stage::Invalid(capitalized(&why))
            }
        };
        with_store(|store| {
            if let Some(upload) = &mut store.upload {
                upload.stage = stage;
            }
        });
    });
    audit(&app, "os.upload", format!("{length} bytes")).await;
    Ok(no_store((StatusCode::ACCEPTED, axum::Json(job))))
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    let mut out: String = chars.next().map(|first| first.to_uppercase().collect()).unwrap_or_default();
    out.extend(chars);
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

/// `DELETE /system/os/upload`: drops an uploaded bundle that is not being installed.
pub async fn discard(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    let dropped = with_store(|store| {
        if store.upload.as_ref().is_some_and(|upload| matches!(upload.stage, Stage::Installing { .. } | Stage::Uploading)) {
            return false;
        }
        store.upload = None;
        true
    });
    if !dropped {
        return Err(ApiError::conflict("The update is being installed."));
    }
    let _ = std::fs::remove_file(bundle_path(&app));
    Ok(no_store(StatusCode::NO_CONTENT))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallBody {
    #[serde(default)]
    password: String,
}

/// `POST /system/os/install`: a job that writes the checked bundle into the other slot and
/// makes it boot from the next restart on.
pub async fn install(State(app): State<App>, peer: Option<Extension<Peer>>, _: Admin, Json(body): Json<InstallBody>) -> ApiResult<Response> {
    let checked = with_store(|store| match store.upload.as_ref().map(|upload| &upload.stage) {
        Some(Stage::Ready(checked)) => Some(checked.clone()),
        _ => None,
    })
    .ok_or_else(|| ApiError::conflict("Upload an image and wait for it to be checked first."))?;
    auth::reconfirm(&app, client(peer), &body.password, "password").await?;
    let state = boot_api::read_status(&app, true).await?;
    let current = state.current.ok_or_else(|| ApiError::unavailable("boot_unavailable", "The running slot is unknown, so the update has nowhere safe to go."))?;
    let target = current.other();
    if !boot_api::claim_install() {
        return Err(ApiError::conflict("A kernel or system install is already running."));
    }
    let job = match jobs::create(&app, "os_install", "Starting") {
        Ok(job) => job,
        Err(error) => {
            boot_api::release_install();
            return Err(error);
        }
    };
    with_store(|store| {
        if let Some(upload) = &mut store.upload {
            upload.stage = Stage::Installing { job: job.id.clone(), checked: checked.clone(), slot: target };
        }
    });
    log::warn!("os: installing image {} into slot {}", checked.version, target.letter());
    audit(&app, "os.install", format!("image {} into slot {}", checked.version, target.letter())).await;
    let (worker_app, running) = (app.clone(), job.clone());
    tokio::spawn(async move {
        let (progress_app, progress_job) = (worker_app.clone(), running.clone());
        let handle = tokio::runtime::Handle::current();
        let path = bundle_path(&worker_app);
        let run_dir = worker_app.config.run_dir.clone();
        let job_checked = checked.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let report = |done: f32, detail: &str| {
                let (app, job, detail) = (progress_app.clone(), progress_job.clone(), detail.to_owned());
                handle.spawn(async move { jobs::progress(&app, &job, done, &detail) });
            };
            install_into(&path, &run_dir, &state, &job_checked, target, &report)
        })
        .await
        .unwrap_or_else(|_| Err("the install stopped unexpectedly".into()));
        boot_api::release_install();
        boot_api::forget_status();
        let stage = match outcome {
            Ok(()) => {
                log::warn!("os: image {} is in slot {} and boots next", checked.version, target.letter());
                let _ = std::fs::remove_file(bundle_path(&worker_app));
                jobs::finish(&worker_app, &running, serde_json::json!({ "slot": target, "version": checked.version }));
                Stage::Installed { checked, slot: target }
            }
            Err(why) => {
                log::warn!("os: install failed: {why}");
                jobs::fail(&worker_app, &running, "install_failed", &capitalized(&why));
                // The bundle is still good: it can be installed again.
                Stage::Ready(checked)
            }
        };
        with_store(|store| {
            if let Some(upload) = &mut store.upload {
                upload.stage = stage;
            }
        });
    });
    Ok(no_store((StatusCode::ACCEPTED, axum::Json(job))))
}

fn install_into(path: &Path, run_dir: &Path, state: &boot::BootState, checked: &Checked, target: Slot, progress: &dyn Fn(f32, &str)) -> Result<(), String> {
    let board = boot::board();
    let current = target.other();
    // Until the new system is complete, the running one must stay the one that boots.
    if state.next != Some(current) || state.once {
        boot::set_next(board, state, current, Mode::Permanent)?;
    }
    progress(0.0, "Preparing");
    let (bootfs, rootfs) = (target.partition("bootfs"), target.partition("rootfs"));
    let (boot_target, root_target) = if boot::dry_run() { (Target::DryRun, Target::DryRun) } else { (Target::Device(&bootfs), Target::Device(&rootfs)) };
    osupdate::write_images(path, checked, boot_target, root_target, progress)?;
    progress(0.98, "Finishing");
    if !boot::dry_run() {
        // The system image is smaller than its partition: let it use the whole slot.
        if board.run("e2fsck", &["-f", "-y", &rootfs]).is_ok()
            && let Err(error) = board.run("resize2fs", &[&rootfs])
        {
            log::warn!("os: the new system was not grown to its partition: {error}");
        }
    }
    if boot::dry_run() {
        log::info!("os (dry run): slot {} would boot next", target.letter());
        return Ok(());
    }
    let fresh = boot::status(board, run_dir).map_err(|error| format!("cannot read the boot slots: {error}"))?;
    boot::set_next(board, &fresh, target, Mode::Permanent)
}

async fn audit(app: &App, action: &'static str, detail: String) {
    let now = clock::now();
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "admin", action, &detail)).await;
}
