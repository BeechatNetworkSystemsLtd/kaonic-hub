//! Jobs: long operations followed by `GET /jobs/{id}` and the `jobs` topic.
//!
//! Jobs are kept in memory (the last 50): a restart forgets them.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::response::Response;
use serde::Serialize;

use super::no_store;
use crate::app::App;
use crate::auth::Viewer;
use crate::error::{ApiError, ApiResult};
use crate::{clock, random};

const KEEP: usize = 50;
const SCAN_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Serialize)]
pub struct Job {
    pub id: String,
    pub kind: &'static str,
    pub state: &'static str,
    pub node_id: Option<String>,
    pub progress: Option<f32>,
    pub detail: Option<String>,
    pub result: Option<serde_json::Value>,
    pub error: Option<serde_json::Value>,
    pub created_ts: i64,
    pub updated_ts: i64,
}

#[derive(Default)]
pub struct Jobs {
    jobs: Mutex<VecDeque<Job>>,
}

impl Jobs {
    fn put(&self, job: Job) {
        let mut jobs = self.jobs.lock().expect("jobs lock");
        jobs.retain(|known| known.id != job.id);
        jobs.push_back(job);
        while jobs.len() > KEEP {
            jobs.pop_front();
        }
    }

    fn get(&self, id: &str) -> Option<Job> {
        self.jobs
            .lock()
            .expect("jobs lock")
            .iter()
            .find(|job| job.id == id)
            .cloned()
    }
}

fn update(app: &App, mut job: Job, state: &'static str, change: impl FnOnce(&mut Job)) -> Job {
    job.state = state;
    job.updated_ts = clock::now();
    change(&mut job);
    app.jobs.put(job.clone());
    app.bus.publish("jobs", "job.updated", &job);
    job
}

/// A new running job of `kind`, for work that reports its own progress (`progress`, `finish`, `fail`).
pub fn create(app: &App, kind: &'static str, detail: &str) -> ApiResult<Job> {
    let now = clock::now();
    let job = Job {
        id: random::hex(&random::bytes::<8>()?),
        kind,
        state: "queued",
        node_id: None,
        progress: Some(0.0),
        detail: None,
        result: None,
        error: None,
        created_ts: now,
        updated_ts: now,
    };
    Ok(update(app, job, "running", |job| job.detail = Some(detail.to_owned())))
}

/// A queued job acting on the node `node_id`; `progress` starts it.
pub fn queue(app: &App, kind: &'static str, node_id: &str) -> ApiResult<Job> {
    let now = clock::now();
    let job = Job {
        id: random::hex(&random::bytes::<8>()?),
        kind,
        state: "queued",
        node_id: Some(node_id.to_owned()),
        progress: Some(0.0),
        detail: Some("Waiting".into()),
        result: None,
        error: None,
        created_ts: now,
        updated_ts: now,
    };
    Ok(update(app, job, "queued", |_| {}))
}

pub fn progress(app: &App, job: &Job, done: f32, detail: &str) -> Job {
    update(app, job.clone(), "running", |job| {
        job.progress = Some(done.clamp(0.0, 1.0));
        job.detail = Some(detail.to_owned());
    })
}

pub fn finish(app: &App, job: &Job, result: serde_json::Value) -> Job {
    update(app, job.clone(), "done", |job| {
        job.progress = Some(1.0);
        job.detail = None;
        job.result = Some(result);
    })
}

pub fn fail(app: &App, job: &Job, code: &str, message: &str) -> Job {
    update(app, job.clone(), "failed", |job| {
        job.detail = Some(message.to_owned());
        job.error = Some(serde_json::json!({ "code": code, "message": message }));
    })
}

/// Starts a scan and returns its job; the job finishes when the results arrive.
pub async fn start_scan(app: &App) -> ApiResult<Job> {
    let now = clock::now();
    let job = Job {
        id: random::hex(&random::bytes::<8>()?),
        kind: "wifi_scan",
        state: "queued",
        node_id: None,
        progress: None,
        detail: None,
        result: None,
        error: None,
        created_ts: now,
        updated_ts: now,
    };
    // Subscribe before asking, so results cannot slip past.
    let mut events = app.bus.subscribe();
    app.wifi.scan().await.map_err(super::wifi::wifi_error)?;
    let job = update(app, job, "running", |job| {
        job.detail = Some("Scanning".into())
    });

    let app = app.clone();
    let running = job.clone();
    tokio::spawn(async move {
        let outcome = tokio::time::timeout(SCAN_TIMEOUT, async {
            loop {
                match events.recv().await {
                    Ok(event) if event.kind == "wifi.scan" => return Some(event.data),
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return None,
                }
            }
        })
        .await;
        match outcome {
            Ok(Some(results)) => update(&app, running, "done", |job| {
                job.progress = Some(1.0);
                job.detail = None;
                job.result = Some(results);
            }),
            _ => update(&app, running, "failed", |job| {
                job.detail = Some("The scan did not finish.".into());
                job.error = Some(
                    serde_json::json!({ "code": "not_running", "message": "The scan did not finish. Try again." }),
                );
            }),
        };
    });
    Ok(job)
}

pub async fn list(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    let jobs: Vec<Job> = app
        .jobs
        .jobs
        .lock()
        .expect("jobs lock")
        .iter()
        .cloned()
        .collect();
    Ok(no_store(axum::Json(jobs)))
}

pub async fn get_job(
    State(app): State<App>,
    _: Viewer,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    app.jobs
        .get(&id)
        .map(|job| no_store(axum::Json(job)))
        .ok_or_else(|| ApiError::not_found("No such job."))
}
