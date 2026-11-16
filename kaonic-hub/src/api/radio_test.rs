//! `/radio/bands/{band}/test`: test messages sent as raw frames on a band, below the mesh, to
//! check a link with a receiver or a spectrum analyser. One message, or the same message
//! again and again at an interval until stopped (or after a count).
//!
//! Each band runs at most one test; a new one replaces it. On the mesh band the frames share
//! the air with the mesh, and other hubs count them as frames they cannot decode.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kaonic_mesh::radio::RadioSocket;
use serde::{Deserialize, Serialize};

use super::{Json, no_store};
use crate::app::App;
use crate::auth::{Admin, Viewer};
use crate::error::{ApiError, ApiResult};

/// The largest test message: one frame of the transceiver, less the byte the old gateway kept.
pub const MAX_PAYLOAD: usize = 2047;
pub const MIN_INTERVAL_MS: u64 = 100;
pub const MAX_INTERVAL_MS: u64 = 3_600_000;
pub const MAX_COUNT: u64 = 1_000_000;

#[derive(Deserialize, Clone, Copy, Default, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    #[default]
    Text,
    Hex,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestInput {
    /// The payload: text as UTF-8, or hex digits (spaces and colons allowed between bytes).
    message: String,
    #[serde(default)]
    format: Format,
    /// Left out: one message. Given: the message again every `interval_ms` until stopped.
    interval_ms: Option<u64>,
    /// With an interval: stop after this many. Left out: until stopped.
    count: Option<u64>,
}

/// A test's state, as the API shows it.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct TestView {
    running: bool,
    sent: u64,
    failed: u64,
    /// Bytes per message.
    bytes: usize,
    interval_ms: Option<u64>,
    count: Option<u64>,
    started_ts_ms: i64,
    last_error: Option<String>,
}

struct Run {
    started_ts_ms: i64,
    bytes: usize,
    interval_ms: Option<u64>,
    count: Option<u64>,
    sent: AtomicU64,
    failed: AtomicU64,
    running: AtomicBool,
    last_error: Mutex<Option<String>>,
    task: Mutex<Option<tokio::task::AbortHandle>>,
}

impl Run {
    fn view(&self) -> TestView {
        TestView {
            running: self.running.load(Ordering::Relaxed),
            sent: self.sent.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            bytes: self.bytes,
            interval_ms: self.interval_ms,
            count: self.count,
            started_ts_ms: self.started_ts_ms,
            last_error: self.last_error.lock().expect("radio test error lock").clone(),
        }
    }

    fn stop(&self) {
        if let Some(task) = self.task.lock().expect("radio test task lock").take() {
            task.abort();
        }
        self.running.store(false, Ordering::Relaxed);
    }
}

/// The last test of each band, by band id.
static RUNS: Mutex<Option<HashMap<&'static str, Arc<Run>>>> = Mutex::new(None);

fn run_of(band: &str) -> Option<Arc<Run>> {
    RUNS.lock().expect("radio test lock").as_ref()?.get(band).cloned()
}

/// The band's last test, for the band's view.
pub(crate) fn view_of(band: &str) -> Option<TestView> {
    run_of(band).map(|run| run.view())
}

/// Stops the band's test, if one runs.
pub(crate) fn stop_band(band: &str) {
    if let Some(run) = run_of(band) {
        run.stop();
    }
}

/// The message's bytes.
fn payload(input: &TestInput) -> Result<Vec<u8>, (&'static str, String)> {
    let bytes = match input.format {
        Format::Text => input.message.as_bytes().to_vec(),
        Format::Hex => {
            let digits: String = input.message.chars().filter(|c| !matches!(c, ' ' | ':' | '\n' | '\r' | '\t' | ',')).collect();
            let digits = digits.strip_prefix("0x").unwrap_or(&digits);
            if !digits.len().is_multiple_of(2) || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(("message", "Use pairs of hex digits, such as 4b 41 4f.".into()));
            }
            (0..digits.len()).step_by(2).map(|at| u8::from_str_radix(&digits[at..at + 2], 16).expect("hex digits")).collect()
        }
    };
    if bytes.is_empty() {
        return Err(("message", "Type a message to send.".into()));
    }
    if bytes.len() > MAX_PAYLOAD {
        return Err(("message", format!("Use at most {MAX_PAYLOAD} bytes; this is {}.", bytes.len())));
    }
    Ok(bytes)
}

fn check(input: &TestInput) -> ApiResult<Vec<u8>> {
    let mut problems = Vec::new();
    let bytes = payload(input).map_err(|problem| problems.push(problem)).ok();
    if let Some(interval) = input.interval_ms
        && !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&interval)
    {
        problems.push(("interval_ms", format!("Use {MIN_INTERVAL_MS} ms to {} minutes.", MAX_INTERVAL_MS / 60_000)));
    }
    match (input.count, input.interval_ms) {
        (Some(_), None) => problems.push(("count", "A count needs an interval.".into())),
        (Some(count), Some(_)) if !(1..=MAX_COUNT).contains(&count) => problems.push(("count", format!("Use 1 to {MAX_COUNT}."))),
        _ => {}
    }
    match bytes {
        Some(bytes) if problems.is_empty() => Ok(bytes),
        _ => Err(ApiError::invalid(problems)),
    }
}

fn send_error(error: std::io::Error) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, "radio_rejected", format!("The radio did not send it: {error}."))
}

/// `POST /radio/bands/{band}/test`
pub async fn start(State(app): State<App>, Admin(_): Admin, Path(id): Path<String>, Json(input): Json<TestInput>) -> ApiResult<Response> {
    let (band, interface) = super::radio_bands::test_target(&app, &id).await?;
    let bytes = check(&input)?;
    let socket = RadioSocket::open_sender(interface).map_err(|error| match error.kind() {
        std::io::ErrorKind::Unsupported => ApiError::unavailable("radio_unavailable", "Test messages need the board's radio; this hub has none."),
        _ => ApiError::unavailable("radio_unavailable", format!("The radio {interface} cannot be opened: {error}.")),
    })?;
    stop_band(band);
    let run = Arc::new(Run {
        started_ts_ms: crate::clock::now_ms(),
        bytes: bytes.len(),
        interval_ms: input.interval_ms,
        count: input.count,
        sent: AtomicU64::new(0),
        failed: AtomicU64::new(0),
        running: AtomicBool::new(input.interval_ms.is_some()),
        last_error: Mutex::new(None),
        task: Mutex::new(None),
    });
    RUNS.lock().expect("radio test lock").get_or_insert_with(HashMap::new).insert(band, run.clone());
    let detail = match input.interval_ms {
        None => format!("{interface}: one message of {} bytes", bytes.len()),
        Some(interval) => format!("{interface}: {} bytes every {interval} ms, {}", bytes.len(), input.count.map_or("until stopped".to_owned(), |count| format!("{count} times"))),
    };
    log::info!("radio test {detail}");
    let stamp = crate::clock::now();
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, stamp, "admin", "radio.test", &detail)).await;

    let Some(interval) = input.interval_ms else {
        // One message: sent before the answer, so a refusal is the answer.
        let sent = socket.send(&bytes).await;
        return match sent {
            Ok(()) => {
                run.sent.store(1, Ordering::Relaxed);
                Ok(no_store(axum::Json(run.view())))
            }
            Err(error) => {
                run.failed.store(1, Ordering::Relaxed);
                *run.last_error.lock().expect("radio test error lock") = Some(error.to_string());
                Err(send_error(error))
            }
        };
    };
    let task_run = run.clone();
    let task = tokio::spawn(async move {
        repeat(&socket, &bytes, Duration::from_millis(interval), task_run.count, &task_run).await;
        task_run.running.store(false, Ordering::Relaxed);
        log::info!("radio test on {}: done, {} sent, {} failed", socket.iface(), task_run.sent.load(Ordering::Relaxed), task_run.failed.load(Ordering::Relaxed));
    });
    *run.task.lock().expect("radio test task lock") = Some(task.abort_handle());
    Ok((StatusCode::ACCEPTED, no_store(axum::Json(run.view()))).into_response())
}

/// Sends the message every `interval` (from the start of one send to the next) until `count`.
async fn repeat(socket: &RadioSocket, bytes: &[u8], interval: Duration, count: Option<u64>, run: &Run) {
    let mut tick = tokio::time::interval(interval);
    // A send that waited on a busy channel does not make the next ones bunch up.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut done = 0u64;
    while count.is_none_or(|count| done < count) {
        tick.tick().await;
        match socket.send(bytes).await {
            Ok(()) => {
                run.sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                run.failed.fetch_add(1, Ordering::Relaxed);
                let text = error.to_string();
                let mut last = run.last_error.lock().expect("radio test error lock");
                if last.as_deref() != Some(text.as_str()) {
                    log::warn!("radio test on {}: send: {text}", socket.iface());
                }
                *last = Some(text);
            }
        }
        done += 1;
    }
}

#[derive(Serialize)]
struct NoTest {
    running: bool,
}

/// `GET /radio/bands/{band}/test`: the band's last test (`running: false` if none).
pub async fn get(State(_app): State<App>, _: Viewer, Path(id): Path<String>) -> ApiResult<Response> {
    let band = super::radio_bands::band_id(&id)?;
    Ok(match view_of(band) {
        Some(view) => no_store(axum::Json(view)),
        None => no_store(axum::Json(NoTest { running: false })),
    })
}

/// `POST /radio/bands/{band}/test/stop`
pub async fn stop(State(_app): State<App>, Admin(_): Admin, Path(id): Path<String>) -> ApiResult<Response> {
    let band = super::radio_bands::band_id(&id)?;
    let Some(run) = run_of(band) else { return Ok(no_store(axum::Json(NoTest { running: false }))) };
    if run.running.load(Ordering::Relaxed) {
        run.stop();
        log::info!("radio test on band {band}: stopped, {} sent", run.sent.load(Ordering::Relaxed));
    }
    Ok(no_store(axum::Json(run.view())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(json: &str) -> TestInput {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_message_is_text_or_hex_and_fits_one_frame() {
        assert_eq!(check(&input(r#"{"message":"KAO"}"#)).unwrap(), b"KAO");
        assert_eq!(check(&input(r#"{"message":"4b 41:4F","format":"hex"}"#)).unwrap(), b"KAO");
        assert_eq!(check(&input(r#"{"message":"0x4b414f","format":"hex"}"#)).unwrap(), b"KAO");
        for bad in [r#"{"message":"4b4","format":"hex"}"#, r#"{"message":"zz","format":"hex"}"#, r#"{"message":""}"#, r#"{"message":"  ","format":"hex"}"#] {
            assert!(check(&input(bad)).is_err(), "{bad}");
        }
        let longest = format!(r#"{{"message":"{}"}}"#, "x".repeat(MAX_PAYLOAD));
        assert_eq!(check(&input(&longest)).unwrap().len(), MAX_PAYLOAD);
        let too_long = format!(r#"{{"message":"{}"}}"#, "x".repeat(MAX_PAYLOAD + 1));
        assert!(check(&input(&too_long)).is_err());
        // Multi-byte text is counted in bytes.
        let wide = format!(r#"{{"message":"{}"}}"#, "é".repeat(1024));
        assert!(check(&input(&wide)).is_err());
    }

    #[test]
    fn repeats_need_a_sane_interval_and_count() {
        assert!(check(&input(r#"{"message":"a","interval_ms":1000}"#)).is_ok());
        assert!(check(&input(r#"{"message":"a","interval_ms":1000,"count":5}"#)).is_ok());
        assert!(check(&input(r#"{"message":"a","interval_ms":10}"#)).is_err());
        assert!(check(&input(r#"{"message":"a","interval_ms":1000,"count":0}"#)).is_err());
        assert!(check(&input(r#"{"message":"a","count":5}"#)).is_err());
        assert!(serde_json::from_str::<TestInput>(r#"{"message":"a","format":"base64"}"#).is_err());
        assert!(serde_json::from_str::<TestInput>(r#"{"message":"a","bogus":1}"#).is_err());
    }

    #[tokio::test]
    async fn a_counted_run_stops_by_itself_and_a_stopped_one_stays_stopped() {
        // The emulator's air with nobody listening swallows frames: a socket that always sends.
        let socket = RadioSocket::open("air://127.0.0.1:9/test").unwrap();
        let run = Run {
            started_ts_ms: 0,
            bytes: 1,
            interval_ms: Some(1),
            count: Some(3),
            sent: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            running: AtomicBool::new(true),
            last_error: Mutex::new(None),
            task: Mutex::new(None),
        };
        repeat(&socket, b"x", Duration::from_millis(1), Some(3), &run).await;
        assert_eq!(run.sent.load(Ordering::Relaxed) + run.failed.load(Ordering::Relaxed), 3);

        let run = Arc::new(Run { count: None, sent: AtomicU64::new(0), ..run });
        let task_run = run.clone();
        let task = tokio::spawn(async move {
            let socket = RadioSocket::open("air://127.0.0.1:9/test").unwrap();
            repeat(&socket, b"x", Duration::from_millis(5), None, &task_run).await;
        });
        *run.task.lock().unwrap() = Some(task.abort_handle());
        tokio::time::sleep(Duration::from_millis(60)).await;
        run.stop();
        assert!(!run.view().running);
        let after_stop = run.sent.load(Ordering::Relaxed) + run.failed.load(Ordering::Relaxed);
        assert!(after_stop >= 2, "sent {after_stop}");
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(run.sent.load(Ordering::Relaxed) + run.failed.load(Ordering::Relaxed), after_stop);
    }
}
