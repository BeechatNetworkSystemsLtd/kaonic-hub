//! `/ptt`: push-to-talk state and settings, the browser's audio socket, and UDP sessions for
//! native clients.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use super::{Json, no_store};
use crate::app::App;
use crate::auth::{self, Admin, Role, Viewer};
use crate::error::{ApiError, ApiResult};
use crate::server::ws_send;
use crate::ptt::{Control, KeyError, Ptt, SettingsPatch, Source, udp, wav};

const PING_EVERY: Duration = Duration::from_secs(20);
const SILENCE_LIMIT: Duration = Duration::from_secs(60);
const SESSION_CHECK: Duration = Duration::from_secs(30);
/// A 20 ms frame is 640 bytes; control messages are small.
const MAX_MESSAGE: usize = 4096;

fn ptt(app: &App) -> ApiResult<Arc<Ptt>> {
    app.ptt.get().cloned().ok_or_else(|| ApiError::unavailable("ptt_unavailable", "Push-to-talk needs the radio, which is not running on this device."))
}

/// `GET /ptt`
pub async fn get(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    Ok(no_store(axum::Json(ptt(&app)?.state())))
}

/// `PATCH /ptt/settings`
pub async fn patch_settings(State(app): State<App>, _: Admin, Json(patch): Json<SettingsPatch>) -> ApiResult<Response> {
    let ptt = ptt(&app)?;
    let settings = patch.apply(ptt.settings()).map_err(|(field, message)| ApiError::field(field, message))?;
    ptt.set_settings(settings.clone()).await;
    Ok(no_store(axum::Json(settings)))
}

/// `POST /ptt/test-tone`
pub async fn test_tone(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    if ptt(&app)?.test_tone().await {
        Ok(no_store(StatusCode::NO_CONTENT))
    } else {
        Err(ApiError::unavailable("no_audio_device", "This device has no speaker the hub can use."))
    }
}

/// What a failed key answers: 503 when talk is not possible here, 409 `ptt_busy` with the
/// talker when the floor is taken.
fn key_error(error: KeyError) -> Response {
    match error {
        KeyError::Unavailable(message) => axum::response::IntoResponse::into_response(ApiError::unavailable("ptt_unavailable", message)),
        KeyError::Busy(talker) => {
            let message = match &talker {
                Some(talker) if !talker.codename.is_empty() => format!("{} is talking.", talker.codename),
                Some(_) => "Someone else is talking.".to_owned(),
                // Voice was heard in the last 300 ms, and its talker is gone.
                None => "The channel is busy: someone has just talked. Try again.".to_owned(),
            };
            no_store((StatusCode::CONFLICT, axum::Json(json!({ "code": "ptt_busy", "message": message, "talker": talker }))))
        }
    }
}

/// `GET /ptt/devices`: the sound card's capture and playback devices.
pub async fn devices(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    ptt(&app)?;
    let (capture, playback) = tokio::task::spawn_blocking(crate::ptt::mixer::devices).await.unwrap_or_default();
    Ok(no_store(axum::Json(json!({ "capture": capture, "playback": playback }))))
}

/// `POST /ptt/key`: talk from the device microphone; repeated while held.
pub async fn key(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    Ok(match ptt(&app)?.key_device().await {
        Ok(()) => no_store(StatusCode::NO_CONTENT),
        Err(error) => key_error(error),
    })
}

/// `POST /ptt/unkey`: stop talking from the device microphone, or a test transmission.
pub async fn unkey(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    let ptt = ptt(&app)?;
    ptt.unkey(Source::Device).await;
    ptt.unkey(Source::Test).await;
    Ok(no_store(StatusCode::NO_CONTENT))
}

/// `GET /ptt/test/wav`: the test recording, or null.
pub async fn test_wav(State(app): State<App>, _: Viewer) -> ApiResult<Response> {
    ptt(&app)?;
    Ok(no_store(axum::Json(wav::stored(&app.config.state_dir))))
}

/// `PUT /ptt/test/wav`: a WAV to transmit as a test (stored at 16 kHz mono).
pub async fn put_test_wav(State(app): State<App>, _: Admin, body: Bytes) -> ApiResult<Response> {
    ptt(&app)?;
    if body.len() > wav::MAX_BYTES {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "Use a WAV file of at most 32 MiB."));
    }
    let dir = app.config.state_dir.clone();
    let stored = tokio::task::spawn_blocking(move || wav::store(&dir, &body)).await.map_err(|_| ApiError::internal())?;
    let stored = stored.map_err(|why| ApiError::field("file", format!("This is not a WAV file the hub can play: {why}.")))?;
    Ok(no_store(axum::Json(stored)))
}

/// `DELETE /ptt/test/wav`
pub async fn delete_test_wav(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    ptt(&app)?;
    wav::remove(&app.config.state_dir);
    Ok(no_store(StatusCode::NO_CONTENT))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTxBody {
    source: String,
    #[serde(default)]
    r#loop: bool,
}

/// `POST /ptt/test/tx`: the recording or the test signal, as a burst to every node.
pub async fn test_tx(State(app): State<App>, _: Admin, Json(body): Json<TestTxBody>) -> ApiResult<Response> {
    let ptt = ptt(&app)?;
    let signal = match body.source.as_str() {
        "tone" => wav::tone_signal(),
        "wav" => {
            let dir = app.config.state_dir.clone();
            match tokio::task::spawn_blocking(move || wav::load(&dir)).await.ok().flatten() {
                Some(signal) => signal,
                None => return Ok(no_store((StatusCode::CONFLICT, axum::Json(json!({ "code": "no_recording", "message": "Upload a test recording first." }))))),
            }
        }
        _ => return Err(ApiError::field("source", "Use wav or tone.")),
    };
    Ok(match ptt.test_tx(signal, body.r#loop).await {
        Ok(()) => no_store(StatusCode::NO_CONTENT),
        Err(error) => key_error(error),
    })
}

/// `POST /ptt/test/tx/stop`
pub async fn stop_test_tx(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    ptt(&app)?.unkey(Source::Test).await;
    Ok(no_store(StatusCode::NO_CONTENT))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionBody {
    transport: String,
}

/// `POST /ptt/sessions`: a UDP session in the old plugin's protocol.
pub async fn create_session(State(app): State<App>, Admin(caller): Admin, Json(body): Json<SessionBody>) -> ApiResult<Response> {
    if body.transport != "udp" {
        return Err(ApiError::field("transport", "Only udp is offered."));
    }
    let ptt = ptt(&app)?;
    let port = ptt.udp.port().ok_or_else(|| ApiError::unavailable("ptt_unavailable", "The UDP session port is not open."))?;
    let token = ptt.udp.create(caller.token_hash).ok_or_else(|| ApiError::unavailable("too_many_sessions", "Too many audio sessions are open."))?;
    let session = json!({
        "token": format!("{token:08x}"),
        "transport": "udp",
        "udp_port": port,
        "format": "pcm_s16le_mono",
        "sample_rate_hz": 16000,
        "frame_ms": 20,
        "samples_per_frame": crate::ptt::opus::FRAME_SAMPLES,
        "keepalive_interval_ms": udp::KEEPALIVE_INTERVAL_MS,
        "unkey_timeout_ms": udp::UNKEY_TIMEOUT_MS,
    });
    Ok(no_store((StatusCode::CREATED, axum::Json(session))))
}

/// `GET /ptt/audio`: the browser's talk and listen socket.
pub async fn audio(State(app): State<App>, headers: HeaderMap, upgrade: WebSocketUpgrade) -> ApiResult<Response> {
    // Browsers do not apply CORS to WebSockets: this check is what stops another site.
    auth::check_origin(&headers)?;
    if headers.get(axum::http::header::ORIGIN).is_none() && !app.config.dev {
        return Err(ApiError::forbidden("forbidden", "Open the audio socket from the device's own page."));
    }
    let caller = auth::current(&app, &headers).await?.ok_or_else(|| ApiError::unauthenticated("Sign in to continue."))?;
    let ptt = ptt(&app)?;
    Ok(upgrade.max_message_size(MAX_MESSAGE).on_upgrade(move |socket| serve(app, ptt, caller, socket)))
}

#[derive(Deserialize)]
struct Op {
    op: String,
    /// For `listen`: false stops listening.
    on: Option<bool>,
}

static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);

async fn send_json(socket: &mut WebSocket, value: serde_json::Value) -> bool {
    ws_send(socket, Message::Text(value.to_string().into())).await
}

async fn serve(app: App, ptt: Arc<Ptt>, caller: auth::Caller, mut socket: WebSocket) {
    let source = Source::Browser(NEXT_SOCKET.fetch_add(1, Ordering::Relaxed));
    let mut listening = false;
    let mut played = ptt.listen();
    let mut control = ptt.control();
    let mut ping = tokio::time::interval(PING_EVERY);
    let mut session = tokio::time::interval(SESSION_CHECK);
    let mut last_heard = tokio::time::Instant::now();
    loop {
        tokio::select! {
            message = socket.recv() => {
                let Some(Ok(message)) = message else { break };
                last_heard = tokio::time::Instant::now();
                match message {
                    Message::Binary(data) => {
                        if let Some(frame) = udp::pcm(&data) {
                            ptt.audio(source, frame);
                        }
                    }
                    Message::Text(text) => {
                        let (op, on) = serde_json::from_str::<Op>(&text).map(|op| (op.op, op.on)).unwrap_or_default();
                        let answered = match op.as_str() {
                            "listen" if on == Some(false) => {
                                listening = false;
                                true
                            }
                            "listen" => {
                                listening = true;
                                send_json(&mut socket, json!({ "type": "talker", "talker": ptt.talker() })).await
                            }
                            "key" if caller.role != Role::Admin => send_json(&mut socket, json!({ "type": "unkeyed", "reason": "forbidden" })).await,
                            "key" => match ptt.key(source).await {
                                Ok(()) => send_json(&mut socket, json!({ "type": "keyed" })).await,
                                Err(talker) => send_json(&mut socket, json!({ "type": "busy", "talker": talker })).await,
                            },
                            "unkey" => {
                                ptt.unkey(source).await;
                                true
                            }
                            _ => {
                                let _ = ws_send(&mut socket, Message::Close(Some(CloseFrame { code: 1008, reason: "invalid op".into() }))).await;
                                break;
                            }
                        };
                        if !answered {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            frame = played.recv(), if listening => match frame {
                Ok(frame) => {
                    let bytes: Vec<u8> = frame.iter().flat_map(|sample| sample.to_le_bytes()).collect();
                    if !ws_send(&mut socket, Message::Binary(bytes.into())).await {
                        break;
                    }
                }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            },
            event = control.recv() => match event {
                Ok(Control::Unkeyed { source: unkeyed, reason }) if unkeyed == source => {
                    if !send_json(&mut socket, json!({ "type": "unkeyed", "reason": reason })).await {
                        break;
                    }
                }
                Ok(Control::Talker(talker)) => {
                    if !send_json(&mut socket, json!({ "type": "talker", "talker": talker })).await {
                        break;
                    }
                }
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            },
            _ = ping.tick() => {
                if last_heard.elapsed() > SILENCE_LIMIT || !ws_send(&mut socket, Message::Ping(Vec::new().into())).await {
                    break;
                }
            }
            _ = session.tick() => {
                let hash = caller.token_hash.clone();
                let now = crate::clock::now();
                let alive = app.store.call(move |c| kaonic_store::sessions::find_and_touch(c, &hash, now)).await.ok().flatten().is_some();
                if !alive {
                    let _ = ws_send(&mut socket, Message::Close(Some(CloseFrame { code: 4401, reason: "session ended".into() }))).await;
                    break;
                }
            }
        }
    }
    // A socket that goes away does not keep the floor.
    ptt.unkey(source).await;
}
