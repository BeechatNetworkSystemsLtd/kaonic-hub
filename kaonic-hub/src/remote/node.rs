//! The node's side: runs what its admin asks and hosts the admin's shells.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::proto::{self, Message};
use super::pty::Pty;
use super::stream::ByteStream;
use crate::app::App;
use crate::error::{ApiError, ApiResult};

/// Answers kept for repeated requests.
const CACHE: usize = 16;
/// Requests run at once; a request past this is dropped and runs on the admin's retry.
const MAX_RUNNING: usize = 4;
/// Shells open at once on this node.
const MAX_SHELLS: usize = 2;
/// A shell whose admin is not heard (not even its keepalive) for this long is closed.
const SILENCE: Duration = Duration::from_secs(60);
/// A shell nobody typed into for this long is closed.
const IDLE: Duration = Duration::from_secs(30 * 60);
/// Output is gathered for this long before it goes out: fewer, fuller radio frames.
const BATCH: Duration = Duration::from_millis(30);
pub(crate) const KEEPALIVE: Duration = Duration::from_secs(10);
/// Between the parts of a long answer.
const PART_GAP: Duration = Duration::from_millis(40);

/// One operation the admin can ask for; anything else is refused.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Op {
    // Empty braces, not unit variants: serde ignores unknown fields on a tagged unit variant.
    Info {},
    Codename { codename: String },
    Radio { band: String, config: Value },
    Ptt { settings: Value },
    Restart {},
    Reboot {},
    Update {},
}

enum Input {
    Data { offset: u32, ack: u32, bytes: Vec<u8> },
    Resize { cols: u16, rows: u16 },
    Close,
}

#[derive(Default)]
struct State {
    /// Requests running now, so a repeat does not run them twice.
    running: HashSet<(String, u32)>,
    /// Cached answers going out again now: a repeat meanwhile adds no task.
    sending: HashSet<(String, u32)>,
    answered: VecDeque<((String, u32), Vec<Message>)>,
    shells: HashMap<(String, u32), mpsc::Sender<Input>>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(Default::default);

/// What to do with a request from the admin.
enum Admit {
    /// Running, being answered, or too many running: nothing.
    Skip,
    Resend(Vec<Message>),
    Run,
}

impl State {
    fn admit(&mut self, key: &(String, u32)) -> Admit {
        if self.running.contains(key) || self.sending.contains(key) {
            return Admit::Skip;
        }
        if let Some((_, parts)) = self.answered.iter().find(|(known, _)| known == key) {
            let parts = parts.clone();
            self.sending.insert(key.clone());
            return Admit::Resend(parts);
        }
        if self.running.len() >= MAX_RUNNING {
            return Admit::Skip;
        }
        self.running.insert(key.clone());
        Admit::Run
    }
}

/// A cached answer being sent again; done when dropped.
struct Sending((String, u32));

impl Drop for Sending {
    fn drop(&mut self) {
        state().sending.remove(&self.0);
    }
}

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().expect("remote node lock")
}

/// When this hub started: a restart asked again right after one is the same request
/// repeated (its answer was lost with the old process), not a new one.
pub(super) static STARTED: LazyLock<Instant> = LazyLock::new(Instant::now);
const JUST_STARTED: Duration = Duration::from_secs(90);

/// Traffic for a shell already open (its admin was checked when it opened). True if taken.
pub(super) fn on_session_message(peer: &str, message: &Message) -> bool {
    let (session, input) = match message {
        Message::Data { session, offset, ack, bytes } => (*session, Input::Data { offset: *offset, ack: *ack, bytes: bytes.clone() }),
        Message::Resize { session, cols, rows } => (*session, Input::Resize { cols: *cols, rows: *rows }),
        Message::Close { session, .. } => (*session, Input::Close),
        _ => return false,
    };
    let sender = state().shells.get(&(peer.to_owned(), session)).cloned();
    match sender {
        Some(sender) => {
            // A full queue drops the message; the stream sends it again.
            let _ = sender.try_send(input);
            true
        }
        None => false,
    }
}

/// An order from our admin (already checked).
pub(super) async fn on_message(app: &App, peer: &str, message: Message) {
    match message {
        Message::Request { req, op } => {
            let key = (peer.to_owned(), req);
            let admitted = state().admit(&key);
            let (app, peer) = (app.clone(), peer.to_owned());
            match admitted {
                Admit::Skip => {}
                Admit::Resend(parts) => {
                    tokio::spawn(async move {
                        let _sending = Sending(key);
                        send_parts(&app, &peer, &parts).await;
                    });
                }
                Admit::Run => {
                    tokio::spawn(async move { answer(&app, &peer, req, &op).await });
                }
            }
        }
        Message::Open { session, cols, rows } => open(app, peer, session, cols, rows).await,
        // DATA, RESIZE or CLOSE for a shell that is gone: tell the admin it is closed.
        Message::Data { session, .. } | Message::Resize { session, .. } => {
            super::send(app, peer, &Message::Close { session, reason: "This shell is closed.".into() }).await;
        }
        _ => {}
    }
}

async fn answer(app: &App, peer: &str, req: u32, op: &[u8]) {
    let op = serde_json::from_slice::<Op>(op).map_err(|_| ApiError::bad_request("This node does not know that operation. Update it."));
    let label = op.as_ref().map(op_name).unwrap_or("unknown");
    let outcome = match op {
        Ok(op) => run(app, op).await,
        Err(error) => Err(error),
    };
    let (ok, body) = match &outcome {
        Ok(value) => (true, value.clone()),
        Err(error) => (false, json!({ "code": error.code, "message": error.message, "fields": error.fields })),
    };
    let detail = format!("{label} from {peer}: {}", if ok { "done" } else { "refused" });
    let now = crate::clock::now();
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "remote-admin", "remote.op", &detail)).await;
    let parts = proto::split_response(req, ok, &serde_json::to_vec(&body).unwrap_or_default());
    {
        let mut state = state();
        let key = (peer.to_owned(), req);
        state.running.remove(&key);
        state.answered.push_back((key, parts.clone()));
        while state.answered.len() > CACHE {
            state.answered.pop_front();
        }
    }
    send_parts(app, peer, &parts).await;
}

/// The parts of an answer, spaced out: a burst of full frames is lost on a busy or multi-hop
/// path, where relays and the air queue cannot take them all at once.
async fn send_parts(app: &App, peer: &str, parts: &[Message]) {
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            tokio::time::sleep(PART_GAP).await;
        }
        super::send(app, peer, part).await;
    }
}

fn op_name(op: &Op) -> &'static str {
    match op {
        Op::Info {} => "info",
        Op::Codename { .. } => "codename",
        Op::Radio { .. } => "radio",
        Op::Ptt { .. } => "ptt",
        Op::Restart {} => "restart",
        Op::Reboot {} => "reboot",
        Op::Update {} => "update",
    }
}

async fn run(app: &App, op: Op) -> ApiResult<Value> {
    match op {
        Op::Info {} => Ok(json!({
            "device": crate::api::device::device_json(app).await?,
            "metrics": app.metrics.read(&app.device, &app.config.state_dir),
            "bands": crate::api::radio_bands::all_bands(app).await,
            "ptt": app.ptt.get().map(|ptt| ptt.settings()),
        })),
        Op::Codename { codename } => {
            crate::api::device::set_codename_here(app, codename, "remote-admin").await?;
            crate::api::device::device_json(app).await
        }
        Op::Radio { band, config } => crate::api::radio_bands::apply_remote(app, &band, config).await,
        Op::Ptt { settings } => {
            let ptt = app.ptt.get().ok_or_else(|| ApiError::unavailable("ptt_unavailable", "Talk is not running on this node."))?;
            let patch: crate::ptt::SettingsPatch = serde_json::from_value(settings).map_err(|_| ApiError::bad_request("These talk settings are not valid."))?;
            let settings = patch.apply(ptt.settings()).map_err(|(field, message)| ApiError::field(field, message))?;
            ptt.set_settings(settings.clone()).await;
            Ok(serde_json::to_value(settings)?)
        }
        Op::Restart {} | Op::Reboot {} => {
            let reboot = matches!(op, Op::Reboot {});
            let just_started = if reboot { app.device.uptime_secs() < JUST_STARTED.as_secs() } else { STARTED.elapsed() < JUST_STARTED };
            if just_started {
                return Ok(json!({}));
            }
            log::warn!("remote: the admin asked for a {}", if reboot { "reboot" } else { "restart of the hub" });
            if !app.config.dev {
                // Answer first; the admin's repeats after this are answered by the new process.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    if reboot {
                        let _ = tokio::process::Command::new("systemctl").arg("reboot").status().await;
                    } else {
                        // systemd (Restart=always) starts the hub again.
                        std::process::exit(0);
                    }
                });
            }
            Ok(json!({}))
        }
        Op::Update {} => Err(ApiError::unavailable("not_available", "Updating other nodes over the mesh is not available in this release.")),
    }
}

fn shell() -> &'static str {
    if std::path::Path::new("/bin/bash").exists() { "/bin/bash" } else { "/bin/sh" }
}

async fn open(app: &App, peer: &str, session: u32, cols: u16, rows: u16) {
    let key = (peer.to_owned(), session);
    let (sender, input) = mpsc::channel(64);
    let refusal = {
        let mut state = state();
        if state.shells.contains_key(&key) {
            // A repeated OPEN: the first answer was lost.
            Some((true, String::new()))
        } else if state.shells.len() >= MAX_SHELLS {
            Some((false, format!("{MAX_SHELLS} shells are open on this node already.")))
        } else {
            state.shells.insert(key.clone(), sender);
            None
        }
    };
    if let Some((ok, message)) = refusal {
        super::send(app, peer, &Message::Opened { session, ok, message }).await;
        return;
    }
    let pty = match Pty::spawn(shell(), cols, rows) {
        Ok(pty) => pty,
        Err(error) => {
            log::error!("remote: could not start a shell: {error}");
            state().shells.remove(&key);
            super::send(app, peer, &Message::Opened { session, ok: false, message: "The node could not start a shell.".into() }).await;
            return;
        }
    };
    super::send(app, peer, &Message::Opened { session, ok: true, message: String::new() }).await;
    let (app, peer) = (app.clone(), peer.to_owned());
    tokio::spawn(async move {
        audit(&app, "remote.shell.open", &peer).await;
        log::warn!("remote: the admin {peer} opened a shell");
        let reason = serve(&app, &peer, session, pty, input).await;
        state().shells.remove(&(peer.clone(), session));
        super::send(&app, &peer, &Message::Close { session, reason: reason.into() }).await;
        audit(&app, "remote.shell.close", &format!("{peer}: {reason}")).await;
        log::info!("remote: the shell of {peer} closed: {reason}");
    });
}

async fn audit(app: &App, action: &'static str, detail: &str) {
    let (now, detail) = (crate::clock::now(), detail.to_owned());
    let _ = app.store.call(move |c| kaonic_store::audit::record(c, now, "remote-admin", action, &detail)).await;
}

/// Bridges the shell and the admin until either ends; returns why.
async fn serve(app: &App, peer: &str, session: u32, pty: Pty, mut input: mpsc::Receiver<Input>) -> &'static str {
    let mut stream = ByteStream::default();
    let mut tick = tokio::time::interval(BATCH);
    let mut buffer = [0u8; 2048];
    let (mut heard, mut typed, mut sent) = (Instant::now(), Instant::now(), Instant::now());
    let mut ended: Option<(&'static str, Instant)> = None;
    loop {
        tokio::select! {
            read = pty.read(&mut buffer), if ended.is_none() && stream.room() >= buffer.len() => match read {
                Ok(n) => {
                    stream.push(&buffer[..n]);
                }
                Err(_) => ended = Some(("The shell ended.", Instant::now())),
            },
            message = input.recv() => match message {
                Some(Input::Data { offset, ack, bytes }) => {
                    heard = Instant::now();
                    stream.on_ack(ack, Instant::now());
                    let fresh = stream.on_data(offset, &bytes);
                    if !fresh.is_empty() && ended.is_none() {
                        typed = Instant::now();
                        if pty.write(&fresh).await.is_err() {
                            ended = Some(("The shell ended.", Instant::now()));
                        }
                    }
                }
                Some(Input::Resize { cols, rows }) => pty.resize(cols, rows),
                Some(Input::Close) | None => return "Closed by the admin.",
            },
            _ = tick.tick() => {
                for (offset, bytes) in stream.poll(Instant::now()) {
                    super::send(app, peer, &Message::Data { session, offset, ack: stream.ack(), bytes }).await;
                    sent = Instant::now();
                }
                if sent.elapsed() >= KEEPALIVE {
                    super::send(app, peer, &Message::Data { session, offset: 0, ack: stream.ack(), bytes: Vec::new() }).await;
                    sent = Instant::now();
                }
                if heard.elapsed() >= SILENCE {
                    return "The admin was not heard for a minute.";
                }
                if typed.elapsed() >= IDLE {
                    return "Closed after 30 minutes without input.";
                }
                // The shell is gone: its last output is delivered (for a while) before closing.
                if let Some((reason, at)) = ended
                    && (stream.idle() || at.elapsed() >= Duration::from_secs(10))
                {
                    return reason;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_operations_with_exact_fields_are_accepted() {
        assert!(matches!(serde_json::from_str::<Op>(r#"{"op":"info"}"#), Ok(Op::Info {})));
        assert!(matches!(serde_json::from_str::<Op>(r#"{"op":"codename","codename":"abcd1234"}"#), Ok(Op::Codename { .. })));
        assert!(serde_json::from_str::<Op>(r#"{"op":"shell","command":"rm -rf /"}"#).is_err());
        assert!(serde_json::from_str::<Op>(r#"{"op":"restart","now":true}"#).is_err());
        assert!(serde_json::from_str::<Op>(r#"{"op":"codename"}"#).is_err());
    }

    #[test]
    fn a_repeated_request_adds_no_work_and_running_ones_are_capped() {
        let mut state = State::default();
        let key = |req| ("admin".to_owned(), req);
        assert!(matches!(state.admit(&key(1)), Admit::Run));
        assert!(matches!(state.admit(&key(1)), Admit::Skip), "a repeat while it runs");
        for req in 2..MAX_RUNNING as u32 + 1 {
            assert!(matches!(state.admit(&key(req)), Admit::Run));
        }
        assert!(matches!(state.admit(&key(99)), Admit::Skip), "past the cap");
        // Answered: a repeat sends the answer again, once at a time.
        state.running.remove(&key(1));
        state.answered.push_back((key(1), Vec::new()));
        assert!(matches!(state.admit(&key(1)), Admit::Resend(_)));
        assert!(matches!(state.admit(&key(1)), Admit::Skip), "a repeat while the answer goes out");
        state.sending.remove(&key(1));
        assert!(matches!(state.admit(&key(1)), Admit::Resend(_)));
        assert!(matches!(state.admit(&key(99)), Admit::Run), "a slot came free");
    }
}
