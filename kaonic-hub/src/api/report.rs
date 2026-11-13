//! `GET /system/report`: everything about this device's Kaonic software and OS, as plain
//! text to paste into a support request. No secrets: no keys, tokens, passwords or Wi-Fi
//! names; the serial and node identity hash are in it, so it is for the admin only.

use std::fmt::Write as _;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use super::no_store;
use crate::app::App;
use crate::auth::Admin;
use crate::error::ApiResult;

pub async fn get(State(app): State<App>, _: Admin) -> ApiResult<Response> {
    let text = report(&app).await;
    Ok(no_store(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text)).into_response())
}

/// One `name: value` line, padded so the values line up.
fn line(out: &mut String, name: &str, value: impl std::fmt::Display) {
    let _ = writeln!(out, "  {name:<30} {value}");
}

/// A JSON value as indented `key: value` lines (for views that already exist).
fn flatten(out: &mut String, prefix: &str, value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                let name = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
                flatten(out, &name, value);
            }
        }
        serde_json::Value::Array(items) if items.iter().all(|item| !item.is_object()) => {
            let joined: Vec<String> = items.iter().map(|item| item.to_string().trim_matches('"').to_owned()).collect();
            line(out, prefix, joined.join(", "));
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                flatten(out, &format!("{prefix}[{index}]"), item);
            }
        }
        serde_json::Value::Null => line(out, prefix, "–"),
        serde_json::Value::String(text) => line(out, prefix, text),
        other => line(out, prefix, other),
    }
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS UTC`.
fn utc(secs: i64) -> String {
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC", rest / 3600, rest / 60 % 60, rest % 60)
}

fn duration(secs: u64) -> String {
    let (days, hours, minutes) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60);
    if days > 0 { format!("{days} d {hours} h {minutes} min") } else { format!("{hours} h {minutes} min") }
}

async fn report(app: &App) -> String {
    let mut out = String::from("Kaonic system report\n");
    let _ = writeln!(out, "  {:<30} {} (Unix {})", "Generated", utc(crate::clock::now()), crate::clock::now());

    out.push_str("\nDevice\n");
    match super::device::device_json(app).await {
        Ok(device) => {
            for (name, key) in [("Model", "model"), ("Serial", "serial"), ("Codename", "codename"), ("Hostname", "hostname"), ("Node identity", "identity_hash")] {
                line(&mut out, name, device[key].as_str().unwrap_or("–"));
            }
            line(&mut out, "Admin device", if device["is_admin"].as_bool() == Some(true) { "yes" } else { "no" });
        }
        Err(error) => line(&mut out, "Device", format!("unavailable ({})", error.message)),
    }
    line(&mut out, "Uptime", duration(app.device.uptime_secs()));

    out.push_str("\nKaonic software\n");
    let from_update = std::env::var("KAONIC_CORE_EXEC").is_ok_and(|value| value == "kaonic-hub");
    line(&mut out, "Hub", format!("{} ({})", env!("CARGO_PKG_VERSION"), if from_update { "updated copy" } else { "system image" }));
    line(&mut out, "Hub commit", env!("KAONIC_HUB_COMMIT"));
    line(&mut out, "Hub API", super::device::API_VERSION);
    line(&mut out, "Web UI", app.config.webui.version().unwrap_or_else(|| "not built in".into()));
    let installer = &app.plugins().installer;
    line(&mut out, "Plugin installer", installer.health().await.unwrap_or_else(|failure| format!("not reachable ({})", failure.message)));
    match installer.policy_view().await {
        Ok(policy) => {
            let key = policy.get("release_key").and_then(serde_json::Value::as_bool);
            line(&mut out, "Release key", match key {
                Some(true) => "yes",
                Some(false) => "no (development device: packages install unsigned)",
                None => "unknown",
            });
            line(&mut out, "Signed plugins only", policy.get("require_signed").and_then(serde_json::Value::as_bool).map_or("unknown", |on| if on { "yes" } else { "no" }));
        }
        Err(_) => line(&mut out, "Release key", "unknown"),
    }
    if let Ok(core) = installer.core().await {
        for status in core.as_array().into_iter().flatten() {
            let id = status["id"].as_str().unwrap_or("?");
            let updated = &status["updated"];
            let text = if updated.is_null() {
                "none (the image's copy runs)".to_owned()
            } else {
                format!(
                    "{}{}{}, failed starts {}",
                    updated["version"].as_str().unwrap_or("?"),
                    if updated["confirmed"].as_bool() == Some(true) { ", confirmed" } else { ", on trial" },
                    if updated["signed"].as_bool() == Some(true) { ", signed" } else { ", unsigned" },
                    status["attempts"],
                )
            };
            line(&mut out, &format!("Updated {id}"), text);
        }
    }
    if let Ok(Some(job)) = installer.hub_job().await {
        line(&mut out, "Last hub update", format!("{} {:?}: {}", job.version, job.state, job.message).to_lowercase());
    }

    out.push_str("\nOS\n");
    line(&mut out, "OS", app.device.os_name().unwrap_or_else(|| app.device.os_version()));
    line(&mut out, "OS version", app.device.os_version());
    line(&mut out, "Kernel", app.device.kernel().unwrap_or_else(|| "unknown".into()));
    line(&mut out, "Board", app.device.machine().unwrap_or_else(|| "unknown".into()));
    line(&mut out, "Architecture", std::env::consts::ARCH);
    match super::boot::read_status(app, false).await {
        Ok(boot) => flatten(&mut out, "boot", &serde_json::to_value(&boot).unwrap_or_default()),
        Err(error) => line(&mut out, "boot", format!("unavailable ({})", error.message)),
    }
    let metrics = app.metrics.read(&app.device, &app.config.state_dir);
    flatten(&mut out, "", &serde_json::to_value(&metrics).unwrap_or_default());

    out.push_str("\nServices\n");
    for unit in ["kaonic-hub.service", "kaonic-hub-installer.service", "kaonic-commd.service"] {
        line(&mut out, unit, service_state(unit).await);
    }

    out.push_str("\nMesh\n");
    match &app.mesh {
        Some(mesh) => {
            line(&mut out, "Radio", &app.config.radio);
            line(&mut out, "Peers heard", mesh.peers().len());
        }
        None => line(&mut out, "Radio", "not running"),
    }
    match app.links.get() {
        Some(links) => line(&mut out, "Secure links up", links.established().len()),
        None => line(&mut out, "Secure links", "not running"),
    }
    line(&mut out, "VPN", if app.vpn.get().is_some() { "running" } else { "off" });

    out.push_str("\nPlugins\n");
    match app.plugins().list().await {
        Ok(plugins) if plugins.is_empty() => line(&mut out, "Plugins", "none"),
        Ok(plugins) => {
            for plugin in plugins.iter() {
                let manifest = &plugin.record.manifest;
                let permissions: Vec<String> = manifest.permissions.iter().map(|permission| format!("{permission:?}").to_lowercase()).collect();
                line(
                    &mut out,
                    &manifest.id,
                    format!(
                        "{} {}, {}{}{}",
                        manifest.version,
                        if plugin.record.signed { "signed" } else { "unsigned" },
                        if plugin.running { "running" } else if plugin.record.enabled { "NOT RUNNING" } else { "stopped" },
                        if permissions.is_empty() { String::new() } else { format!(", permissions {}", permissions.join(" ")) },
                        plugin.record.previous.as_ref().map(|previous| format!(", previous {}", previous.manifest.version)).unwrap_or_default(),
                    ),
                );
            }
        }
        Err(failure) => line(&mut out, "Plugins", format!("unavailable ({})", failure.message)),
    }
    out
}

/// What systemd says about a unit: its state and, when it has one, since when.
async fn service_state(unit: &str) -> String {
    let output = tokio::process::Command::new("systemctl").args(["show", "-p", "ActiveState", "-p", "SubState", "--value", unit]).output().await;
    match output {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = text.lines().map(str::trim).filter(|part| !part.is_empty()).collect();
            if parts.is_empty() { "unknown".into() } else { parts.join(" / ") }
        }
        _ => "unknown (no systemctl)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_durations_read_plainly() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_794_571_445), "2026-11-13 12:04:05 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(duration(90_061), "1 d 1 h 1 min");
        assert_eq!(duration(3_660), "1 h 1 min");
    }

    #[test]
    fn views_flatten_to_lines() {
        let mut out = String::new();
        flatten(&mut out, "boot", &serde_json::json!({ "current": "a", "order": ["a", "b"], "slots": [{ "kernel": "6.1" }], "next": null }));
        assert!(out.contains("boot.current"));
        assert!(out.contains("a, b"));
        assert!(out.contains("boot.slots[0].kernel"));
        assert!(out.contains("–"));
    }
}
