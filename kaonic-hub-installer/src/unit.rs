//! The plugin's systemd unit, written by the installer. Packages carry no unit: what a
//! plugin may set is the manifest's few keys, and everything else is fixed here.
//!
//! A plugin runs as its own numeric uid and gid (from [`crate::records::UIDS`], no user
//! entry), sandboxed, with write access to its `data/` (and `run/`, for its page socket)
//! only. Permissions in the manifest add groups and limits.

use std::fmt::Write as _;

use crate::installer::Paths;
use crate::manifest::{Manifest, Permission, Restart};

/// The unit's file name.
pub fn name(id: &str) -> String {
    format!("kaonic-plugin-{id}.service")
}

pub const MARKER: &str = "# Written by kaonic-hub-installer. Changes here are overwritten.";

/// The unit for `manifest`, run as `uid` (ignored for a `root` plugin). The manifest must
/// have passed [`crate::manifest::validate`].
pub fn render(manifest: &Manifest, uid: u32, paths: &Paths) -> String {
    let id = &manifest.id;
    let dir = paths.plugin(id);
    let program = dir.join("current").join(manifest.program());
    let data = dir.join("data");
    let mut exec = quote(&program.to_string_lossy());
    for arg in &manifest.args {
        exec.push(' ');
        exec.push_str(&quote(arg));
    }

    let mut unit = String::new();
    let mut line = |text: &str| {
        unit.push_str(text);
        unit.push('\n');
    };
    line(MARKER);
    line("[Unit]");
    line(&format!("Description={}", escape_text(&manifest.name)));
    line("After=network.target kaonic-hub.service");
    line("");
    line("[Service]");
    line("Type=simple");
    line(&format!("ExecStart={exec}"));
    line(&format!("WorkingDirectory={}", quote(&data.to_string_lossy())));
    line(&format!("Environment=KAONIC_PLUGIN_ID={id}"));
    line(&format!("Environment={}", quote(&format!("KAONIC_PLUGIN_DIR={}", dir.to_string_lossy()))));
    line(&format!("Environment={}", quote(&format!("KAONIC_PLUGIN_TOKEN={}", dir.join("token").to_string_lossy()))));
    line(&format!("Environment={}", quote(&format!("KAONIC_HUB_API=unix:{}", paths.plugin_api_socket(id).to_string_lossy()))));
    if manifest.page {
        line(&format!("Environment={}", quote(&format!("KAONIC_PLUGIN_PAGE_SOCKET={}", paths.page_socket(id).to_string_lossy()))));
    }
    for (key, value) in &manifest.environment {
        line(&format!("Environment={}", quote(&format!("{key}={value}"))));
    }
    line(match manifest.restart {
        Restart::OnFailure => "Restart=on-failure",
        Restart::Always => "Restart=always",
        Restart::No => "Restart=no",
    });
    line(&format!("RestartSec={}", manifest.restart_sec));
    line(&format!("TimeoutStopSec={}", manifest.stop_timeout));
    if manifest.nice != 0 {
        line(&format!("Nice={}", manifest.nice));
    }
    if manifest.memory_max_mb != 0 {
        line(&format!("MemoryMax={}M", manifest.memory_max_mb));
    }
    if manifest.cpu_quota != 0 {
        line(&format!("CPUQuota={}%", manifest.cpu_quota));
    }
    if manifest.has(Permission::Root) {
        // Signed packages only (checked when the package is opened).
        line("User=root");
    } else {
        line(&format!("User={uid}"));
        line(&format!("Group={uid}"));
        line("NoNewPrivileges=yes");
        line("ProtectSystem=strict");
        line("ProtectHome=yes");
        line("PrivateTmp=yes");
        line(if manifest.has(Permission::Audio) { "PrivateDevices=no" } else { "PrivateDevices=yes" });
        line("ProtectKernelTunables=yes");
        line("ProtectKernelModules=yes");
        line("ProtectControlGroups=yes");
        line("RestrictSUIDSGID=yes");
        line("LockPersonality=yes");
        if manifest.page {
            line(&format!("ReadWritePaths={} {}", quote(&data.to_string_lossy()), quote(&dir.join("run").to_string_lossy())));
        } else {
            line(&format!("ReadWritePaths={}", quote(&data.to_string_lossy())));
        }
        line("UMask=0077");
        line("LimitNOFILE=256");
        line("TasksMax=64");
        if manifest.has(Permission::Audio) {
            line("SupplementaryGroups=audio");
        }
        if manifest.has(Permission::Realtime) {
            line("AmbientCapabilities=CAP_SYS_NICE CAP_IPC_LOCK");
            line("CapabilityBoundingSet=CAP_SYS_NICE CAP_IPC_LOCK");
            line("LimitRTPRIO=95");
            line("LimitMEMLOCK=infinity");
        } else {
            line("CapabilityBoundingSet=");
        }
        if !manifest.has(Permission::Network) {
            // Local sockets (the hub's plugin API, its page) and loopback only.
            line("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6");
            line("IPAddressAllow=localhost");
            line("IPAddressDeny=any");
        }
    }
    line("");
    line("[Install]");
    line("WantedBy=multi-user.target");
    unit
}

/// One argument, double-quoted for systemd: `\` and `"` escaped, `%` and `$` doubled so
/// systemd expands nothing.
fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", c as u32 & 0xff);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Free text on one line: control characters dropped, `\` made `/` (so no line ends in a
/// continuation), `%` doubled.
fn escape_text(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).map(|c| if c == '\\' { '/' } else { c }).collect::<String>().trim().replace('%', "%%")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest;

    fn paths() -> Paths {
        Paths::under(std::path::Path::new("/t"))
    }

    fn manifest(service: &str) -> Manifest {
        manifest::parse(&format!("[kaonic-plugin]\nformat = 2\nid = \"sample\"\nname = \"Sample 100%\"\nversion = \"1\"\ndeveloper = \"B\"\n[service]\n{service}")).unwrap()
    }

    #[test]
    fn a_plugin_runs_as_its_own_sandboxed_uid() {
        let unit = render(&manifest(""), 61_000, &paths());
        assert!(unit.starts_with(MARKER));
        assert!(unit.contains("\nUser=61000\nGroup=61000\n"));
        assert!(unit.contains("\nLimitNOFILE=256\nTasksMax=64\n"));
        assert!(unit.contains("\nEnvironment=\"KAONIC_HUB_API=unix:/t/run/plugins/sample.sock\"\n"));
        assert!(!unit.contains("KAONIC_PLUGIN_PAGE_SOCKET"));
        assert!(unit.contains("\nExecStart=\"/t/plugins/sample/current/bin/sample\"\n"));
        assert!(unit.contains("\nNoNewPrivileges=yes\n"));
        assert!(unit.contains("\nProtectSystem=strict\n"));
        assert!(unit.contains("\nReadWritePaths=\"/t/plugins/sample/data\"\n"));
        assert!(unit.contains("\nIPAddressDeny=any\n"));
        assert!(unit.contains("\nCapabilityBoundingSet=\n"));
        assert!(unit.contains("\nDescription=Sample 100%%\n"));
        assert!(unit.contains("\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=15\n"), "defaults");
        assert!(!unit.contains("MemoryMax") && !unit.contains("Nice="));
        assert!(!unit.contains("audio"));
    }

    #[test]
    fn permissions_add_only_what_they_name() {
        let unit = render(&manifest("permissions = \"audio realtime network\"\n"), 61_001, &paths());
        assert!(unit.contains("\nSupplementaryGroups=audio\n"));
        assert!(unit.contains("\nLimitRTPRIO=95\n"));
        assert!(unit.contains("\nPrivateDevices=no\n"));
        assert!(!unit.contains("IPAddressDeny"));
        assert!(unit.contains("\nUser=61001\n"), "still not root");
    }

    #[test]
    fn service_settings_become_unit_lines() {
        let unit = render(&manifest("permissions = \"realtime\"\nrestart = \"always\"\nrestart_sec = 2\nnice = -10\nmemory_max_mb = 64\ncpu_quota = 50\nenvironment = \"RUST_LOG=debug MODE=a%b\"\n"), 61_000, &paths());
        for expected in ["Restart=always", "RestartSec=2", "Nice=-10", "MemoryMax=64M", "CPUQuota=50%", "Environment=\"RUST_LOG=debug\"", "Environment=\"MODE=a%%b\""] {
            assert!(unit.lines().any(|line| line == expected), "{expected}\n{unit}");
        }
    }

    #[test]
    fn arguments_cannot_add_lines_or_expand_anything() {
        let unit = render(&manifest("args = '--a=\"x\" ;/bin/sh $HOME %h'\n"), 61_000, &paths());
        let exec = unit.lines().find(|line| line.starts_with("ExecStart=")).unwrap();
        assert_eq!(exec, r#"ExecStart="/t/plugins/sample/current/bin/sample" "--a=\"x\"" ";/bin/sh" "$$HOME" "%%h""#);
        assert_eq!(unit.lines().filter(|line| line.starts_with("Exec")).count(), 1);
    }

    #[test]
    fn a_page_gets_its_socket_directory() {
        let text = "[kaonic-plugin]\nformat = 2\nid = \"sample\"\nname = \"S\"\nversion = \"1\"\ndeveloper = \"B\"\npage = true\n";
        let unit = render(&manifest::parse(text).unwrap(), 61_000, &paths());
        assert!(unit.contains("\nEnvironment=\"KAONIC_PLUGIN_PAGE_SOCKET=/t/plugins/sample/run/page.sock\"\n"), "{unit}");
        assert!(unit.contains("\nReadWritePaths=\"/t/plugins/sample/data\" \"/t/plugins/sample/run\"\n"), "{unit}");
    }

    #[test]
    fn a_description_cannot_continue_onto_the_next_line() {
        let text = "[kaonic-plugin]\nformat = 2\nid = \"sample\"\nname = 'N \\'\nversion = \"1\"\ndeveloper = \"B\"\n";
        let unit = render(&manifest::parse(text).unwrap(), 61_000, &paths());
        assert!(unit.contains("\nDescription=N /\nAfter="), "{unit}");
        assert!(!unit.lines().any(|line| line.ends_with('\\')), "{unit}");
    }
}
