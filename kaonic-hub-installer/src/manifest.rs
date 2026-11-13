//! `kaonic-plugin.toml`: what a plugin is, and how it runs.
//!
//! ```toml
//! [kaonic-plugin]
//! format = 2
//! id = "audio-ptt"
//! name = "Audio PTT"
//! description = "Push-to-talk over the mesh"
//! version = "0.3.0"
//! developer = "Beechat Network Systems Ltd"
//! channel = "stable"                 # dev, experimental, unstable, stable
//! url = "https://github.com/..."
//! page = true                        # it serves a page on <plugins>/<id>/run/page.sock, shown at /apps/<id>/
//! icon = "files/icon.png"
//! command = true                     # a /usr/bin/<id> link to the program; ids starting with kaonic- only
//!
//! [service]                          # all optional; the defaults are shown
//! args = ""                          # program arguments, split at spaces
//! environment = ""                   # "KEY=value KEY2=value"
//! permissions = ""                   # audio realtime mesh network root
//! restart = "on-failure"             # on-failure, always, no
//! restart_sec = 5
//! stop_timeout = 15                  # seconds to stop before it is killed
//! nice = 0                           # -20..19; below 0 needs realtime
//! memory_max_mb = 0                  # 0: no limit
//! cpu_quota = 0                      # percent of one core; 0: no limit
//! ```
//!
//! Packages carry no systemd unit: the installer writes it from these keys ([`crate::unit`]).
//! Strings, integers and booleans only, read by the small parser here; anything else, and
//! any unknown key or table, is refused. [`validate`] holds every rule, so a manifest read
//! back from a record is checked the same way.

use std::collections::HashMap;

use crate::Error;
use crate::names::{self, Version};

pub const FILE: &str = "kaonic-plugin.toml";

/// Extra rights a plugin asks for; the admin sees them at install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// Sound devices (the `audio` group).
    Audio,
    /// Real-time scheduling and locked memory, for voice.
    Realtime,
    /// The mesh bridge in the hub.
    Mesh,
    /// Network access beyond loopback.
    Network,
    /// Runs as root. Signed packages only.
    Root,
}

impl Permission {
    fn parse(word: &str) -> Result<Self, Error> {
        Ok(match word {
            "audio" => Self::Audio,
            "realtime" => Self::Realtime,
            "mesh" => Self::Mesh,
            "network" => Self::Network,
            "root" => Self::Root,
            _ => return Err(Error::invalid(format!("unknown permission {word:?} (audio, realtime, mesh, network, root)"))),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Restart {
    OnFailure,
    Always,
    No,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub developer: String,
    pub channel: Option<String>,
    pub url: Option<String>,
    pub args: Vec<String>,
    pub permissions: Vec<Permission>,
    /// It serves a web page on `<plugins>/<id>/run/page.sock`.
    pub page: bool,
    pub icon: Option<String>,
    pub command: bool,
    pub restart: Restart,
    pub restart_sec: u32,
    pub stop_timeout: u32,
    pub environment: Vec<(String, String)>,
    pub nice: i8,
    pub memory_max_mb: u32,
    pub cpu_quota: u32,
}

impl Manifest {
    pub fn version(&self) -> Version {
        Version::parse(&self.version).expect("checked when parsed")
    }
    pub fn has(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }
    /// The program, relative to the package root.
    pub fn program(&self) -> String {
        format!("bin/{}", self.id)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Text(String),
    Int(i64),
    Bool(bool),
}

pub fn parse(text: &str) -> Result<Manifest, Error> {
    let (mut plugin, mut service) = tables(text)?;
    match plugin.remove("format") {
        Some(Value::Int(2)) => {}
        None | Some(_) => return Err(Error::invalid(format!("{FILE} needs format = 2 (this is a format 2 installer)"))),
    }
    let id = take_text(&mut plugin, "id")?;
    let name = take_text(&mut plugin, "name")?;
    let description = take_text(&mut plugin, "description")?;
    let version = take_text(&mut plugin, "version")?;
    let developer = take_text(&mut plugin, "developer")?;
    let channel = take_text(&mut plugin, "channel")?.map(|channel| channel.to_ascii_lowercase());
    let url = take_text(&mut plugin, "url")?;
    let icon = take_text(&mut plugin, "icon")?;
    let page = take_flag(&mut plugin, "page")?;
    let command = take_flag(&mut plugin, "command")?;

    let args = take_text(&mut service, "args")?;
    let environment = take_text(&mut service, "environment")?;
    let permissions = take_text(&mut service, "permissions")?;
    let restart = take_text(&mut service, "restart")?;
    let restart_sec = take_int(&mut service, "restart_sec", 5, 1..=3600)? as u32;
    let stop_timeout = take_int(&mut service, "stop_timeout", 15, 1..=300)? as u32;
    let nice = take_int(&mut service, "nice", 0, -20..=19)? as i8;
    let memory_max_mb = take_int(&mut service, "memory_max_mb", 0, 16..=4096)? as u32;
    let cpu_quota = take_int(&mut service, "cpu_quota", 0, 1..=400)? as u32;
    for (table, keys) in [("kaonic-plugin", &plugin), ("service", &service)] {
        if let Some(key) = keys.keys().next() {
            return Err(Error::invalid(format!("{FILE}: unknown key {key} in [{table}]")));
        }
    }

    let required = |key: &str, value: Option<String>| value.ok_or_else(|| Error::invalid(format!("{FILE} needs {key}")));
    let mut permissions = match permissions {
        None => Vec::new(),
        Some(words) => words.split_whitespace().map(Permission::parse).collect::<Result<Vec<_>, _>>()?,
    };
    permissions.sort();
    permissions.dedup();
    let environment = match environment {
        None => Vec::new(),
        Some(pairs) => pairs.split_whitespace().map(env_pair).collect::<Result<Vec<_>, _>>()?,
    };
    let manifest = Manifest {
        id: names::path_id(&required("id", id)?)?.to_owned(),
        name: required("name", name)?,
        description: description.unwrap_or_default(),
        version: required("version", version)?,
        developer: required("developer", developer)?,
        channel,
        url,
        args: args.map(|args| args.split_whitespace().map(str::to_owned).collect()).unwrap_or_default(),
        permissions,
        page,
        icon,
        command,
        restart: match restart.as_deref() {
            None | Some("on-failure") => Restart::OnFailure,
            Some("always") => Restart::Always,
            Some("no") => Restart::No,
            Some(_) => return Err(Error::invalid("restart must be on-failure, always or no")),
        },
        restart_sec,
        stop_timeout,
        environment,
        nice,
        memory_max_mb,
        cpu_quota,
    };
    validate(&manifest)?;
    Ok(manifest)
}

fn take_text(table: &mut HashMap<String, Value>, key: &str) -> Result<Option<String>, Error> {
    match table.remove(key) {
        None => Ok(None),
        Some(Value::Text(value)) => Ok(Some(value.trim().to_owned()).filter(|value| !value.is_empty())),
        Some(_) => Err(Error::invalid(format!("{key} in {FILE} must be a string"))),
    }
}

fn take_flag(table: &mut HashMap<String, Value>, key: &str) -> Result<bool, Error> {
    match table.remove(key) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(value),
        Some(_) => Err(Error::invalid(format!("{key} in {FILE} must be true or false"))),
    }
}

/// An integer in `range`, or `default` when absent (0 means "not set" where the range
/// leaves it out).
fn take_int(table: &mut HashMap<String, Value>, key: &str, default: i64, range: std::ops::RangeInclusive<i64>) -> Result<i64, Error> {
    match table.remove(key) {
        None => Ok(default),
        Some(Value::Int(0)) if default == 0 => Ok(0),
        Some(Value::Int(value)) if range.contains(&value) => Ok(value),
        Some(_) => Err(Error::invalid(format!("{key} in {FILE} must be a number from {} to {}", range.start(), range.end()))),
    }
}

fn env_pair(pair: &str) -> Result<(String, String), Error> {
    let (key, value) = pair.split_once('=').ok_or_else(|| Error::invalid(format!("environment: {pair:?} is not KEY=value")))?;
    env_ok(key, value)?;
    Ok((key.to_owned(), value.to_owned()))
}

/// `KEY=value`: an upper-case name not starting with KAONIC_ (those are the installer's),
/// and a value without spaces or control characters.
fn env_ok(key: &str, value: &str) -> Result<(), Error> {
    let key_ok = !key.is_empty()
        && key.len() <= 64
        && !key.as_bytes()[0].is_ascii_digit()
        && key.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && !key.starts_with("KAONIC_")
        && !matches!(key, "LD_PRELOAD" | "LD_LIBRARY_PATH" | "LD_AUDIT" | "PATH");
    if !key_ok || value.len() > 200 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Error::invalid(format!("environment: {key} cannot be set")));
    }
    Ok(())
}

/// Every rule a manifest must meet. [`parse`] calls it; so does the installer for a
/// manifest read back from a record, before it writes a unit from it.
pub fn validate(manifest: &Manifest) -> Result<(), Error> {
    names::path_id(&manifest.id)?;
    if manifest.name.is_empty() || manifest.developer.is_empty() {
        return Err(Error::invalid(format!("{FILE} needs a name and a developer")));
    }
    for (key, value, max) in [
        ("name", &manifest.name, 80),
        ("description", &manifest.description, 1000),
        ("developer", &manifest.developer, 120),
    ] {
        if value.chars().count() > max || value.chars().any(char::is_control) {
            return Err(Error::invalid(format!("{key} in {FILE} is too long or has control characters")));
        }
    }
    Version::parse(&manifest.version)?;
    if let Some(channel) = &manifest.channel
        && !matches!(channel.as_str(), "dev" | "experimental" | "unstable" | "stable")
    {
        return Err(Error::invalid("channel must be dev, experimental, unstable or stable"));
    }
    if let Some(url) = &manifest.url
        && (!url.starts_with("https://") || url.len() > 300 || url.chars().any(|c| c.is_control() || c.is_whitespace()))
    {
        return Err(Error::invalid("url must be an https address"));
    }
    if manifest.args.len() > 32
        || manifest.args.iter().any(|arg| arg.is_empty() || arg.len() > 200 || arg.chars().any(|c| c.is_control() || c.is_whitespace()))
    {
        return Err(Error::invalid("args: at most 32 arguments of 200 characters, no control characters"));
    }
    let ranges: [(&str, i64, std::ops::RangeInclusive<i64>); 5] = [
        ("restart_sec", manifest.restart_sec.into(), 1..=3600),
        ("stop_timeout", manifest.stop_timeout.into(), 1..=300),
        ("nice", manifest.nice.into(), -20..=19),
        ("memory_max_mb", manifest.memory_max_mb.into(), 16..=4096),
        ("cpu_quota", manifest.cpu_quota.into(), 1..=400),
    ];
    for (key, value, range) in ranges {
        let unset = value == 0 && matches!(key, "nice" | "memory_max_mb" | "cpu_quota");
        if !unset && !range.contains(&value) {
            return Err(Error::invalid(format!("{key} must be a number from {} to {}", range.start(), range.end())));
        }
    }
    if manifest.environment.len() > 32 {
        return Err(Error::invalid("environment: at most 32 variables"));
    }
    for (key, value) in &manifest.environment {
        env_ok(key, value)?;
    }
    if manifest.command && !manifest.id.starts_with("kaonic-") {
        return Err(Error::invalid("command = true needs an id starting with kaonic- (the link is /usr/bin/<id>)"));
    }
    if manifest.nice < 0 && !manifest.has(Permission::Realtime) {
        return Err(Error::invalid("a nice value below 0 needs the realtime permission"));
    }
    if let Some(icon) = &manifest.icon {
        let inside = icon.strip_prefix("files/").ok_or_else(|| Error::invalid("icon must be a file under files/"))?;
        names::relative_path(inside)?;
        if !icon.to_ascii_lowercase().ends_with(".png") {
            return Err(Error::invalid("icon must be a .png file"));
        }
    }
    Ok(())
}

/// The `[kaonic-plugin]` and `[service]` tables as key → value. Other tables are refused.
type Table = HashMap<String, Value>;

fn tables(text: &str) -> Result<(Table, Table), Error> {
    let bad = |line: usize, why: &str| Error::invalid(format!("{FILE} line {line}: {why}"));
    if text.len() > 16 * 1024 {
        return Err(Error::invalid(format!("{FILE} is larger than 16 KiB")));
    }
    let (mut plugin, mut service) = (HashMap::new(), HashMap::new());
    let mut section: Option<&str> = None;
    let mut seen = Vec::new();
    for (number, raw) in text.lines().enumerate() {
        let number = number + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[') {
            let name = strip_comment(name).trim_end();
            let name = name.strip_suffix(']').ok_or_else(|| bad(number, "a table header needs ]"))?.trim();
            section = match name {
                "kaonic-plugin" => Some("kaonic-plugin"),
                "service" => Some("service"),
                _ => return Err(bad(number, "the only tables are [kaonic-plugin] and [service]")),
            };
            if seen.contains(&name.to_owned()) {
                return Err(bad(number, "a table appears twice"));
            }
            seen.push(name.to_owned());
            continue;
        }
        let table = match section {
            Some("kaonic-plugin") => &mut plugin,
            Some(_) => &mut service,
            None => return Err(bad(number, "keys must be inside [kaonic-plugin] or [service]")),
        };
        let (key, value) = line.split_once('=').ok_or_else(|| bad(number, "expected key = value"))?;
        let key = key.trim();
        if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-') {
            return Err(bad(number, "bad key"));
        }
        let value = value_of(value.trim()).map_err(|why| bad(number, why))?;
        if table.insert(key.to_owned(), value).is_some() {
            return Err(bad(number, "a key appears twice"));
        }
    }
    if !seen.iter().any(|name| name == "kaonic-plugin") {
        return Err(Error::invalid(format!("{FILE} has no [kaonic-plugin] table")));
    }
    Ok((plugin, service))
}

fn strip_comment(text: &str) -> &str {
    text.split_once('#').map_or(text, |(before, _)| before)
}

fn value_of(text: &str) -> Result<Value, &'static str> {
    if let Some(rest) = text.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        loop {
            match chars.next().ok_or("unterminated string")? {
                '"' => break,
                '\\' => out.push(match chars.next().ok_or("unterminated string")? {
                    '"' => '"',
                    '\\' => '\\',
                    _ => return Err("unsupported escape (only \\\" and \\\\)"),
                }),
                c => out.push(c),
            }
        }
        let tail = chars.as_str().trim();
        return if tail.is_empty() || tail.starts_with('#') { Ok(Value::Text(out)) } else { Err("text after a string") };
    }
    if let Some(rest) = text.strip_prefix('\'') {
        let (value, tail) = rest.split_once('\'').ok_or("unterminated string")?;
        let tail = tail.trim();
        return if tail.is_empty() || tail.starts_with('#') { Ok(Value::Text(value.to_owned())) } else { Err("text after a string") };
    }
    let bare = strip_comment(text).trim();
    match bare {
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        _ => bare.replace('_', "").parse::<i64>().map(Value::Int).map_err(|_| "unsupported value (strings, integers and booleans only)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const PTT: &str = r#"[kaonic-plugin]
format = 2
id = "kaonic-ptt-voice"
name = "Audio PTT"
description = "Push-to-talk over the mesh"
version = "0.3.0"
developer = "Beechat Network Systems Ltd"
channel = "stable"
page = true # its page
icon = "files/icon.png"
command = true

[service]
args = "--codec opus  --rate 16000"
permissions = "realtime audio mesh audio"
environment = "RUST_LOG=info"
nice = -5
"#;

    #[test]
    fn reads_a_manifest() {
        let manifest = parse(PTT).unwrap();
        assert_eq!(manifest.id, "kaonic-ptt-voice");
        assert_eq!(manifest.args, ["--codec", "opus", "--rate", "16000"]);
        assert_eq!(manifest.permissions, [Permission::Audio, Permission::Realtime, Permission::Mesh]);
        assert!(manifest.page);
        assert_eq!(manifest.restart, Restart::OnFailure);
        assert_eq!((manifest.restart_sec, manifest.stop_timeout, manifest.memory_max_mb), (5, 15, 0), "defaults");
        assert_eq!(manifest.environment, [("RUST_LOG".to_owned(), "info".to_owned())]);
        assert_eq!(manifest.nice, -5);
        assert!(manifest.command);
        assert_eq!(manifest.program(), "bin/kaonic-ptt-voice");
        assert!(validate(&manifest).is_ok());
    }

    #[test]
    fn refuses_bad_manifests() {
        let with = |from: &str, to: &str| parse(&PTT.replace(from, to));
        assert!(with("format = 2", "format = 1").is_err(), "old format");
        assert!(with("version = \"0.3.0\"\n", "").is_err(), "no version");
        assert!(with("\"kaonic-ptt-voice\"", "\"../evil\"").is_err());
        assert!(with("\"kaonic-ptt-voice\"", "\"kaonic-commd\"").is_err());
        assert!(with("page = true", "page = 8780").is_err(), "no page ports any more");
        assert!(with("\"kaonic-ptt-voice\"", "\"ip\"").is_err(), "a command link outside kaonic-*");
        assert!(with("command = true", "command = false").is_ok());
        assert!(with("mesh audio", "mesh sudo").is_err());
        assert!(with("files/icon.png", "../icon.png").is_err());
        assert!(with("files/icon.png", "files/icon.svg").is_err());
        assert!(with("command = true", "command = true\nservice = \"x.service\"").is_err(), "unknown key");
        assert!(with("[service]", "[Service]").is_err(), "another table");
        assert!(with("nice = -5", "ExecStart = \"/bin/sh\"").is_err(), "not a service key");
        assert!(with("RUST_LOG=info", "LD_PRELOAD=/x.so").is_err());
        assert!(with("RUST_LOG=info", "KAONIC_PLUGIN_TOKEN=x").is_err());
        assert!(with("nice = -5", "nice = -50").is_err());
        assert!(with("realtime audio mesh audio", "audio").is_err(), "nice below 0 without realtime");
        assert!(with("nice = -5", "memory_max_mb = 1").is_err());
        assert!(with("Audio PTT", "Audio\\nPTT").is_err(), "escapes beyond quotes");
        assert!(parse(&format!("{PTT}\nname = \"twice\"")).is_err());
    }

    #[test]
    fn validate_catches_what_parse_would() {
        let good = parse(PTT).unwrap();
        let bad = |change: &dyn Fn(&mut Manifest)| {
            let mut manifest = good.clone();
            change(&mut manifest);
            validate(&manifest).is_err()
        };
        assert!(bad(&|m| m.id = "../x".into()));
        assert!(bad(&|m| m.environment.push(("LD_PRELOAD".into(), "/x.so".into()))));
        assert!(bad(&|m| m.environment.push(("A".into(), "x\nExecStart=/bin/sh".into()))));
        assert!(bad(&|m| m.args.push("a b".into())));
        assert!(bad(&|m| m.restart_sec = 0));
        assert!(bad(&|m| m.memory_max_mb = 1));
        assert!(bad(&|m| m.nice = -30));
        assert!(bad(&|m| m.icon = Some("../x.png".into())));
        assert!(bad(&|m| m.name = "a\nb".into()));
    }
}
