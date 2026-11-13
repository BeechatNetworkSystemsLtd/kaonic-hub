//! Builds the web UI into the binary.
//!
//! The files come from `KAONIC_WEBUI_DIST`, or `../resources/kaonic-webui/dist` (the web UI
//! submodule after `npm run build`). Without them the hub builds with no UI and says so;
//! with `KAONIC_WEBUI_REQUIRED=1` (release builds) that is an error instead.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=KAONIC_WEBUI_DIST");
    println!("cargo:rerun-if-env-changed=KAONIC_WEBUI_REQUIRED");
    println!("cargo:rerun-if-env-changed=KAONIC_WEBUI_VERSION");
    // The hub's own commit, for the system report.
    let commit = std::process::Command::new("git").args(["describe", "--always", "--dirty", "--abbrev=10"]).output();
    let commit = commit.ok().filter(|output| output.status.success()).map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    println!("cargo:rustc-env=KAONIC_HUB_COMMIT={}", commit.unwrap_or_else(|| "unknown".into()));
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist = match std::env::var_os("KAONIC_WEBUI_DIST") {
        Some(dir) => PathBuf::from(dir),
        None => manifest.join("../resources/kaonic-webui/dist"),
    };
    println!("cargo:rerun-if-changed={}", dist.display());

    let mut files = Vec::new();
    if dist.join("index.html").is_file() {
        collect(&dist, &dist, &mut files);
        files.sort();
    } else if std::env::var_os("KAONIC_WEBUI_REQUIRED").is_some_and(|value| value == "1") {
        panic!("no web UI at {}: build it first (npm run build in resources/kaonic-webui)", dist.display());
    } else {
        println!("cargo:warning=no web UI at {}: building without one", dist.display());
    }

    let version = std::env::var("KAONIC_WEBUI_VERSION").ok().or_else(|| if files.is_empty() { None } else { version(&dist) });
    let mut out = String::from("pub static FILES: &[(&str, &[u8])] = &[\n");
    for (url, path) in &files {
        writeln!(out, "    ({url:?}, include_bytes!({:?})),", path.display().to_string()).unwrap();
    }
    out.push_str("];\n");
    writeln!(out, "pub const VERSION: Option<&str> = {version:?};").unwrap();
    let target = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("webui.rs");
    std::fs::write(target, out).unwrap();
}

/// Every regular file under `dir`, as (URL path, file). Symlinks are left out.
fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let kind = entry.file_type().unwrap();
        println!("cargo:rerun-if-changed={}", path.display());
        if kind.is_dir() {
            collect(root, &path, files);
        } else if kind.is_file() {
            let relative = path.strip_prefix(root).unwrap();
            let url = format!("/{}", relative.to_str().expect("UTF-8 file name").replace('\\', "/"));
            files.push((url, path.canonicalize().unwrap()));
        }
    }
}

/// `<package.json version>+<commit>` of the web UI, or the `version` file in its build.
fn version(dist: &Path) -> Option<String> {
    if let Ok(text) = std::fs::read_to_string(dist.join("version")) {
        let text = text.trim();
        if !text.is_empty() {
            return Some(text.to_owned());
        }
    }
    let source = dist.parent()?;
    let package: serde_json::Value = serde_json::from_slice(&std::fs::read(source.join("package.json")).ok()?).ok()?;
    let mut version = package.get("version")?.as_str()?.to_owned();
    let commit = std::process::Command::new("git").args(["rev-parse", "--short", "HEAD"]).current_dir(source).output();
    if let Ok(output) = commit
        && output.status.success()
    {
        let commit = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !commit.is_empty() {
            version = format!("{version}+{commit}");
        }
    }
    Some(version)
}
