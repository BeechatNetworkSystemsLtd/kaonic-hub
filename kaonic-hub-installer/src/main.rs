//! `kaonic-hub-installer`: start-up.
//!
//! ```text
//! kaonic-hub-installer [--allow-uid UID]... [--release-key PEM]... [--root DIR] [--settle SECS]
//! kaonic-hub-installer check PACKAGE     check a package and print its manifest
//! ```
//! On a device the defaults are right: the API is on `/run/kaonic-hub-installer/api.sock`
//! for root only. `--allow-uid` replaces root in the allowed peers (repeat it for more).
//! `--root DIR` keeps everything under DIR, for development (it still calls systemctl).
//! A release key that is there but cannot be read stops the start; only a missing one makes
//! this a development device.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kaonic_hub_installer::host::System;
use kaonic_hub_installer::{Installer, Paths, api};

struct Args {
    allowed: Vec<u32>,
    release_keys: Vec<PathBuf>,
    paths: Paths,
    settle: Duration,
    check: Option<PathBuf>,
}

fn args() -> Result<Args, String> {
    let mut args = Args { allowed: Vec::new(), release_keys: Vec::new(), paths: Paths::device(), settle: Duration::from_secs(10), check: None };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--allow-uid" => args.allowed.push(value()?.parse().map_err(|_| "--allow-uid needs a number".to_owned())?),
            "--release-key" => args.release_keys.push(value()?.into()),
            "--root" => args.paths = Paths::under(std::path::Path::new(&value()?)),
            "--settle" => args.settle = Duration::from_secs(value()?.parse().map_err(|_| "--settle needs seconds".to_owned())?),
            "check" => args.check = Some(value()?.into()),
            "--help" | "-h" => return Err(USAGE.to_owned()),
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        }
    }
    if args.allowed.is_empty() {
        args.allowed.push(0);
    }
    if args.release_keys.is_empty() {
        args.release_keys.push("/etc/kaonic/beechat-ota.pub.pem".into());
    }
    Ok(args)
}

const USAGE: &str = "usage: kaonic-hub-installer [--allow-uid UID]... [--release-key PEM]... [--root DIR] [--settle SECS]
       kaonic-hub-installer check PACKAGE";

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }
    fn log(&self, record: &log::Record) {
        let ours = record.target().starts_with("kaonic");
        if self.enabled(record.metadata()) && (ours || record.level() <= log::Level::Warn) {
            eprintln!("{:<5} {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}

fn main() {
    let _ = log::set_logger(&Logger).map(|_| log::set_max_level(log::LevelFilter::Info));
    let args = match args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    // The hub may have updated us: run that copy if it is good (returns if not).
    if args.check.is_none() {
        kaonic_hub_installer::core::exec_newer(&args.paths.core, "kaonic-hub-installer", env!("CARGO_PKG_VERSION"));
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a tokio runtime").block_on(run(args));
}

fn fatal(message: impl std::fmt::Display) -> ! {
    eprintln!("kaonic-hub-installer: {message}");
    std::process::exit(1);
}

async fn run(args: Args) {
    let release_keys = kaonic_hub_installer::core::read_release_keys(&args.release_keys).unwrap_or_else(|error| fatal(error));
    if release_keys.is_empty() {
        log::warn!("installer: no release key: development device, packages install unsigned (root plugins too)");
    }
    let installer = match Installer::new(args.paths.clone(), release_keys, Arc::new(System), args.settle) {
        Ok(installer) => Arc::new(installer),
        Err(error) => fatal(error),
    };

    if let Some(path) = args.check {
        let result = std::fs::File::open(&path)
            .map_err(|error| error.to_string())
            .and_then(|mut file| installer.check(&mut file).map_err(|error| error.to_string()));
        match result {
            Ok(package) => {
                println!("{}", serde_json::to_string_pretty(&package.manifest).expect("serialises"));
                println!("signed: {}", package.signed);
            }
            Err(error) => {
                eprintln!("{}: {error}", path.display());
                std::process::exit(1);
            }
        }
        return;
    }

    // The socket first, so the hub can connect while plugins start.
    let socket = &args.paths.socket;
    let listener = api::bind(socket).unwrap_or_else(|error| fatal(format!("listening on {}: {error}", socket.display())));
    let restore = installer.clone();
    if let Err(error) = tokio::task::spawn_blocking(move || restore.restore()).await.expect("restore task") {
        log::warn!("installer: restoring plugins: {error}");
    }
    log::info!("installer: {} listening on {} for uids {:?}", env!("CARGO_PKG_VERSION"), socket.display(), args.allowed);
    kaonic_hub_installer::core::healthy(&args.paths.core, "kaonic-hub-installer");
    let shutdown = async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    if let Err(error) = api::serve(listener, args.allowed, installer, shutdown).await {
        log::error!("installer: {error}");
    }
}
