//! `kaonic-hub`: start-up and wiring.
//!
//! ```text
//! kaonic-hub [--state-dir DIR] [--webui-dir DIR] [--run-dir DIR] [--root DIR]
//!            [--https ADDR] [--http ADDR] [--dev ADDR]
//!            [--installer-socket PATH] [--plugin-api-dir DIR]
//! ```
//! On a device the defaults are right: state on userfs (`/usr/local/kaonic-hub`),
//! the web UI built in, HTTPS on :443 and a redirect on :80. `--webui-dir` serves the UI
//! from a directory instead, for working on it.
//! `--dev 127.0.0.1:8080` serves plain HTTP with no Wi-Fi hardware, for a laptop.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kaonic_hub::api::Jobs;
use kaonic_hub::app::{App, Config, Inner};
use kaonic_hub::auth::Limiter;
use kaonic_hub::events::Bus;
use kaonic_hub::system::{Device, Metrics};
use kaonic_hub::{clock, server, tls, wifi};
use kaonic_keystore::{Keystore, RawKey};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

struct Args {
    state_dir: PathBuf,
    webui_dir: Option<PathBuf>,
    run_dir: PathBuf,
    root: PathBuf,
    https: SocketAddr,
    http: Option<SocketAddr>,
    dev: Option<SocketAddr>,
    radio: String,
    /// Where setup is answered; `br0` and `usb0` unless given.
    setup_interfaces: Vec<String>,
    announce_secs: u64,
    /// UDP port of push-to-talk sessions (phone and ATAK clients).
    ptt_udp_port: u16,
    /// Leave Wi-Fi to whatever manages it now (tests of the mesh alone).
    no_wifi: bool,
    /// The mesh VPN: on unless `--no-vpn`.
    vpn: Option<kaonic_vpn::VpnConfig>,
    /// The plugin installer's socket and the plugin API's sockets.
    plugins: kaonic_hub::plugins::Settings,
}

fn args() -> Result<Args, String> {
    let mut args = Args {
        state_dir: "/usr/local/kaonic-hub".into(),
        webui_dir: None,
        run_dir: "/run/kaonic-hub".into(),
        root: "/".into(),
        https: "0.0.0.0:443".parse().expect("valid address"),
        http: Some("0.0.0.0:80".parse().expect("valid address")),
        dev: None,
        radio: "rf09_a".into(),
        setup_interfaces: Vec::new(),
        announce_secs: 120,
        ptt_udp_port: 8781,
        no_wifi: false,
        vpn: None,
        plugins: Default::default(),
    };
    // On by default: a provisioned node shares the mesh with its clients.
    let mut vpn_on = true;
    let mut lan_interfaces_given = false;
    let mut vpn = kaonic_vpn::VpnConfig {
        network: "10.77.0.0/16".parse().expect("valid prefix"),
        interface: "kaonic0".into(),
        advertise: Vec::new(),
        // One radio frame carries 896 B of Reticulum packet: 799 B of link payload over relays.
        max_packet: 799,
        limits: Default::default(),
        share: Default::default(),
        forward: kaonic_vpn::forward::defaults(),
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--state-dir" => args.state_dir = value()?.into(),
            "--webui-dir" => args.webui_dir = Some(value()?.into()),
            "--run-dir" => args.run_dir = value()?.into(),
            "--root" => args.root = value()?.into(),
            "--https" => args.https = value()?.parse().map_err(|_| "--https: not an address")?,
            "--http" => args.http = Some(value()?.parse().map_err(|_| "--http: not an address")?),
            "--no-http" => args.http = None,
            "--dev" => args.dev = Some(value()?.parse().map_err(|_| "--dev: not an address")?),
            "--radio" => args.radio = value()?,
            "--setup-interface" => args.setup_interfaces.push(value()?),
            "--no-wifi" => args.no_wifi = true,
            "--installer-socket" => args.plugins.installer = value()?.into(),
            "--plugin-api-dir" => args.plugins.api_dir = value()?.into(),
            // Log the A/B boot commands instead of running them (always so off Linux).
            "--boot-dry-run" => kaonic_hub::boot::configure(true),
            // Kept so old command lines work: the VPN is on unless --no-vpn.
            "--vpn" => vpn_on = true,
            "--no-vpn" => vpn_on = false,
            // Hub-to-hub repair (ARQ): off until tuned for the boards. On real hardware it halved
            // TCP (85 vs 197 kbit/s, 2026-10-16) although it helped on the emulator.
            "--vpn-arq" => vpn.limits.arq = true,
            "--vpn-no-arq" => vpn.limits.arq = false,
            "--vpn-network" => vpn.network = value()?.parse().map_err(|error| format!("--vpn-network: {error}"))?,
            "--vpn-interface" => vpn.interface = value()?,
            "--vpn-advertise" => vpn.advertise.push(value()?.parse().map_err(|error| format!("--vpn-advertise: {error}"))?),
            "--vpn-lan-interface" => {
                if !lan_interfaces_given {
                    vpn.share.lan_interfaces.clear();
                    lan_interfaces_given = true;
                }
                vpn.share.lan_interfaces.push(value()?);
            }
            "--ptt-udp-port" => args.ptt_udp_port = value()?.parse().map_err(|_| "--ptt-udp-port: not a port")?,
            "--announce-secs" => {
                args.announce_secs = value()?
                    .parse()
                    .map_err(|_| "--announce-secs: not a number")?
            }
            "--version" => {
                println!("kaonic-hub {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.setup_interfaces.is_empty() {
        args.setup_interfaces = vec!["br0".into(), "usb0".into()];
    }
    // The management ports kept off the tunnel are the ones this hub listens on.
    vpn.limits.protected_tcp = std::iter::once(args.https.port()).chain(args.http.map(|http| http.port())).collect();
    vpn.limits.protected_udp = vec![args.ptt_udp_port];
    args.vpn = vpn_on.then_some(vpn);
    Ok(args)
}

/// Logs to stderr, which journald keeps. `KAONIC_HUB_LOG=debug` for more.
struct Logger(log::LevelFilter);

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.0
    }
    fn log(&self, record: &log::Record) {
        let ours = ["kaonic", "hub_"]
            .iter()
            .any(|prefix| record.target().starts_with(prefix));
        // Libraries are chatty below warnings; their problems still show.
        let shown = ours || record.level() <= log::Level::Warn;
        if self.enabled(record.metadata()) && shown {
            eprintln!("{:<5} {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}

fn private_dir(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

fn main() {
    let args = match args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("kaonic-hub: {error}");
            std::process::exit(2);
        }
    };
    // The installer may have updated us: run that copy if it is good (returns if not). It
    // inherits our environment, the systemd socket included.
    kaonic_hub_installer::core::exec_newer(&args.plugins.core_dir, "kaonic-hub", env!("CARGO_PKG_VERSION"));
    // Only this process talks to systemd: the commands it runs must not inherit the socket.
    let notify_socket = std::env::var("NOTIFY_SOCKET").ok();
    // SAFETY: before any thread exists.
    unsafe { std::env::remove_var("NOTIFY_SOCKET") };
    NOTIFY.set(notify_socket).ok();
    let level = match std::env::var("KAONIC_HUB_LOG").as_deref() {
        Ok("debug") => log::LevelFilter::Debug,
        Ok("warn") => log::LevelFilter::Warn,
        _ => log::LevelFilter::Info,
    };
    let _ = log::set_logger(Box::leak(Box::new(Logger(level)))).map(|()| log::set_max_level(level));
    if let Err(error) = kaonic_keystore::harden_process() {
        log::warn!("could not harden the process: {error}");
    }
    // One core: the current-thread runtime, with blocking work on its own threads.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(error) = runtime.block_on(run(args)) {
        log::error!("{error}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    private_dir(&args.state_dir)?;
    private_dir(&args.run_dir)?;
    if args.plugins.api_dir.starts_with(&args.run_dir) {
        // Plugins pass through to their API sockets; nothing in here can be listed, and
        // what is in here is private on its own (the Wi-Fi files, the slot mounts).
        use std::os::unix::fs::PermissionsExt;
        private_dir(&args.run_dir.join("slot"))?;
        std::fs::set_permissions(&args.run_dir, std::fs::Permissions::from_mode(0o711))?;
    }
    let dev = args.dev.is_some();

    let store = kaonic_store::Store::open(&args.state_dir.join("hub.db"))?;
    // Interim root of trust: a random key file next to the keystore. To move to an
    // OTP- or OP-TEE-bound key.
    let key_path = args.state_dir.join("keystore.key");
    let kek = if key_path.exists() {
        RawKey::load(&key_path)?
    } else {
        RawKey::generate_file(&key_path)?
    };
    let mut keystore = Keystore::open_or_create(args.state_dir.join("keystore"), &kek)?;
    // The identity this device is born with; a member keeps it.
    keystore.get_or_generate(kaonic_hub::api::BOOT_IDENTITY, 64)?;
    // The mesh speaks as this node: its set-up identity, or the boot identity before setup.
    let node_identity = {
        let bytes = keystore
            .get(kaonic_hub::api::NODE_IDENTITY)
            .or_else(|| keystore.get(kaonic_hub::api::BOOT_IDENTITY))
            .map(|secret| secret.expose().to_vec());
        bytes
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .map(|bytes| kaonic_hub::identity::NodeIdentity::from_bytes(&bytes))
    };
    let keystore = Arc::new(Mutex::new(keystore));

    let device = Device::new(&args.root);
    let bus = Bus::new();
    let suffix = device
        .serial()
        .rsplit('-')
        .next()
        .unwrap_or("0000")
        .chars()
        .take(4)
        .collect::<String>()
        .to_uppercase();
    let radio: Box<dyn wifi::Radio> = if dev || args.no_wifi {
        Box::new(wifi::NullRadio)
    } else {
        Box::new(wifi::linux::LinuxRadio::new(
            &args.run_dir,
            device.machine(),
        )?)
    };
    let wifi = wifi::start(
        radio,
        store.clone(),
        keystore.clone(),
        bus.clone(),
        format!("Kaonic /{suffix}/"),
    )?;

    let app = App::new(Inner {
        config: Config {
            state_dir: args.state_dir.clone(),
            webui: match &args.webui_dir {
                Some(dir) => kaonic_hub::web::Webui::Dir(dir.clone()),
                None => kaonic_hub::web::Webui::Embedded,
            },
            run_dir: args.run_dir.clone(),
            dev,
            radio: args.radio.clone(),
            setup_interfaces: args.setup_interfaces.clone(),
            plugins: args.plugins.clone(),
        },
        store,
        keystore,
        bus,
        limiter: Limiter::default(),
        argon: Semaphore::new(1),
        device,
        metrics: Metrics::default(),
        wifi,
        jobs: Jobs::default(),
        ca_pem: std::sync::OnceLock::new(),
        mesh: None,
        provisioning: Default::default(),
        radio_stats: Default::default(),
        links: Default::default(),
        ptt_group: Default::default(),
        ptt: Default::default(),
        vpn: Default::default(),
        vpn_error: Default::default(),
        vpn_config: args.vpn.clone(),
        plugins: Default::default(),
    });
    let app = match (dev, node_identity) {
        (false, Some(identity)) => start_mesh(app, identity, &args).await,
        _ => app,
    };
    background(app.clone());
    kaonic_hub::provision::serve(app.clone());
    kaonic_hub::api::boot::after_start();
    kaonic_hub::api::radio::spawn_producers(app.clone());
    kaonic_hub::api::radio_bands::restore_other_bands(&app).await;
    kaonic_hub::api::radio_bands::spawn(app.clone());
    kaonic_hub::remote::spawn(app.clone());
    if kaonic_hub::secure::start_links(&app).await.is_some() {
        kaonic_hub::secure::start_group(&app).await;
        let _ = app.ptt.set(kaonic_hub::ptt::Ptt::start(&app, args.ptt_udp_port).await);
        if let Some(config) = app.vpn_config.clone() {
            let config = kaonic_hub::api::vpn::with_stored_share(&app, config).await;
            kaonic_hub::secure::start_vpn(&app, config).await;
        }
    }
    // The plugin API's sockets and the mesh bridge, on the links if they run.
    kaonic_hub::plugins::start(&app).await;
    let router = kaonic_hub::router(app.clone());

    if let Some(address) = args.dev {
        log::warn!(
            "development mode: plain HTTP on {address}, no Wi-Fi hardware; never use this on a device"
        );
        server::http(TcpListener::bind(address).await?, router, server::Gate::open()).await;
        return Ok(());
    }

    let (names, addresses) = tls::device_names(&app);
    let tls = tls::load_or_create(&app, names, addresses)
        .await
        .map_err(|error| error.message)?;
    let _ = app.ca_pem.set(tls.ca_pem.clone());

    // Nothing is answered to the mesh VPN: only the device's own networks reach the API.
    let gate_app = app.clone();
    let gate = server::Gate::new(move |remote, local| server::via_tunnel(&gate_app, remote) || server::via_tunnel(&gate_app, local));
    if let Some(address) = args.http {
        let listener = TcpListener::bind(address).await?;
        tokio::spawn(server::http(listener, server::redirect_router(), gate.clone()));
    }
    log::info!(
        "kaonic-hub {} on https://{}",
        env!("CARGO_PKG_VERSION"),
        args.https
    );
    notify_ready();
    kaonic_hub::api::software::report_ready(&app);
    server::https(TcpListener::bind(args.https).await?, router, tls.config, gate).await;
    Ok(())
}

/// Starts Reticulum on the radio. Without a radio the hub still runs; the mesh pages say so.
async fn start_mesh(app: App, identity: kaonic_hub::identity::NodeIdentity, args: &Args) -> App {
    let info = match kaonic_hub::api::node_info(&app).await {
        Ok(info) => info,
        Err(error) => {
            log::error!("mesh: cannot read this node's settings: {}", error.message);
            return app;
        }
    };
    // The band's full saved record (Radio page) wins over the older mesh-only record.
    let settings = match kaonic_hub::api::radio_bands::restore_mesh_band(&app, &args.radio).await {
        Some(settings) => settings,
        None => radio_settings(&app, &args.radio).await,
    };
    let config = kaonic_mesh::MeshConfig {
        radio: args.radio.clone(),
        announce_secs: args.announce_secs,
        offline_secs: args.announce_secs * 4,
        settings: Some(settings),
        ..Default::default()
    };
    match kaonic_mesh::Mesh::start(identity.to_reticulum(), info, config).await {
        Ok(mesh) => {
            log::info!("mesh: on {} as {}", args.radio, mesh.identity_hash());
            app.with_mesh(mesh)
        }
        Err(error) => {
            log::error!("mesh: cannot start on {}: {error}", args.radio);
            app
        }
    }
}

/// The mesh radio's settings: as saved (`radio.<iface>` = frequency,channel,spacing,mcs,opt,power),
/// else the fielded defaults, which are then saved so they survive whatever reconfigures the driver.
async fn radio_settings(app: &App, iface: &str) -> kaonic_mesh::settings::RadioSettings {
    let key = format!("radio.{iface}");
    let stored_key = key.clone();
    let stored = app
        .store
        .call(move |c| kaonic_store::settings::get(c, &stored_key))
        .await
        .ok()
        .flatten();
    let parsed = stored.as_deref().and_then(|text| {
        let fields: Vec<u64> = text
            .split(',')
            .filter_map(|field| field.trim().parse().ok())
            .collect();
        let [
            frequency_hz,
            channel,
            channel_spacing_hz,
            ofdm_mcs,
            ofdm_opt,
            tx_power,
        ] = fields[..]
        else {
            return None;
        };
        Some(kaonic_mesh::settings::RadioSettings {
            frequency_hz,
            channel: u16::try_from(channel).ok()?,
            channel_spacing_hz,
            ofdm_mcs: u8::try_from(ofdm_mcs).ok()?,
            ofdm_opt: u8::try_from(ofdm_opt).ok()?,
            tx_power: u8::try_from(tx_power).ok()?,
        })
    });
    let settings = parsed.unwrap_or_else(kaonic_mesh::settings::RadioSettings::sub_ghz_default);
    let text = format!(
        "{},{},{},{},{},{}",
        settings.frequency_hz,
        settings.channel,
        settings.channel_spacing_hz,
        settings.ofdm_mcs,
        settings.ofdm_opt,
        settings.tx_power
    );
    let _ = app
        .store
        .call(move |c| kaonic_store::settings::set(c, &key, &text))
        .await;
    settings
}

/// Periodic work: metrics while someone watches, network state after Wi-Fi changes, old sessions.
fn background(app: App) {
    let metrics_app = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            if metrics_app.bus.receivers() > 1 {
                let metrics = metrics_app
                    .metrics
                    .read(&metrics_app.device, &metrics_app.config.state_dir);
                metrics_app
                    .bus
                    .publish("metrics", "metrics.system", metrics);
            }
        }
    });
    if let Some(mesh) = app.mesh.clone() {
        let peers_app = app.clone();
        tokio::spawn(async move {
            let mut updates = mesh.subscribe();
            loop {
                match updates.recv().await {
                    Ok(peer) => kaonic_hub::api::publish_peer(&peers_app, &peer.id).await,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        peers_app.bus.publish("system", "resync", ())
                    }
                    Err(_) => return,
                }
            }
        });
    }
    let network_app = app.clone();
    tokio::spawn(async move {
        let mut events = network_app.bus.subscribe();
        loop {
            match events.recv().await {
                Ok(event) if event.kind == "wifi.changed" => {
                    if let Ok(wifi) = network_app.wifi.get().await {
                        network_app.bus.publish(
                            "network",
                            "network.changed",
                            kaonic_hub::api::network_state(&wifi),
                        );
                    }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => return,
            }
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let now = clock::now();
            let _ = app
                .store
                .call(move |c| kaonic_store::sessions::purge_expired(c, now))
                .await;
        }
    });
}

static NOTIFY: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// Tells systemd (`Type=notify`) that the hub is up, if it is watching.
fn notify_ready() {
    let Some(Some(path)) = NOTIFY.get() else {
        return;
    };
    if let Ok(socket) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = socket.send_to(b"READY=1", path.trim_start_matches('@'));
    }
}
