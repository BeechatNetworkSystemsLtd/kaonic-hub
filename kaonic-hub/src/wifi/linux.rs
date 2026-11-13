//! The real [`Radio`]: wpa_supplicant, hostapd, networkd and `iw` on the device.
//!
//! - Both daemons run as transient systemd units (`systemd-run`), so they outlive
//!   a hub restart and do not die with the hub's cgroup.
//! - wpa_supplicant's config holds no network: the hub adds them over the
//!   control socket. hostapd's config holds the hotspot passphrase, so it is
//!   rendered to tmpfs (`/run`), mode 0600, and never reaches the SD card.
//! - DHCP on the client interface is a networkd file under `/run/systemd/network`,
//!   which sorts before the image's `wlan0.network`.
//! - With the client and the hotspot both on (repeater), the hotspot runs on a
//!   virtual `uap0` interface on the client's channel; alone, it runs on `wlan0`.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kaonic_wifi::ctrl::Ctrl;
use kaonic_wifi::wpa;

use super::{HotspotConfig, Radio, Supplicant};

const CLIENT: &str = "wlan0";
const VIRTUAL_AP: &str = "uap0";
const BRIDGE: &str = "br0";
const SUPPLICANT_UNIT: &str = "kaonic-hub-wpa";
const HOSTAPD_UNIT: &str = "kaonic-hub-hostapd";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

pub struct LinuxRadio {
    run_dir: PathBuf,
    network_dir: PathBuf,
    machine: Option<String>,
    client_running: bool,
}

impl LinuxRadio {
    /// `run_dir` is the hub's tmpfs directory (`/run/kaonic-hub`).
    pub fn new(run_dir: &Path, machine: Option<String>) -> io::Result<Self> {
        for dir in ["wpa", "wpa-client", "hostapd"] {
            private_dir(&run_dir.join(dir))?;
        }
        // The image's own hostapd must not fight the hub for wlan0.
        let _ = run("systemctl", &["stop", "hostapd.service"]);
        Ok(Self {
            run_dir: run_dir.to_owned(),
            network_dir: PathBuf::from("/run/systemd/network"),
            machine,
            client_running: false,
        })
    }

    fn supplicant_socket(&self) -> PathBuf {
        self.run_dir.join("wpa").join(CLIENT)
    }
}

impl Radio for LinuxRadio {
    fn supplicant(&mut self) -> io::Result<Box<dyn Supplicant>> {
        let socket = self.supplicant_socket();
        if !socket.exists() {
            let config = self.run_dir.join("wpa_supplicant.conf");
            write_private(
                &config,
                &format!(
                    "ctrl_interface={}\nupdate_config=0\nap_scan=1\n",
                    self.run_dir.join("wpa").display()
                ),
            )?;
            let _ = run("ip", &["link", "set", CLIENT, "nomaster"]);
            run("ip", &["link", "set", CLIENT, "up"])?;
            // The Wi-Fi chip's power save makes the LAN unreachable at times.
            let _ = run("iw", &["dev", CLIENT, "set", "power_save", "off"]);
            run(
                "systemd-run",
                &[
                    &format!("--unit={SUPPLICANT_UNIT}"),
                    "--collect",
                    "--property=Restart=on-failure",
                    "--property=RestartSec=2",
                    "/usr/sbin/wpa_supplicant",
                    "-i",
                    CLIENT,
                    "-D",
                    "nl80211",
                    "-c",
                    &config.to_string_lossy(),
                ],
            )?;
            wait_for(&socket, Duration::from_secs(10))?;
        }
        self.client_running = true;
        let supplicant =
            kaonic_wifi::supplicant::Supplicant::open(&socket, &self.run_dir.join("wpa-client"))?;
        Ok(Box::new(supplicant))
    }

    fn notices(&mut self) -> io::Result<super::NoticeReader> {
        let ctrl = Ctrl::open(&self.supplicant_socket(), &self.run_dir.join("wpa-client"))?;
        ctrl.attach()?;
        Ok(Box::new(move |timeout| ctrl.next_event(timeout)))
    }

    fn stop_supplicant(&mut self) -> io::Result<()> {
        self.client_running = false;
        let _ = run(
            "systemctl",
            &["stop", &format!("{SUPPLICANT_UNIT}.service")],
        );
        let _ = fs::remove_file(self.supplicant_socket());
        Ok(())
    }

    fn hotspot(
        &mut self,
        config: Option<&HotspotConfig>,
        client_frequency: Option<u32>,
    ) -> io::Result<()> {
        let path = self.run_dir.join("hostapd.conf");
        let interface = if self.client_running { VIRTUAL_AP } else { CLIENT };
        // The same hotspot already running (the hub restarted): keep it, since a restart
        // drops every station.
        if let Some(config) = config {
            let text = render_hostapd(config, interface, client_frequency, &self.run_dir.join("hostapd"));
            let running = run("systemctl", &["is-active", "--quiet", &format!("{HOSTAPD_UNIT}.service")]).is_ok();
            let interface_up = interface == CLIENT || Path::new("/sys/class/net").join(VIRTUAL_AP).exists();
            if running && interface_up && fs::read_to_string(&path).is_ok_and(|current| current == text) {
                return Ok(());
            }
        }
        let _ = run("systemctl", &["stop", &format!("{HOSTAPD_UNIT}.service")]);
        let _ = run("iw", &["dev", VIRTUAL_AP, "del"]);
        let Some(config) = config else { return Ok(()) };

        let interface = if self.client_running {
            run(
                "iw",
                &[
                    "dev",
                    CLIENT,
                    "interface",
                    "add",
                    VIRTUAL_AP,
                    "type",
                    "__ap",
                ],
            )?;
            VIRTUAL_AP
        } else {
            CLIENT
        };
        write_private(
            &path,
            &render_hostapd(
                config,
                interface,
                client_frequency,
                &self.run_dir.join("hostapd"),
            ),
        )?;
        run(
            "systemd-run",
            &[
                &format!("--unit={HOSTAPD_UNIT}"),
                "--collect",
                "--property=Restart=on-failure",
                "--property=RestartSec=3",
                "/usr/sbin/hostapd",
                &path.to_string_lossy(),
            ],
        )?;
        Ok(())
    }

    fn client_address(&mut self) -> Option<String> {
        let output = run("ip", &["-4", "-o", "addr", "show", "dev", CLIENT]).ok()?;
        output
            .split_whitespace()
            .skip_while(|word| *word != "inet")
            .nth(1)
            .map(str::to_owned)
    }

    fn client_dhcp(&mut self, on: bool) -> io::Result<()> {
        const CONFIG: &str = "[Match]\nName=wlan0\n\n[Network]\nDHCP=ipv4\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n\n[DHCPv4]\nRouteMetric=600\nUseDNS=yes\n";
        let path = self.network_dir.join("62-kaonic-wlan0.network");
        // Only a real change reloads networkd: a reconfigure drops the address the client has.
        let present = fs::read_to_string(&path).ok();
        if on == (present.as_deref() == Some(CONFIG)) {
            return Ok(());
        }
        if on {
            fs::create_dir_all(&self.network_dir)?;
            fs::write(&path, CONFIG)?;
        } else if present.is_some() {
            fs::remove_file(&path)?;
        }
        run("networkctl", &["reload"])?;
        let _ = run("networkctl", &["reconfigure", CLIENT]);
        Ok(())
    }

    fn hotspot_healthy(&mut self) -> bool {
        let interface = if self.client_running { VIRTUAL_AP } else { CLIENT };
        let unit = run("systemctl", &["is-active", "--quiet", &format!("{HOSTAPD_UNIT}.service")]).is_ok();
        let ap_mode = run("iw", &["dev", interface, "info"]).is_ok_and(|info| info.lines().any(|line| line.trim() == "type AP"));
        unit && ap_mode
    }

    fn restart_hotspot(&mut self) -> io::Result<()> {
        run("systemctl", &["restart", &format!("{HOSTAPD_UNIT}.service")]).map(|_| ())
    }

    fn antenna_supported(&self) -> bool {
        // Only these boards have the antenna switch on gpiochip 8, line 0.
        matches!(
            self.machine.as_deref(),
            Some("stm32mp1-kaonic-protob" | "stm32mp1-kaonic-protoc")
        )
    }

    fn set_antenna(&mut self, external: bool) -> io::Result<()> {
        run(
            "gpioset",
            &["-z", "-c", "8", if external { "0=1" } else { "0=0" }],
        )
        .map(|_| ())
    }
}

/// hostapd's config. The SSID goes as hex so no name can break the file;
/// the passphrase is checked for printable ASCII before it gets here.
pub fn render_hostapd(
    config: &HotspotConfig,
    interface: &str,
    frequency: Option<u32>,
    ctrl_dir: &Path,
) -> String {
    let (band, channel) = frequency.and_then(channel_of).unwrap_or((
        "g",
        config
            .channel
            .filter(|channel| (1..=13).contains(channel))
            .unwrap_or(6),
    ));
    let mut text = format!(
        "interface={interface}\nbridge={BRIDGE}\ndriver=nl80211\nctrl_interface={}\nssid2={}\nutf8_ssid=1\nhw_mode={band}\nchannel={channel}\n\
         ieee80211n=1\nwmm_enabled=1\nauth_algs=1\nignore_broadcast_ssid=0\nmax_num_sta=16\n",
        ctrl_dir.display(),
        wpa::hex(&config.ssid),
    );
    if let Some(country) = &config.country
        && country.len() == 2
        && country.bytes().all(|byte| byte.is_ascii_uppercase())
    {
        text.push_str(&format!("country_code={country}\nieee80211d=1\n"));
    }
    if let Some(password) = &config.password
        && wpa::valid_passphrase(password)
    {
        text.push_str(&format!("wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nieee80211w=1\nwpa_passphrase={password}\n"));
    }
    text
}

/// 802.11 channel for a frequency: (`hw_mode`, channel).
pub fn channel_of(frequency: u32) -> Option<(&'static str, u32)> {
    match frequency {
        2412..=2472 => Some(("g", (frequency - 2407) / 5)),
        2484 => Some(("g", 14)),
        5000..=5900 => Some(("a", (frequency - 5000) / 5)),
        _ => None,
    }
}

fn private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
}

/// Writes a file only the hub can read, replacing it atomically.
fn write_private(path: &Path, text: &str) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, path)
}

fn wait_for(path: &Path, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{} did not appear", path.display()),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// Runs a command with a time limit; Err unless it exits 0. Returns its stdout.
fn run(program: &str, args: &[&str]) -> io::Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            let output = child.wait_with_output()?;
            return if status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).into_owned())
            } else {
                Err(io::Error::other(format!(
                    "{program} {}: {}",
                    args.first().unwrap_or(&""),
                    String::from_utf8_lossy(&output.stderr).trim()
                )))
            };
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{program} took too long"),
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostapd_config_is_safe_and_follows_the_client() {
        let config = HotspotConfig {
            ssid: "Kaonic\nbridge=evil".into(),
            password: Some("hotspot-pass".into()),
            country: Some("DE".into()),
            channel: Some(1),
        };
        let text = render_hostapd(
            &config,
            "uap0",
            Some(2437),
            Path::new("/run/kaonic-hub/hostapd"),
        );
        assert!(text.contains("interface=uap0\n"));
        assert!(text.contains("ssid2=4b616f6e69630a6272696467653d6576696c\n"));
        assert!(text.contains("channel=6\n") && text.contains("hw_mode=g\n"));
        assert!(text.contains("country_code=DE\n"));
        assert!(text.contains("wpa_passphrase=hotspot-pass\n"));
        assert_eq!(text.matches("bridge=").count(), 1);

        let open = HotspotConfig {
            ssid: "Open".into(),
            password: None,
            country: Some("de\nx".into()),
            channel: None,
        };
        let text = render_hostapd(&open, "wlan0", Some(5180), Path::new("/run/h"));
        assert!(!text.contains("wpa=") && !text.contains("country_code"));
        assert!(text.contains("hw_mode=a\nchannel=36\n"));
    }

    #[test]
    fn channels() {
        assert_eq!(channel_of(2412), Some(("g", 1)));
        assert_eq!(channel_of(2484), Some(("g", 14)));
        assert_eq!(channel_of(5745), Some(("a", 149)));
        assert_eq!(channel_of(900), None);
    }
}
