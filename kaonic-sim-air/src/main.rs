//! `kaonic-sim-air`: an emulated radio channel for kaonic-hub nodes. See the crate docs.

use std::net::SocketAddr;
use std::time::Duration;

use kaonic_sim_air::{Air, LinkParams, MediumConfig};

const USAGE: &str = "usage: kaonic-sim-air [--listen ADDR] [--loss P] [--rssi DBM] [--bitrate BPS] [--tx-gap-us US]
                  [--queue-frames N] [--no-carrier-sense] [--seed N] [--stats-secs S]
                  [--link A:B[:loss=P][:rssi=DBM]]... [--block A:B]...

  --listen ADDR       UDP address nodes send to (0.0.0.0:7000)
  --loss P            loss probability for pairs not given with --link (0)
  --rssi DBM          RSSI for pairs not given with --link (-60)
  --bitrate BPS       PHY bit rate (2400000: MR-OFDM option 1, MCS 6)
  --tx-gap-us US      per-frame sender time beyond the air time (9000)
  --queue-frames N    frames a sender may queue before frames are dropped (6)
  --no-carrier-sense  send without listening first
  --link A:B:...      loss and RSSI between nodes A and B (both ways)
  --block A:B         A and B cannot hear each other
  --stats-secs S      print counters every S seconds, 0 for never (10)";

struct Args {
    listen: SocketAddr,
    config: MediumConfig,
    seed: u64,
    stats_secs: u64,
    links: Vec<(String, String, LinkParams)>,
    blocks: Vec<(String, String)>,
}

fn pair(text: &str) -> Result<(String, String, &str), String> {
    let mut parts = text.splitn(3, ':');
    let (Some(a), Some(b)) = (parts.next(), parts.next()) else { return Err(format!("{text}: use A:B")) };
    if a.is_empty() || b.is_empty() {
        return Err(format!("{text}: use A:B"));
    }
    Ok((a.to_owned(), b.to_owned(), parts.next().unwrap_or("")))
}

fn args() -> Result<Args, String> {
    let mut args = Args {
        listen: "0.0.0.0:7000".parse().expect("valid address"),
        config: MediumConfig::default(),
        seed: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(1, |elapsed| elapsed.as_nanos() as u64),
        stats_secs: 10,
        links: Vec::new(),
        blocks: Vec::new(),
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let mut value = || iter.next().ok_or_else(|| format!("{flag} needs a value"));
        fn number<T: std::str::FromStr>(flag: &str, text: String) -> Result<T, String> {
            text.parse().map_err(|_| format!("{flag}: not a number: {text}"))
        }
        match flag.as_str() {
            "--listen" => args.listen = value()?.parse().map_err(|_| "--listen: not an address")?,
            "--loss" => args.config.default_link.loss = number(&flag, value()?)?,
            "--rssi" => args.config.default_link.rssi = number(&flag, value()?)?,
            "--bitrate" => args.config.bit_rate = number(&flag, value()?)?,
            "--tx-gap-us" => args.config.tx_gap_us = number(&flag, value()?)?,
            "--queue-frames" => args.config.queue_frames = number(&flag, value()?)?,
            "--no-carrier-sense" => args.config.carrier_sense = false,
            "--seed" => args.seed = number(&flag, value()?)?,
            "--stats-secs" => args.stats_secs = number(&flag, value()?)?,
            "--block" => {
                let (a, b, _) = pair(&value()?)?;
                args.blocks.push((a, b));
            }
            "--link" => {
                let text = value()?;
                let (a, b, rest) = pair(&text)?;
                let mut params = args.config.default_link;
                for setting in rest.split(':').filter(|setting| !setting.is_empty()) {
                    match setting.split_once('=') {
                        Some(("loss", loss)) => params.loss = number("--link loss", loss.to_owned())?,
                        Some(("rssi", rssi)) => params.rssi = number("--link rssi", rssi.to_owned())?,
                        _ => return Err(format!("--link {text}: unknown setting {setting}")),
                    }
                }
                args.links.push((a, b, params));
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if !(0.0..=1.0).contains(&args.config.default_link.loss) || args.links.iter().any(|(_, _, params)| !(0.0..=1.0).contains(&params.loss)) {
        return Err("loss must be between 0 and 1".into());
    }
    Ok(args)
}

fn main() {
    let args = match args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("kaonic-sim-air: {error}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
    runtime.block_on(async move {
        let air = match Air::start(args.listen, args.config, args.seed).await {
            Ok(air) => air,
            Err(error) => {
                eprintln!("kaonic-sim-air: cannot listen on {}: {error}", args.listen);
                std::process::exit(1);
            }
        };
        for (a, b, params) in &args.links {
            air.set_link(a, b, *params);
        }
        for (a, b) in &args.blocks {
            air.block(a, b);
        }
        eprintln!("kaonic-sim-air: listening on {}", air.local_addr());
        if args.stats_secs == 0 {
            std::future::pending::<()>().await;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(args.stats_secs));
        tick.tick().await;
        loop {
            tick.tick().await;
            for (name, stats) in air.stats() {
                eprintln!(
                    "kaonic-sim-air: {name:<8} sent {} dropped {} | received {} lost {} collided {} deaf {}",
                    stats.sent, stats.dropped, stats.received, stats.lost, stats.collided, stats.deaf
                );
            }
        }
    });
}
