use anyhow::Result;
use clap::{Parser, Subcommand};
use std::time::Duration;

mod airplay;
mod capture;
mod discover;



#[derive(Parser)]
#[command(
    name = "podstream",
    version,
    about = "Stream macOS system audio to AirPlay receivers (HomePod), from the CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan the local network for AirPlay receivers
    Discover {
        /// How long to scan, in seconds
        #[arg(long, default_value_t = 3)]
        timeout: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Test pair-setup M1/M2 exchange against a receiver (host[:port])
    Pair {
        host: String,
    },
    /// Pair, negotiate the session (both SETUP phases), report ports
    Setup { host: String },
    /// Pair and send one encrypted request over the control channel
    Probe {
        host: String,
    },
    /// Capture system audio for N seconds and print stats (test capture)
    TestCapture {
        #[arg(long, default_value_t = 3)]
        seconds: u64,
    },
    /// Connect to a receiver and start streaming (placeholder)
    Connect {
        /// Receiver name (from `discover`) or index
        name: String,
    },
    /// Stop streaming (placeholder)
    Disconnect,
    /// Set receiver volume 0-100 (placeholder)
    Volume {
        percent: u8,
    },
    /// Show current state (placeholder)
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

fn channel_local_ip(_c: &airplay::crypto::EncryptedChannel) -> String {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect("10.0.0.204:7000").unwrap();
    sock.local_addr().unwrap().ip().to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Discover { timeout, json } => {
            discover::discover(Duration::from_secs(timeout), json).await
        }
        Command::Pair { host } => {
            let (host, port) = match host.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(7000)),
                None => (host, 7000),
            };
            let mut pair = airplay::pair::PairSetupClient::new(&host, port)?;
            let keys = pair.pair().or_else(|e| {
                eprintln!("PIN 3939 failed ({e}); retrying with empty password");
                airplay::pair::PairSetupClient::new(&host, port)?.pair_with("")
            })?;
            println!(
                "pair-setup complete: read_key {} write_key {}",
                hex::encode(keys.read_key),
                hex::encode(keys.write_key)
            );
            Ok(())
        }
        Command::Setup { host } => {
            let (host, port) = match host.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(7000)),
                None => (host, 7000),
            };
            let pair = airplay::pair::PairSetupClient::new(&host, port)?;

            // Sender-side UDP sockets: timing (NTP replies) and control (RTCP).
            let timing = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let timing_port = timing.local_addr()?.port();
            let _timing_stop = airplay::timing::spawn_responder(timing);
            let control = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let control_port = control.local_addr()?.port();

            let device_id = "AA:BB:CC:DD:EE:FF".to_string();
            let channel = pair.into_encrypted_after_pair()?;
            let local_ip = channel_local_ip(&channel);
            let mut session = airplay::session::Session::new(
                channel,
                &host,
                port,
                local_ip,
                device_id,
            );
            session.setup_phase1(timing_port)?;
            println!(
                "SETUP phase 1 OK: event_port={:?} timing_port={:?}",
                session.event_port, session.timing_port
            );
            let events = session.connect_events();
            println!("event channel: {:?}", events.is_ok());
            let _events_keepalive = events;

            let shk: [u8; 32] = rand::random();
            session.setup_phase2(control_port, shk)?;
            session.record()?;
            println!(
                "SETUP phase 2 OK: data_port={:?} control_port={:?} event_port={:?}",
                session.data_port, session.control_port, session.event_port
            );
            Ok(())
        }
        Command::Probe { host } => {
            let (host, port) = match host.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(7000)),
                None => (host, 7000),
            };
            let pair = airplay::pair::PairSetupClient::new(&host, port)?;
            let mut channel = pair.into_encrypted_after_pair()?;
            // POST /feedback is used as a keepalive; any authenticated
            // reply proves the whole encrypted channel works.
            let resp = channel.request("POST", "/feedback", &[], b"")?;
            println!("decrypted response ({} bytes):\n{}", resp.len(), resp);
            Ok(())
        }
        Command::TestCapture { seconds } => {
            let mut frames = 0usize;
            let mut samples = 0usize;
            let mut sr = 0u32;
            let stats = std::sync::Arc::new(std::sync::Mutex::new((0usize, 0usize, 0u32)));
            let stats2 = stats.clone();
            capture::capture(Duration::from_secs(seconds), move |frame| {
                let mut s = stats2.lock().unwrap();
                s.0 += 1;
                s.1 += frame.data.len();
                s.2 = frame.channels;
            })?;
            let (frames, samples, sr) = std::sync::Arc::try_unwrap(stats)
                .ok()
                .and_then(|m| m.into_inner().ok())
                .unwrap_or_default();
            println!("captured {frames} frames, {samples} samples, channels={sr}");
            Ok(())
        }
        Command::Connect { name } => {
            println!("connect: not implemented yet (receiver: {name})");
            Ok(())
        }
        Command::Disconnect => {
            println!("disconnect: not implemented yet");
            Ok(())
        }
        Command::Volume { percent } => {
            println!("volume: not implemented yet ({percent}%)");
            Ok(())
        }
        Command::Status { json } => {
            let state = serde_json::json!({ "state": "idle" });
            if json {
                println!("{}", serde_json::to_string_pretty(&state)?);
            } else {
                println!("idle");
            }
            Ok(())
        }
    }
}
