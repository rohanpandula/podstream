use anyhow::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::time::Duration;

/// A discovered AirPlay-capable receiver.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Receiver {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub device_id: Option<String>,
    pub model: Option<String>,
    pub flags: Option<String>,
}

pub async fn discover(timeout: Duration, json: bool) -> Result<()> {
    let mdns = ServiceDaemon::new()?;

    let receiver = mdns.browse("_airplay._tcp.local.")?;
    let mut receivers: Vec<Receiver> = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let timeout_left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if timeout_left.is_zero() {
            break;
        }
        let event = match tokio::time::timeout(timeout_left, receiver.recv_async()).await {
            Ok(Ok(event)) => event,
            _ => break,
        };
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let txt = &info.get_properties();
                receivers.push(Receiver {
                    name: info.get_fullname().to_string(),
                    host: info.get_addresses().iter().next().map(|a| a.to_string()).unwrap_or_default(),
                    port: info.get_port(),
                    device_id: txt.get_property_val_str("deviceid").map(|s| s.to_string()),
                    model: txt.get_property_val_str("model").map(|s| s.to_string()),
                    flags: txt.get_property_val_str("flags").map(|s| s.to_string()),
                });
            }
            ServiceEvent::SearchStarted(_) | ServiceEvent::ServiceFound(_, _) => {}
            _ => {}
        }
    }
    mdns.shutdown()?;

    // Dedupe: same device advertised over IPv4 and IPv6.
    let mut seen = std::collections::HashSet::new();
    receivers.retain(|r| {
        let key = (
            r.device_id.clone().unwrap_or_else(|| r.name.clone()),
            r.model.clone().unwrap_or_default(),
        );
        seen.insert(key)
    });
    receivers.sort_by(|a, b| a.name.cmp(&b.name));

    if json {
        println!("{}", serde_json::to_string_pretty(&receivers)?);
    } else {
        if receivers.is_empty() {
            println!("no receivers found");
        }
        for (i, r) in receivers.iter().enumerate() {
            println!(
                "{:>2}  {:<24} {:<16}:{:<5} model={:?}",
                i,
                r.name.trim_end_matches("._airplay._tcp.local."),
                r.host,
                r.port,
                r.model
            );
        }
    }
    Ok(())
}
