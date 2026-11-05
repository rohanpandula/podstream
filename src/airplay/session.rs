//! Session negotiation: two-phase SETUP over the encrypted control channel.
//!
//! Wire format replicated from a capture of a working sender (Unisson):
//! Phase 1: sender identity + timing, rich plist
//! Phase 2: audio stream (type 96, raw LPCM), streamConnectionID = URI id
//! RECORD comes after both SETUP phases.

use anyhow::{bail, Context, Result};
use plist::Value;
use std::net::TcpStream;
use uuid::Uuid;

use super::crypto::EncryptedChannel;

pub struct Session {
    pub channel: EncryptedChannel,
    pub host: String,
    pub port: u16,
    /// The sender's own local IP (receivers put it in the RTSP URI).
    pub local_ip: String,
    pub device_id: String,
    pub session_uuid: Uuid,
    /// Numeric session/stream connection id used in the URI.
    pub conn_id: u32,
    pub cseq: u32,
    pub dacp_id: String,
    pub active_remote: u32,
    pub event_port: Option<u16>,
    pub timing_port: Option<u16>,
    pub data_port: Option<u16>,
    pub control_port: Option<u16>,
    pub debug_next: bool,
}

impl Session {
    pub fn new(
        channel: EncryptedChannel,
        host: &str,
        port: u16,
        local_ip: String,
        device_id: String,
    ) -> Self {
        let conn_id: u32 = rand::random();
        Session {
            channel,
            host: host.to_string(),
            port,
            local_ip,
            device_id,
            session_uuid: Uuid::new_v4(),
            conn_id,
            cseq: 0,
            dacp_id: "1234ABCD5678EF90".to_string(),
            active_remote: rand::random(),
            event_port: None,
            timing_port: None,
            data_port: None,
            control_port: None,
            debug_next: false,
        }
    }

    fn uri(&self) -> String {
        format!("rtsp://{}/{}", self.local_ip, self.conn_id)
    }

    fn request(
        &mut self,
        method: &str,
        uri: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
        self.cseq += 1;
        let mut req = format!("{method} {uri} RTSP/1.0\r\n");
        req.push_str("User-Agent: AirPlay/550.10\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        req.push_str(&format!("CSeq: {}\r\n", self.cseq));
        req.push_str(&format!("DACP-ID: {}\r\n", self.dacp_id));
        req.push_str(&format!("Active-Remote: {}\r\n", self.active_remote));
        req.push_str(&format!("Client-Instance: {}\r\n", self.dacp_id));
        if let Some(ct) = content_type {
            req.push_str(&format!("Content-Type: {ct}\r\n"));
        }
        req.push_str("\r\n");
        let mut msg = req.into_bytes();
        msg.extend_from_slice(body);
        self.channel.send(&msg)?;
        let resp = self.channel.recv()?;
        // Find the header/body boundary in the raw bytes, NOT via a
        // lossy-UTF8 string (binary plist bodies are not UTF-8).
        let sep = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| anyhow::anyhow!("no header terminator in response"))?;
        let headers_bytes = &resp[..sep];
        let body_part = resp[sep + 4..].to_vec();
        let text = String::from_utf8_lossy(headers_bytes).to_string();
        let mut lines = text.lines();
        let status_line = lines.next().unwrap_or_default();
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .context("bad status line")?;
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
            .collect();
        if self.debug_next {
            eprintln!("--- raw response ---\n{text}\n--- end ---");
            self.debug_next = false;
        }
        Ok((status, headers, body_part))
    }

    /// SETUP phase 1: sender identity, timing and event channels.
    pub fn setup_phase1(&mut self, local_timing_port: u16) -> Result<()> {
        let body = plist_dict([
            ("deviceID", Value::String(self.device_id.clone())),
            ("sessionUUID", Value::String(self.session_uuid.to_string().to_uppercase())),
            ("timingPort", Value::Integer(local_timing_port.into())),
            ("timingProtocol", Value::String("NTP".to_string())),
            ("isMultiSelectAirPlay", Value::Boolean(true)),
            ("groupContainsGroupLeader", Value::Boolean(false)),
            ("macAddress", Value::String(self.device_id.clone())),
            ("model", Value::String("Mac18,5".to_string())),
            ("name", Value::String("podstream".to_string())),
            ("osBuildVersion", Value::String("24G71".to_string())),
            ("osName", Value::String("macOS".to_string())),
            ("osVersion", Value::String("15.6".to_string())),
            ("senderSupportsRelay", Value::Boolean(false)),
            ("sourceVersion", Value::String("690.7.1".to_string())),
            ("statsCollectionEnabled", Value::Boolean(false)),
        ]);
        let (status, _headers, resp_body) = self
            .request("SETUP", &self.uri(), Some("application/x-apple-binary-plist"), &body)
            .context("SETUP phase 1")?;
        if status != 200 {
            bail!("SETUP phase 1 failed: {status}");
        }
        let dict = parse_plist(&resp_body)?;
        if let Some(v) = dict.get("eventPort").and_then(|v| v.as_unsigned_integer()) {
            self.event_port = Some(v as u16);
        }
        if let Some(v) = dict.get("timingPort").and_then(|v| v.as_unsigned_integer()) {
            self.timing_port = Some(v as u16);
        }
        Ok(())
    }

    /// SETUP phase 2: audio stream definition (realtime LPCM, type 96) —
    /// exactly what a working sender captured on the wire.
    pub fn setup_phase2(&mut self, local_control_port: u16, shk: [u8; 32]) -> Result<()> {
        let stream_items = [
            ("audioFormat", Value::Integer(2048.into())), // PCM 44100/16/2
            ("audioMode", Value::String("default".to_string())),
            ("controlPort", Value::Integer(local_control_port.into())),
            ("ct", Value::Integer(1.into())), // LPCM
            ("isMedia", Value::Boolean(true)),
            ("latencyMax", Value::Integer(88200.into())),
            ("latencyMin", Value::Integer(4366.into())),
            ("shk", Value::Data(shk.to_vec())),
            ("spf", Value::Integer(352.into())),
            ("sr", Value::Integer(44100.into())),
            ("type", Value::Integer(96.into())),
            ("supportsDynamicStreamID", Value::Boolean(false)),
            ("streamConnectionID", Value::Integer(self.conn_id.into())),
        ];
        let stream = Value::Dictionary(dict_from(stream_items));
        let body = plist_dict([("streams", Value::Array(vec![stream]))]);
        let (status, _headers, resp_body) = self
            .request("SETUP", &self.uri(), Some("application/x-apple-binary-plist"), &body)
            .context("SETUP phase 2")?;
        if status != 200 {
            bail!("SETUP phase 2 failed: {status}");
        }
        let dict = parse_plist(&resp_body)?;
        if let Some(streams) = dict.get("streams").and_then(|v| v.as_array()) {
            if let Some(s) = streams.first().and_then(|s| s.as_dictionary()) {
                for (key, slot) in [
                    ("dataPort", &mut self.data_port),
                    ("controlPort", &mut self.control_port),
                    ("eventPort", &mut self.event_port),
                ] {
                    if let Some(v) = s.get(key).and_then(|v| v.as_unsigned_integer()) {
                        *slot = Some(v as u16);
                    }
                }
            }
        }
        Ok(())
    }

    /// Bodyless RECORD — after both SETUP phases.
    pub fn record(&mut self) -> Result<()> {
        let (status, _headers, _body) = self
            .request("RECORD", &self.uri(), None, &[])
            .context("RECORD")?;
        if status != 200 {
            bail!("RECORD failed: {status}");
        }
        Ok(())
    }

    /// Set receiver volume in dB (-30.0 .. 0.0, 0 = max).
    pub fn set_volume(&mut self, db: f64) -> Result<()> {
        let body = format!("volume: {db:.6}\r\n");
        let (status, _headers, _body) = self
            .request(
                "SET_PARAMETER",
                &self.uri(),
                Some("text/parameters"),
                body.as_bytes(),
            )
            .context("SET_PARAMETER volume")?;
        if status != 200 {
            bail!("SET_PARAMETER volume failed: {status}");
        }
        Ok(())
    }

    /// Connect to the receiver's event port (reverse event channel).
    pub fn connect_events(&self) -> Result<TcpStream> {
        let port = self.event_port.context("no event port from SETUP phase 1")?;
        TcpStream::connect((self.host.as_str(), port)).context("connecting event channel")
    }
}

fn dict_from(items: impl IntoIterator<Item = (&'static str, Value)>) -> plist::Dictionary {
    let mut dict = plist::Dictionary::new();
    for (k, v) in items {
        dict.insert(k.to_string(), v);
    }
    dict
}

fn plist_dict(items: impl IntoIterator<Item = (&'static str, Value)>) -> Vec<u8> {
    let mut buf = Vec::new();
    Value::Dictionary(dict_from(items))
        .to_writer_binary(&mut buf)
        .expect("plist encode");
    buf
}

fn parse_plist(bytes: &[u8]) -> Result<plist::Dictionary> {
    let value = Value::from_reader(std::io::Cursor::new(bytes)).context("parsing plist response")?;
    value.into_dictionary().context("expected plist dictionary")
}
