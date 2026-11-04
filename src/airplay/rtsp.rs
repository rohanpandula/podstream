//! Minimal RTSP/HTTP client for AirPlay 2 (RTSP over TCP port 7000,
//! requests are HTTP-like with binary bodies).

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct RtspClient {
    stream: TcpStream,
    pub cseq: u32,
}

pub struct RtspResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RtspClient {
    pub fn into_stream(self) -> std::net::TcpStream {
        self.stream
    }

    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let stream = TcpStream::connect((host, port))
            .with_context(|| format!("connecting to {host}:{port}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(RtspClient { stream, cseq: 0 })
    }

    pub fn request(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<RtspResponse> {
        let version = if method == "GET" { "RTSP/1.0" } else { "HTTP/1.1" };
        self.request_version(method, uri, headers, body, version)
    }

    pub fn request_version(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: &[u8],
        version: &str,
    ) -> Result<RtspResponse> {
        self.cseq += 1;
        let mut req = format!("{method} {uri} {version}\r\nCSeq: {}\r\n", self.cseq);
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        req.push_str("User-Agent: podstream/0.1\r\n\r\n");
        self.stream.write_all(req.as_bytes())?;
        self.stream.write_all(body)?;
        self.read_response()
    }

    fn read_response(&mut self) -> Result<RtspResponse> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        // read headers
        let header_end;
        loop {
            let n = self.stream.read(&mut tmp)?;
            if n == 0 {
                anyhow::bail!("connection closed while reading headers");
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or_default();
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .context("bad status line")?;
        let mut headers = Vec::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let content_length: usize = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);

        let mut body = buf[header_end..].to_vec();
        while body.len() < content_length {
            let n = self.stream.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(content_length);
        Ok(RtspResponse { status, headers, body })
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
