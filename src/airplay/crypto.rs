//! Encrypted control channel used after pair-setup/pair-verify.
//!
//! Framing (verified against captured traffic of a working sender):
//! each frame is a 2-byte little-endian plaintext length, then the
//! ChaCha20-Poly1305 ciphertext and its 16-byte tag. The length prefix
//! is the AEAD's associated data. Nonces are a 64-bit little-endian
//! counter in the last 8 bytes of a 12-byte nonce, counted independently
//! in each direction, both starting at zero.

use anyhow::{bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct EncryptedChannel {
    stream: TcpStream,
    write: ChaCha20Poly1305,
    read: ChaCha20Poly1305,
    write_counter: u64,
    read_counter: u64,
}

impl EncryptedChannel {
    pub fn new(stream: TcpStream, write_key: [u8; 32], read_key: [u8; 32]) -> Self {
        EncryptedChannel {
            stream,
            write: ChaCha20Poly1305::new(Key::from_slice(&write_key)),
            read: ChaCha20Poly1305::new(Key::from_slice(&read_key)),
            write_counter: 0,
            read_counter: 0,
        }
    }

    fn write_nonce(counter: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&counter.to_le_bytes());
        Nonce::from(n)
    }

    /// Encrypt and send one plaintext frame.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let len = plaintext.len();
        if len > 0xFFFF {
            bail!("frame too large: {len}");
        }
        let aad = (len as u16).to_le_bytes();
        let ct = self
            .write
            .encrypt(
                &Self::write_nonce(self.write_counter),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypt failed"))?;
        self.write_counter += 1;
        let mut frame = Vec::with_capacity(2 + ct.len());
        frame.extend_from_slice(&aad);
        frame.extend_from_slice(&ct);
        self.stream.write_all(&frame)?;
        Ok(())
    }

    /// Read, authenticate, and decrypt one frame.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let mut aad = [0u8; 2];
        self.stream.read_exact(&mut aad)?;
        let len = u16::from_le_bytes(aad) as usize;
        let mut buf = vec![0u8; len + 16];
        self.stream.read_exact(&mut buf)?;
        let pt = self
            .read
            .decrypt(
                &Self::write_nonce(self.read_counter),
                Payload {
                    msg: &buf,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("decrypt/auth failed (frame {}) — keys or framing wrong", self.read_counter))?;
        self.read_counter += 1;
        Ok(pt)
    }

    /// Send an RTSP/HTTP request over the encrypted channel and read the
    /// encrypted response (headers + body as plaintext bytes).
    pub fn request(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<String> {
        let mut req = format!("{method} {uri} RTSP/1.0\r\n");
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        let mut msg = req.into_bytes();
        msg.extend_from_slice(body);
        self.send(&msg)?;
        let resp = self.recv()?;
        Ok(String::from_utf8_lossy(&resp).to_string())
    }
}
