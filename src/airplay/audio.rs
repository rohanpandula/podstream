//! Realtime (type 96) audio RTP streaming.
//!
//! Packet: [RTP header (12B)][ChaCha20-Poly1305 ciphertext][tag (16B)][nonce (8B)]
//! - key = shk from SETUP phase 2
//! - AAD = RTP timestamp (4B BE) || SSRC (4B BE)
//! - nonce = 12 bytes, seq (u16 LE) at offset 4; last 8 bytes transmitted
//! - marker bit set on the first packet
//!
//! Sync packets (PT 84) go to the control port once per second.

use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub const PAYLOAD_TYPE: u8 = 96;
pub const SYNC_TYPE: u8 = 84;
pub const SAMPLES_PER_FRAME: u32 = 352;
pub const SAMPLE_RATE: u32 = 44100;

pub struct AudioSender {
    sock: UdpSocket,
    cipher: ChaCha20Poly1305,
    data_port: u16,
    control_port: u16,
    seq: u16,
    ssrc: u32,
    /// RTP timestamp of the next frame (44.1kHz clock).
    pub rtptime: u32,
    first: bool,
}

impl AudioSender {
    pub fn new(sock: UdpSocket, shk: [u8; 32], host: &str, data_port: u16, control_port: u16) -> Self {
        let ssrc = rand::random::<u32>() | 1;
        AudioSender {
            sock,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&shk)),
            data_port,
            control_port,
            seq: 0,
            ssrc,
            rtptime: 4366,
            first: true,
        }
    }

    /// Send a sync (PT 84) packet: correlates RTP timestamps to NTP time.
    pub fn send_sync(&mut self) -> Result<()> {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x80;
        pkt[1] = 0x80 | SYNC_TYPE; // marker set
        pkt[2..4].copy_from_slice(&self.seq.to_be_bytes());
        // NTP now
        let (sec, frac) = ntp_now();
        pkt[8..12].copy_from_slice(&sec.to_be_bytes());
        pkt[12..16].copy_from_slice(&frac.to_be_bytes());
        // RTP timestamp for the next audio packet
        pkt[16..20].copy_from_slice(&self.rtptime.to_be_bytes());
        self.sock
            .send_to(&pkt, ("0.0.0.0", self.control_port))
            .map_err(|e| anyhow::anyhow!("send sync: {e}"))?;
        Ok(())
    }

    /// Encrypt and send one frame of interleaved s16 stereo samples to `host`.
    pub fn send_frame_to(&mut self, pcm: &[u8], host: &str) -> Result<()> {
        let marker = if self.first { 0x80 } else { 0x00 };
        self.first = false;

        let mut header = [0u8; 12];
        header[0] = 0x80;
        header[1] = marker | PAYLOAD_TYPE;
        header[2..4].copy_from_slice(&self.seq.to_be_bytes());
        header[4..8].copy_from_slice(&self.rtptime.to_be_bytes());
        header[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        let mut aad = [0u8; 8];
        aad[0..4].copy_from_slice(&self.rtptime.to_be_bytes());
        aad[4..8].copy_from_slice(&self.ssrc.to_be_bytes());

        let mut nonce = [0u8; 12];
        nonce[4..6].copy_from_slice(&self.seq.to_le_bytes());

        let ct = self
            .cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: pcm, aad: &aad })
            .map_err(|_| anyhow::anyhow!("audio encrypt failed"))?;

        let mut packet = Vec::with_capacity(12 + ct.len() + 8);
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&ct);
        packet.extend_from_slice(&nonce[4..12]);

        self.sock
            .send_to(&packet, (host, self.data_port))
            .map_err(|e| anyhow::anyhow!("send audio: {e}"))?;
        self.seq = self.seq.wrapping_add(1);
        self.rtptime = self.rtptime.wrapping_add(SAMPLES_PER_FRAME);
        Ok(())
    }
}

fn ntp_now() -> (u32, u32) {
    const NTP_EPOCH_DELTA: u64 = 2_208_988_800;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    (
        (now.as_secs() + NTP_EPOCH_DELTA) as u32,
        (now.subsec_nanos() as u64 * u32::MAX as u64 / 1_000_000_000) as u32,
    )
}

/// Shared counters for the streaming loop.
pub struct StreamStats {
    pub frames: AtomicU64,
    pub bytes: AtomicU64,
    pub running: Arc<AtomicBool>,
}
