//! Realtime (type 96) audio RTP streaming + sync (PT 84) packets.
//!
//! Audio packet: [RTP header (12B)][ChaCha20-Poly1305 ciphertext][tag (16B)][nonce (8B)]
//! - key = shk from SETUP phase 2
//! - AAD = RTP timestamp (4B BE) || SSRC (4B BE)
//! - nonce = 12 bytes, seq (u16 LE) at offset 4; last 8 bytes transmitted
//!
//! Sync packet (20B, observed from a working sender):
//!   [0]=0x80 [1]=0xd4 [2..4]=seq [4..8]=current rtptime
//!   [8..12]=NTP seconds [12..16]=NTP fraction [16..20]=next rtptime

use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::net::UdpSocket;

pub const PAYLOAD_TYPE: u8 = 96;
pub const SAMPLES_PER_FRAME: u32 = 352;
pub const SAMPLE_RATE: u32 = 44100;

pub struct AudioSender {
    sock: UdpSocket,
    cipher: ChaCha20Poly1305,
    data_port: u16,
    control_port: u16,
    seq: u16,
    sync_seq: u16,
    ssrc: u32,
    /// RTP timestamp of the next frame (44.1kHz clock).
    pub rtptime: u32,
    /// RTP-time playback latency ahead of `rtptime`. The sync packet's
    /// "next RTP timestamp" must be `rtptime + latency` so the receiver
    /// knows it has `latency` samples to buffer. Setting it to `rtptime`
    /// (0 latency) makes the HomePod play with a 0-sample buffer -> static.
    latency: u32,
    /// Set on the first audio frame (RTP marker bit).
    first_audio: bool,
    /// Set on the first sync packet (extension bit, after RECORD).
    first_sync: bool,
}

impl AudioSender {
    pub fn new(
        sock: UdpSocket,
        shk: [u8; 32],
        data_port: u16,
        control_port: u16,
    ) -> Self {
        Self {
            sock,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&shk)),
            data_port,
            control_port,
            seq: rand::random::<u16>().wrapping_add(9000),
            sync_seq: rand::random::<u16>(),
            ssrc: rand::random::<u32>() | 1,
            rtptime: 1_418_702,
            latency: 88_200, // 2s of 44.1k samples, the phase-2 latencyMax
            first_audio: true,
            first_sync: true,
        }
    }

    /// Set the playback latency in RTP-time samples (receiver jitter buffer).
    pub fn set_latency(&mut self, latency: u32) { self.latency = latency; }

    /// Encrypt and send one frame of interleaved s16 stereo samples to `host`.
    pub fn send_frame_to(&mut self, pcm: &[u8], host: &str) -> Result<()> {
        let mut header = [0u8; 12];
        header[0] = 0x80;
        // Marker bit set on the first audio frame so the receiver anchors
        // its jitter buffer to the stream start.
        header[1] = if self.first_audio { 0x80 | PAYLOAD_TYPE } else { PAYLOAD_TYPE };
        self.first_audio = false;
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
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: pcm,
                    aad: &aad,
                },
            )
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

    /// Send a sync (PT 84) packet to the receiver's control port.
    pub fn send_sync(&mut self, host: &str) -> Result<()> {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x80;
        // Extension bit (0x10) on the first sync packet after RECORD.
        pkt[1] = if self.first_sync { 0x10 | 0xd4 } else { 0xd4 };
        self.first_sync = false;
        pkt[2..4].copy_from_slice(&self.sync_seq.to_be_bytes());
        pkt[4..8].copy_from_slice(&self.rtptime.to_be_bytes());
        let (sec, frac) = ntp_now();
        pkt[8..12].copy_from_slice(&sec.to_be_bytes());
        pkt[12..16].copy_from_slice(&frac.to_be_bytes());
        // "next" RTP timestamp = current + latency, NOT current. Tells the
        // receiver it has `latency` samples buffered before playback.
        pkt[16..20].copy_from_slice(&self.rtptime.wrapping_add(self.latency).to_be_bytes());
        self.sock
            .send_to(&pkt, (host, self.control_port))
            .map_err(|e| anyhow::anyhow!("send sync: {e}"))?;
        self.sync_seq = self.sync_seq.wrapping_add(1);
        // Once audio frames start flowing, clear the extension/marker primacy.
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
