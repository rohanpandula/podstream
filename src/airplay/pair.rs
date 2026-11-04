//! AirPlay 2 pair-setup client — HKPv4 transient pairing.
//!
//! Wire format verified by packet capture of a working client against a real
//! receiver (see protocol.md):
//!
//!   M1: POST /pair-setup {method=0, state=1, flags(0x13)=0x10}
//!   M2: <- {salt(16), server public key B(384 = 3072-bit SRP group)}
//!   M3: -> {public key A(384), client proof(64)}   [SRP-6a, PIN "3939"]
//!   M4: <- {server proof(64)}
//!
//! After M4 the SRP session key is used to derive ChaCha20-Poly1305
//! control-channel keys via HKDF-SHA512 ("Control-Salt" /
//! "Control-{Read,Write}-Encryption-Key").

use anyhow::{bail, Context, Result};
use hkdf::Hkdf;

use sha2::Sha512;
use super::crypto::EncryptedChannel;
use super::rtsp::RtspClient;
use super::srp::SrpClient;
use super::tlv::Tlv;

pub const PAIR_SETUP_URI: &str = "/pair-setup";
pub const PIN: &str = "3939";
pub const IDENTITY: &[u8] = b"Pair-Setup";

fn headers() -> Vec<(&'static str, String)> {
    vec![
        ("User-Agent", "AirPlay/320.20".to_string()),
        ("Connection", "keep-alive".to_string()),
        ("X-Apple-HKP", "4".to_string()),
        ("Content-Type", "application/octet-stream".to_string()),
    ]
}

#[allow(non_snake_case)]
pub struct PairingKeys {
    pub read_key: [u8; 32],
    pub write_key: [u8; 32],
}

pub struct PairSetupClient {
    pub client: RtspClient,
    write_key: Option<[u8; 32]>,
    read_key: Option<[u8; 32]>,
}

impl PairSetupClient {
    pub fn new(host: &str, port: u16) -> Result<Self> {
        let mut client = RtspClient::connect(host, port)?;
        // The working client sends /pair-pin-start before /pair-setup.
        client.request("POST", "/pair-pin-start", &headers(), &[])?;
        Ok(PairSetupClient {
            client,
            write_key: None,
            read_key: None,
        })
    }

    /// Run the full M1..M4 transient pair-setup and derive channel keys.
    pub fn pair(&mut self) -> Result<PairingKeys> {
        self.pair_with(PIN)
    }

    pub fn pair_with(&mut self, pin: &str) -> Result<PairingKeys> {
        // M1
        let m1 = Tlv::new()
            .add(0x00, [0x00])
            .add(0x06, [0x01])
            .add(0x13, [0x10])
            .encode();
        let resp = self
            .client
            .request("POST", PAIR_SETUP_URI, &headers(), &m1)
            .context("M1")?;
        if resp.status != 200 {
            bail!("M1 failed: status {}", resp.status);
        }
        let tlv = Tlv::decode(&resp.body)?;
        if let Some(err) = tlv.get(0x07) {
            bail!("pairing rejected by receiver (TLV error {err:?})");
        }
        let salt = tlv.get(0x02).context("M2: no salt")?.to_vec();
        let b_pub = tlv.get(0x03).context("M2: no server public key")?.to_vec();
        // Pad B to the group width (server may send a leading-zero-stripped value).
        let mut b_pub_padded = vec![0u8; 384 - b_pub.len().min(384)];
        b_pub_padded.extend_from_slice(&b_pub);
        let b_pub = b_pub_padded;

        // Apple's HomeKit SRP-6a variant (SHA-512, 3072-bit group, transient PIN).
        let a: [u8; 64] = rand::random();
        let mut srp = SrpClient::new(IDENTITY, pin.as_bytes(), &a);
        let a_pub = srp.public_key();
        srp.proof(&salt, &b_pub)
            .map_err(|e| anyhow::anyhow!("SRP proof: {e:?}"))?;
        let client_proof = srp.m1().to_vec();

        // M3 — field order matches the captured working client (state first).
        let m3 = Tlv::new()
            .add(0x06, [0x03])
            .add(0x03, a_pub)
            .add(0x04, client_proof)
            .encode();
        let resp = self
            .client
            .request("POST", PAIR_SETUP_URI, &headers(), &m3)
            .context("M3")?;
        if resp.status != 200 {
            bail!("M3 failed: status {}", resp.status);
        }
        let tlv = Tlv::decode(&resp.body)?;
        if let Some(err) = tlv.get(0x07) {
            bail!("M3 rejected (TLV error {err:?})");
        }
        let server_proof = tlv.get(0x04).context("M4: no server proof")?;
        srp.verify_server(server_proof)
            .map_err(|e| anyhow::anyhow!("server proof mismatch: {e:?}"))?;

        // Derive control channel keys from the SRP session key.
        let session_key = srp.session_key();
        let hk = Hkdf::<Sha512>::new(Some(b"Control-Salt"), session_key);
        let mut write_key = [0u8; 32];
        let mut read_key = [0u8; 32];
        hk.expand(b"Control-Write-Encryption-Key", &mut write_key).map_err(|e| anyhow::anyhow!("HKDF write key: {e:?}"))?;
        hk.expand(b"Control-Read-Encryption-Key", &mut read_key).map_err(|e| anyhow::anyhow!("HKDF read key: {e:?}"))?;
        self.write_key = Some(write_key);
        self.read_key = Some(read_key);
        Ok(PairingKeys { read_key, write_key })
    }

    /// Pair, then wrap the connection in the encrypted control channel.
    pub fn into_encrypted_after_pair(mut self) -> Result<EncryptedChannel> {
        self.pair()?;
        let w = self.write_key.context("pair() first")?;
        let r = self.read_key.context("pair() first")?;
        let ip = self.client.local_ip()?;
        Ok((EncryptedChannel::new(self.client.into_stream(), w, r), ip).0)
    }

    /// The sender's local IP (used in the RTSP URI).
    pub fn local_ip(&self) -> std::io::Result<std::net::IpAddr> {
        self.client.local_ip()
    }
}
