//! TLV8 codec used by AirPlay/HomeKit pairing (each item: type, length, value).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlvType {
    Method = 0x00,
    Identifier = 0x01,
    Salt = 0x02,
    PublicKey = 0x03,
    Proof = 0x04,
    EncryptedData = 0x05,
    State = 0x06,
    Error = 0x07,
    CertificateId = 0x0a,
    Mismatch = 0x0b,
}

#[derive(Debug, Clone, Default)]
pub struct Tlv(pub Vec<(u8, Vec<u8>)>);

impl Tlv {
    pub fn new() -> Self {
        Tlv(Vec::new())
    }

    pub fn add(mut self, tag: u8, value: impl AsRef<[u8]>) -> Self {
        self.0.push((tag, value.as_ref().to_vec()));
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, value) in &self.0 {
            // Values longer than 255 bytes are split across repeated tags.
            if value.is_empty() {
                out.push(*tag);
                out.push(0);
                continue;
            }
            for chunk in value.chunks(255) {
                out.push(*tag);
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let tag = bytes[i];
            let len = bytes[i + 1] as usize;
            let end = i + 2 + len;
            if end > bytes.len() {
                anyhow::bail!("truncated TLV item");
            }
            let value = &bytes[i + 2..end];
            // append to previous item with same tag (chunked long values)
            if let Some(last) = items.last_mut() {
                if last.0 == tag {
                    last.1.extend_from_slice(value);
                    i = end;
                    continue;
                }
            }
            items.push((tag, value.to_vec()));
            i = end;
        }
        Ok(Tlv(items))
    }

    pub fn get(&self, tag: u8) -> Option<&[u8]> {
        self.0.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.as_slice())
    }
}
