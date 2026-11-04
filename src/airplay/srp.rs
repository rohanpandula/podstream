//! Apple HomeKit SRP-6a variant (SHA-512, RFC 5054 group 3072).
//!
//! Apple deviates from RFC 5054 in exactly one place, and it matters:
//! k = H(N | PAD(g)) and u = H(PAD(A) | PAD(B)) use SRP-6a PAD(),
//! but the session key and the proof hash use each value's *natural*
//! big-endian byte string (H(g) hashes the single byte 0x05, A and B
//! are unpadded). Confirmed against a real receiver; a padded variant
//! completes the exchange and still fails with kTLVError_Authentication.

use anyhow::{bail, Result};
use num_bigint::BigUint;
use sha2::{Digest, Sha512};

/// RFC 5054 / RFC 3526 group 3072 (safe prime, generator 5).
pub struct Group {
    pub n: BigUint,
    pub g: BigUint,
}

impl Group {
    pub fn g3072() -> Self {
        // RFC 3526 3072-bit MODP group
        const N_HEX: &str = concat!(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
            "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
            "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
            "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
            "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
            "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
            "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
        );
        Group {
            n: BigUint::parse_bytes(N_HEX.as_bytes(), 16).unwrap(),
            g: BigUint::from(5u32),
        }
    }

    fn pad_len(&self) -> usize {
        ((self.n.bits() + 7) / 8) as usize
    }

    fn pad(&self, x: &BigUint) -> Vec<u8> {
        let b = x.to_bytes_be();
        let n = self.pad_len();
        if b.len() >= n {
            b
        } else {
            let mut out = vec![0u8; n];
            out[n - b.len()..].copy_from_slice(&b);
            out
        }
    }
}

fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

pub struct SrpClient {
    group: Group,
    identity: Vec<u8>,
    password: Vec<u8>,
    a: BigUint,
    a_pub: BigUint,
    k: BigUint,
    key: Option<Vec<u8>>,
    m1: Option<Vec<u8>>,
}

impl SrpClient {
    /// `a_bytes` should be 32+ random bytes.
    pub fn new(identity: &[u8], password: &[u8], a_bytes: &[u8]) -> Self {
        let group = Group::g3072();
        let a = BigUint::from_bytes_be(a_bytes);
        let a_pub = group.g.modpow(&a, &group.n);
        // k = H(N | PAD(g))
        let k = BigUint::from_bytes_be(&sha512(&[
            &group.n.to_bytes_be(),
            &group.pad(&group.g),
        ]));
        SrpClient {
            group,
            identity: identity.to_vec(),
            password: password.to_vec(),
            a,
            a_pub,
            k,
            key: None,
            m1: None,
        }
    }

    /// A, padded to the group width for the wire.
    pub fn public_key(&self) -> Vec<u8> {
        self.group.pad(&self.a_pub)
    }

    /// x = H(salt | H(identity | ":" | password))
    fn x(&self, salt: &[u8]) -> BigUint {
        let inner = sha512(&[&self.identity, b":", &self.password]);
        BigUint::from_bytes_be(&sha512(&[salt, &inner]))
    }

    /// Consumes the server's salt and B, derives the session key,
    /// returns the client proof M1.
    pub fn proof(&mut self, salt: &[u8], server_pub: &[u8]) -> Result<()> {
        let b = BigUint::from_bytes_be(server_pub);
        if (&b % &self.group.n).to_string() == "0" {
            bail!("server public key is zero mod N");
        }
        // u = H(PAD(A) | PAD(B))
        let u = BigUint::from_bytes_be(&sha512(&[
            &self.group.pad(&self.a_pub),
            &self.group.pad(&b),
        ]));
        let x = self.x(salt);

        // S = (B - k*g^x) ^ (a + u*x) mod N
        let gx = self.group.g.modpow(&x, &self.group.n);
        let kgx = (&self.k * &gx) % &self.group.n;
        let base = (&b + &self.group.n - &kgx) % &self.group.n;
        let exp = &self.a + &(u * x);
        let s = base.modpow(&exp, &self.group.n);

        // K = H(S) with S's natural byte string (Apple's quirk).
        let key = sha512(&[&s.to_bytes_be()]);

        // M1 = H( H(N) XOR H(g) | H(I) | salt | A | B | K )
        // — with N, g, A, B as natural byte strings (unpadded).
        let hn = sha512(&[&self.group.n.to_bytes_be()]);
        let hg = sha512(&[&self.group.g.to_bytes_be()]);
        let xor: Vec<u8> = hn.iter().zip(hg.iter()).map(|(x, y)| x ^ y).collect();
        let m1 = sha512(&[
            &xor,
            &sha512(&[&self.identity]),
            salt,
            &self.a_pub.to_bytes_be(),
            &b.to_bytes_be(),
            &key,
        ]);
        self.key = Some(key);
        self.m1 = Some(m1);
        Ok(())
    }

    pub fn m1(&self) -> &[u8] {
        self.m1.as_deref().expect("call proof() first")
    }

    pub fn session_key(&self) -> &[u8] {
        self.key.as_deref().expect("call proof() first")
    }

    /// M2 = H(A | M1 | K), A unpadded.
    pub fn verify_server(&self, server_proof: &[u8]) -> Result<()> {
        let want = sha512(&[
            &self.a_pub.to_bytes_be(),
            self.m1(),
            self.session_key(),
        ]);
        if want != server_proof {
            bail!("server proof mismatch");
        }
        Ok(())
    }
}
