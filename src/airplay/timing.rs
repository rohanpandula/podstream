//! NTP-like timing responder for AirPlay 2 (single-room).
//!
//! The receiver sends timing requests to the sender's timingPort:
//!   request:  [0]=0x80 [1]=0xd2 [2]=seq, ..., client timestamp at bytes 24..32
//!   reply:    [0]=0x80 [1]=0xd3 [2]=seq, client ts echoed at 8..16,
//!             receive ts at 16..24, transmit ts at 24..32 (32 bytes total)
//!
//! The receiver will not answer the stream SETUP until it has measured the
//! sender's clock, so a wrong reply format looks like a SETUP failure.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const NTP_EPOCH_DELTA: u64 = 2_208_988_800;

fn ntp_now() -> (u32, u32) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (
        (now.as_secs() + NTP_EPOCH_DELTA) as u32,
        (now.subsec_nanos() as u64 * u32::MAX as u64 / 1_000_000_000) as u32,
    )
}

pub static REQUESTS: AtomicUsize = AtomicUsize::new(0);

/// Spawn a thread answering timing requests on `socket`.
pub fn spawn_responder(socket: UdpSocket) -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let flag = running.clone();
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(200)))
        .ok();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while flag.load(Ordering::Relaxed) {
            match socket.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    REQUESTS.fetch_add(1, Ordering::Relaxed);
                    if n < 32 || buf[0] != 0x80 || buf[1] != 0xd2 {
                        continue;
                    }
                    let mut res = [0u8; 32];
                    res[0] = 0x80;
                    res[1] = 0xd3;
                    res[2] = buf[2];
                    // Echo the client's transmit timestamp.
                    res[8..16].copy_from_slice(&buf[24..32]);
                    let (sec, frac) = ntp_now();
                    res[16..20].copy_from_slice(&sec.to_be_bytes());
                    res[20..24].copy_from_slice(&frac.to_be_bytes());
                    let (sec, frac) = ntp_now();
                    res[24..28].copy_from_slice(&sec.to_be_bytes());
                    res[28..32].copy_from_slice(&frac.to_be_bytes());
                    let _ = socket.send_to(&res, peer);
                }
                Err(_) => continue,
            }
        }
    });
    running
}
