# podstream

Stream your Mac's system audio to an AirPlay receiver (HomePod), from the CLI — no
GUI, no audio driver install, no licence/telemetry/updater, nothing phones home.

Built as a clean-room, macOS-only, CLI-first open-source reimplementation of the
*kind* of app Unisson (proprietary, by Jérémi Marceau) is — using reverse
engineering of its released binary only to understand the public AirPlay 2
protocol. All code here is original; all protocol constants are from the public
AirPlay 2 spec / open-source references (OwnTone, libraop, openairplay, pyatv).

## Status (2026-11-04)

**Works end-to-end against real Apple hardware:**

| Milestone | Status |
|---|---|
| `discover` — mDNS scan for `_airplay._tcp` receivers | ✅ |
| `test-capture` — system audio via ScreenCaptureKit (no driver, no admin) | ✅ |
| `pair` — HomeKit transient pair-setup (HKPv4), M1–M4 | ✅ verified vs real HomePod |
| `probe` — encrypted control channel (ChaCha20-Poly1305 framing) | ✅ verified vs real HomePod |
| `setup` — SETUP phase 1 + 2, event channel, RECORD | ✅ verified vs real HomePod |
| `connect` — audio streaming | ⚠️ **partially working** (see below) |

## Commands

```
podstream discover [--timeout 3] [--json]
podstream pair <host[:port]>      # run pair-setup against a receiver
podstream setup <host[:port]>     # pair + full session negotiation, print ports
podstream probe <host[:port]>     # pair + one encrypted round trip
podstream test-capture [--seconds 3]  # verify audio capture
podstream connect <host[:port]> [--seconds 60]  # stream Mac audio to receiver
```

Single-receiver HomePods in the dev environment (per `podstream discover`):
`10.0.0.204` = "Baby Room", `10.0.0.66` = "Living Room (2)".

## Protocol notes (the interesting bits)

### Pairing (HKPv4 transient)
- `POST /pair-pin-start`, then `POST /pair-setup` with `X-Apple-HKP: 4`
  (HKP 3 on a HomePod returns a valid-looking M2 and only fails at M4).
- TLV: `method=0, state=1, flags(0x13)=0x10`; server replies with 16-byte salt
  and a 3072-bit SRP public key (may arrive 383 bytes — leading zero stripped).
- **Apple's SRP-6a deviates from RFC 5054:** the session key and the proof
  hash each value's *natural* big-endian bytes (`H(g)` = SHA-512 of the single
  byte `0x05`); only `k = H(N | PAD(g))` and `u = H(PAD(A) | PAD(B))` use the
  RFC's PAD(). The standard `srp` crate pads everywhere, completes the exchange,
  and still gets `kTLVError_Authentication`. Implemented by hand in
  `src/airplay/srp.rs`.
- PIN is `"3939"` (empty string also accepted as fallback by some receivers).
  After M4: server proof verified, then control keys via HKDF-SHA512 with salt
  `Control-Salt` / info `Control-{Write,Read}-Encryption-Key`.

### Control channel
After M4, every frame is `2-byte LE plaintext length || ChaCha20-Poly1305
ciphertext || 16-byte tag`, the length prefix as AAD, per-direction u64 counter
nonces starting at zero. Verified both ways against a real receiver
(`podstream probe`).

### Session (replicated from captured traffic of a working sender)
- `GET /info` first (working senders do this; we skip it — harmless).
- SETUP phase 1 plist: `deviceID`, `sessionUUID`, `timingPort`, `timingProtocol:
  NTP`, plus sender identity fields (`model`, `name`, `osName`, `macAddress`, …).
- Connect to the returned `eventPort` (reverse event channel).
- SETUP phase 2 plist (streams): **raw LPCM, not ALAC** — `type=96, ct=1,
  audioFormat=2048, sr=44100, spf=352, latencyMin=4366, latencyMax=88200`,
  32-byte `shk`, `isMedia=true`, `supportsDynamicStreamID=false`,
  `streamConnectionID` = the number in the RTSP URI (`rtsp://<sender-ip>/<num>`).
- `RECORD`, then volume `SET_PARAMETER` (`text/parameters`, `volume: 0.000000`).

### Timing
The receiver will **not** answer the stream SETUP until it has measured the
sender's clock. AirPlay NTP uses **RTP-style packets**, not HomeKit-style ones:
request `80 d2`, reply `80 d3`, client timestamp echoed at bytes 8..16, receive
ts at 16..24, transmit ts at 24..32. Implemented in `src/airplay/timing.rs`.

### Audio (type 96)
Packet = `[RTP header 12B][ChaCha20-Poly1305 ciphertext][tag 16B][nonce 8B]`,
key = `shk`, AAD = `timestamp || SSRC`, nonce = seq (u16 LE) at offset 4.
352-sample frames of 16-bit stereo PCM (1444 bytes on the wire). Timestamps
start near **1,418,702** (Unisson starts seq near 9,673 with rtptime near
1.4M — receivers appear to track playback position off these); both are
randomized/nonzero here. Sync packets (PT 84, `80 d4`) carrying
`seq || rtptime || NTP sec/frac || next rtptime` are sent right after RECORD
and every second.

**⚠️ Known issue (2026-11-04): audio packets are emitted at full rate and the
session fully negotiates, but the HomePod produces only static/noise, no
music.** Hypotheses, in order:
1. The sync packet field layout (`rtptime` positions) is subtly wrong.
2. The HomePod's access policy must be "Everyone" (Home app → speaker access).
3. Retransmit requests (PT 85) on the control port are unanswered — we're a
   valid sender but the receiver never talks back.
4. Timestamps need to track the receiver-measured clock offset, not a constant.

Reference materials left in `/tmp`: `test_receiver.log` (every request/response
from a local openairplay2 receiver, including Unisson's exact handshake),
`up.bin` / `down.bin` (reassembled RTSP from the first Unisson sniff).

## Architecture
```
src/main.rs          CLI (clap) + pipeline wiring
src/discover.rs      mDNS (_airplay._tcp) via mdns-sd
src/capture.rs       ScreenCaptureKit loopback -> float PCM
src/airplay/
├── tlv.rs           TLV8 codec
├── rtsp.rs          RTSP/HTTP client
├── pair.rs          HKPv4 transient pair-setup (M1–M4)
├── srp.rs           Apple-variant SRP-6a (SHA-512, G3072)
├── crypto.rs        encrypted control channel
├── session.rs       SETUP phases, RECORD, volume, event channel
├── timing.rs        NTP-like timing responder (RTP-style packets)
└── audio.rs         type-96 RTP audio + PT-84 sync packets
```

## What's planned next
1. Get clean audio playing (see known issue above).
2. `volume`, `disconnect`/teardown commands; `connect` by device name
   (map names from `discover`).
3. MCP server mode (like `unissonctl`) so AI agents can control it.
4. Publish to GitHub as GPL.
