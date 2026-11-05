# podstream

Stream your Mac's system audio to an AirPlay receiver (HomePod), from the CLI — no
GUI, no audio driver install, no licence, no telemetry, no updater.

![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)
![Language](https://img.shields.io/badge/language-Rust-orange.svg)

## Installation

```bash
git clone https://github.com/rohanpandula/podstream.git
cd podstream
cargo build --release
sudo cp target/release/podstream /usr/local/bin/
# or:
cargo run --release -- discover
```

**Requires:** macOS 14+ and the Rust toolchain (or just the binary).
First run will prompt for **Screen Recording** permission
(System Settings → Privacy & Security → Screen Recording) — that's how the
system audio is captured; no kernel extension, no virtual device, no admin.
**Fully offline running:** no licence, no telemetry, no update checks. Nothing
about you gets phoned home.

## Usage

```bash
# Find receivers on your network (mDNS, _airplay._tcp)
podstream discover --timeout 3 --json

# Paired session against a receiver (full negotiation)
podstream setup 10.0.0.66

# Stream your Mac's system audio to a receiver (60 seconds, then stop;
# run without --seconds to stream until Ctrl-C)
podstream connect 10.0.0.66 --seconds 60
```

Every other command is a diagnostic against a real receiver:

```bash
podstream pair 10.0.0.66        # HKPv4 transient pair-setup M1-M4
podstream probe 10.0.0.66       # pair + one encrypted round trip
podstream test-capture          # verify ScreenCaptureKit audio capture
```

## How it compares

| | podstream | airplay2-rs | shairport-sync | airlift / syncast | Unisson |
|---|---|---|---|---|---|
| What | **system audio sender** | file player | receiver | per-app sender (GUI) | system audio (GUI) |
| macOS capture | ScreenCaptureKit, no install | app-specific | — | ScreenCaptureKit/ process tap | CoreAudio virtual device + helper |
| Latency | low (custom sender) | low | — | **~2 s** (OS engine) | low |
| GUI | **none (CLI)** | TUI | service | menu bar | menu bar + panel |
| HomePod support | ✅ (full HomeKit pairing) | ✅ (file playback) | ❌ (receiver) | element experimental / OS-only | ✅, licence-gated |
| Licence/telemetry | **none** | none | none | none | licence + telemetry + updater |
| Language | Rust | Rust | C | Swift | Rust/Tauri |

The other *system-audio* options for macOS are GUI apps or single-app taps with
seconds of latency. The established OSS senders play **files**, not your system
audio. podstream is the only CLI-first, system-audio (not per-app), low-latency
sender for macOS: one dependency-light Rust binary, zero install, zero phone-home.

## Architecture

```
src/main.rs          CLI (clap) + pipeline wiring
src/discover.rs      mDNS discovery (_airplay._tcp) via mdns-sd
src/capture.rs       ScreenCaptureKit system-audio loopback -> float PCM
src/airplay/
├── tlv.rs           TLV8 codec
├── rtsp.rs          RTSP/HTTP client
├── pair.rs          HKPv4 transient pair-setup (M1–M4)
├── srp.rs           Apple-variant SRP-6a (SHA-512, 3072-bit group)
├── crypto.rs        ChaCha20-Poly1305 encrypted control channel
├── session.rs       SETUP phases, RECORD, volume, event channel
├── timing.rs        NTP-like timing responder (RTP-style packets)
└── audio.rs         type-96 RTP audio + PT-84 sync packets
```

## Protocol notes (reverse-engineered, verified on real hardware)

- **HKP:4 is required.** HomeKit transient pairing needs `X-Apple-HKP: 4`;
  HKP:3 returns a valid-looking M2 and only fails at M4.
- **Apple's SRP-6a quirk.** The session key and proof hash each value's
  *natural* bytes (so `H(g)` is SHA-512 of the single byte `0x05`); only
  `k = H(N | PAD(g))` and `u = H(PAD(A) | PAD(B))` use the RFC's PAD().
  A textbook SRP implementation completes the exchange and still gets
  `kTLVError_Authentication`. Hand-rolled in `src/airplay/srp.rs`.
- **Phase 2 streams raw LPCM, not ALAC** — `type=96, ct=1, audioFormat=2048`,
  352-sample frames, `streamConnectionID` = the number in the RTSP URI.
- **The receiver measures your clock first.** AirPlay NTP uses *RTP-style*
  packets (`80 d2` request / `80 d3` reply). Get it slightly wrong and the
  stream SETUP is refused with a bare 400, looking like a plist bug.

## Status

Discovery, capture, pairing, encrypted control channel, and session
negotiation all work end-to-end against real HomePods. Audio streaming works
with the HomePod accepting and decrypting packets at full rate; clean
(non-static) playback is the last open issue (see [Known issue](#known-issue)).

### Known issue

`podstream connect` ... its audio packets are rejected by some receivers in the
last mile (static / silence) with hypotheses ranked in the linked issue.
Reference captures and the open-source receiver used for testing live in the
project notes.

## Features

- **No GUI, ever** — discover/pair/setup/stream in one binary
- **No driver, no helper, no admin** — ScreenCaptureKit loopback; macOS 14+
- **Low latency** — custom sender (OwnTone-style type-96 realtime), ~0.1 s class target
- **Privacy** — no licence server, no telemetry, no update phone-home; runs fully offline
- **CLI-first** — `--json` everywhere, so agents and scripts can drive it (MCP-ready)

## Contributing

Issues and PRs welcome. Most valuable help: testing against real receivers
(HomePod/airplay-class devices) and anything that gets **clean audio playing**
(see Known issue above). Build with `cargo build`; the test loop is
`podstream setup <receiver>` then `podstream connect <receiver>`.

## License

GPL-3.0 — see [LICENSE](LICENSE).

*AirPlay, HomePod, and HomeKit are trademarks of Apple Inc. This project is an
independent clean-room networking client built for interoperability with your
own devices; it is not affiliated with, authorized by, or endorsed by Apple
Inc. Protocol constants and formats are documented in public AirPlay/HomeKit
references (RFC 5054/3526, OwnTone, libraop, shairport-sync, pyatv).*
