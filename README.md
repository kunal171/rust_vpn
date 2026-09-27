# rust_vpn

An educational, WireGuard-inspired VPN built incrementally in Rust on Linux.

This project exists to learn networking, Linux packet handling, and Rust systems programming. It is not production-ready and must not be treated as a secure VPN.

## Current status

Phase 3: packet-capture verification complete.

Currently implemented:

- Separate UDP client and server binaries over IPv4 loopback
- Arbitrary binary payload transfer
- Versioned binary frames with message type, session ID, packet counter, payload length, and payload
- Explicit big-endian encoding for multi-byte header fields
- Strict decoding with bounds and length validation
- Rejection of unknown versions, unknown message types, truncated frames, oversized frames, and length mismatches
- Framed data and acknowledgment messages
- Server-side protection against acknowledgment loops
- Client receive timeout and acknowledgment validation
- Unit tests for valid and malformed frames
- Real-socket framed UDP integration test
- Three stop-and-wait Data/ACK exchanges with counters `1` through `3`
- Structured frame metadata logs for capture correlation
- Reproducible tcpdump procedure and packet-level evidence

Not yet implemented:

- Linux network namespaces
- TUN interfaces
- Routing or NAT
- Encryption or authentication

## Project structure

```text
src/
├── lib.rs
├── protocol.rs
├── transport.rs
└── bin/
    ├── vpn_client.rs
    └── vpn_server.rs
tests/
└── udp_loopback.rs
docs/
└── phase3-packet-capture.md
```

- `protocol.rs` defines the frame format, encoding, decoding, and validation.
- `transport.rs` contains shared UDP configuration.
- `vpn_client.rs` sends data frames and validates acknowledgment frames.
- `vpn_server.rs` validates data frames and returns acknowledgment frames.
- `udp_loopback.rs` verifies framed exchanges over real UDP sockets.
- `phase3-packet-capture.md` documents the verified packet path and capture workflow.

## Requirements

- Linux
- Stable Rust toolchain
- Cargo
- tcpdump for packet-capture verification

## Build

```bash
cargo build
```

## Run

```bash
cargo run --bin vpn_server
# In a second terminal:
cargo run --bin vpn_client
```

The client sends three 21-byte Data frames with counters `1` through `3` to `127.0.0.1:51820`. The server validates each frame and returns a matching 16-byte acknowledgment. The client uses stop-and-wait ordering and validates each acknowledgment or exits after its receive timeout.

See [Phase 3 packet-capture verification](docs/phase3-packet-capture.md) for the tcpdump workflow and byte-level evidence.

## Quality checks

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Next phase

Phase 4 builds a repeatable Linux network-namespace lab with virtual Ethernet pairs.

Planned work:

- Create isolated client and server network namespaces.
- Connect them with a virtual Ethernet (`veth`) pair.
- Configure interfaces and IPv4 addresses with `ip link` and `ip addr`.
- Inspect routes and neighbor entries with `ip route` and `ip neigh`.
- Provide repeatable setup and cleanup commands.

Success criterion: multiple isolated virtual network stacks communicate on one Linux host through a documented, repeatable lab.
