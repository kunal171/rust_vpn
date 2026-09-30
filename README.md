# rust_vpn

An educational, WireGuard-inspired VPN built incrementally in Rust on Linux.

This project exists to learn networking, Linux packet handling, and Rust systems programming. It is not production-ready and must not be treated as a secure VPN.

## Current status

Phase 4: Linux network-namespace lab complete.

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
- Configurable client bind and server endpoint addresses
- Direct namespace topology using one virtual Ethernet (`veth`) pair
- Bridged namespace topology using two veth pairs and a Linux bridge
- Repeatable namespace setup, inspection, and cleanup scripts
- Verified ICMP and framed UDP communication across both topologies

Not yet implemented:

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
├── phase3-packet-capture.md
└── phase4-linux-namespaces.md
scripts/
├── netns-direct.sh
└── netns-bridge.sh
```

- `protocol.rs` defines the frame format, encoding, decoding, and validation.
- `transport.rs` contains shared UDP configuration.
- `vpn_client.rs` sends data frames and validates acknowledgment frames.
- `vpn_server.rs` validates data frames and returns acknowledgment frames.
- `udp_loopback.rs` verifies framed exchanges over real UDP sockets.
- `phase3-packet-capture.md` documents the verified packet path and capture workflow.
- `phase4-linux-namespaces.md` documents both isolated network labs.
- `netns-direct.sh` connects two namespaces with one veth pair.
- `netns-bridge.sh` connects two namespaces through a Linux bridge.

## Requirements

- Linux
- Stable Rust toolchain
- Cargo
- iproute2 (`ip` and `bridge`)
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

See [Phase 4 Linux namespaces](docs/phase4-linux-namespaces.md) to run the client and server in isolated network stacks.

## Quality checks

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Next phase

Phase 5 introduces Linux TUN interfaces so the programs can read and write IP packets rather than only application-created payloads.

Planned work:

- Learn the difference between TUN and TAP devices.
- Create and configure a TUN interface on Linux.
- Read raw IP packets from the TUN file descriptor.
- Inspect packet headers before connecting TUN traffic to the UDP transport.

Success criterion: the program can receive an IP packet injected through a TUN interface and explain its header fields.
