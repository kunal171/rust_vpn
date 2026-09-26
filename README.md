# rust_vpn

An educational, WireGuard-inspired VPN built incrementally in Rust on Linux.

This project exists to learn networking, Linux packet handling, and Rust systems programming. It is not production-ready and must not be treated as a secure VPN.

## Current status

Phase 2: binary packet framing complete.

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

Not yet implemented:

- Packet-capture verification with tcpdump or Wireshark
- TUN interfaces
- Linux namespaces, routing, or NAT
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
```

- `protocol.rs` defines the frame format, encoding, decoding, and validation.
- `transport.rs` contains shared UDP configuration.
- `vpn_client.rs` sends data frames and validates acknowledgment frames.
- `vpn_server.rs` validates data frames and returns acknowledgment frames.
- `udp_loopback.rs` verifies a framed exchange over real UDP sockets.

## Requirements

- Linux
- Stable Rust toolchain
- Cargo

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

The client encodes a five-byte binary payload inside a 21-byte data frame and sends it to `127.0.0.1:51820`. The server validates and decodes the frame, then returns a 16-byte acknowledgment frame containing the same session ID and packet counter. The client validates that acknowledgment or exits after its receive timeout.

## Quality checks

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Next phase

Phase 3 uses tcpdump and Wireshark to prove the packet path and inspect each encapsulation layer.

Planned work:

- Capture the loopback exchange with tcpdump.
- Inspect Ethernet or loopback framing, IPv4, UDP, and the application frame.
- Locate the protocol version, message type, session ID, counter, payload length, and payload in captured bytes.
- Improve packet-counter and frame logging where captures show it is useful.

Success criterion: packet captures clearly demonstrate the complete client-to-server data frame and server-to-client acknowledgment frame.
