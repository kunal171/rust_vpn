# rust_vpn

An educational, WireGuard-inspired VPN built incrementally in Rust on Linux.

This project exists to learn networking, Linux packet handling, and Rust systems programming. It is not production-ready and must not be treated as a secure VPN.

## Current status

Phase 1: UDP client/server complete.

Currently implemented:

- Separate client and server binaries
- Synchronous UDP communication over IPv4 loopback
- Arbitrary binary payload transfer
- Continuous server receive loop
- Server acknowledgments and client receive timeout
- Shared UDP transport configuration
- Automated request-acknowledgment integration test

Not yet implemented:

- Binary packet framing
- TUN interfaces
- Routing or NAT
- Encryption or authentication

## Project structure

```text
src/
├── lib.rs
├── transport.rs
└── bin/
    ├── vpn_client.rs
    └── vpn_server.rs
tests/
└── udp_loopback.rs
```

- `lib.rs` contains code shared by both applications.
- `transport.rs` contains shared UDP configuration.
- `vpn_client.rs` is the client entry point.
- `vpn_server.rs` is the server entry point.

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

The client sends a binary UDP payload to `127.0.0.1:51820`. The server receives it, logs the sender and bytes, returns an acknowledgment, and continues waiting for more datagrams. The client exits after validating the acknowledgment or timing out.

## Quality checks

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Next phase

Phase 2 introduces strict binary packet framing above the UDP transport.

Success criterion:

- Frames contain a version, message type, session identifier, counter, payload length, and payload.
- Valid frames encode and decode without losing information.
- Unknown versions and message types are rejected.
- Truncated, oversized, and length-mismatched frames are rejected safely.
- No encryption is introduced during this phase.
