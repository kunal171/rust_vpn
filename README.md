# rust_vpn

An educational, WireGuard-inspired VPN built incrementally in Rust on Linux.

This project exists to learn networking, Linux packet handling, and Rust systems programming. It is not production-ready and must not be treated as a secure VPN.

## Current status

Phase 0: project skeleton.

Currently implemented:

- Separate client and server binaries
- Shared library crate
- Basic unit-test foundation
- Formatting and Clippy quality checks

Not yet implemented:

- UDP communication
- Packet framing
- TUN interfaces
- Routing or NAT
- Encryption or authentication

## Project structure

```text
src/
├── lib.rs
└── bin/
    ├── vpn_client.rs
    └── vpn_server.rs
```

- `lib.rs` contains code shared by both applications.
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
cargo run --bin vpn_client
cargo run --bin vpn_server
```

These programs currently print startup messages and exit. They do not send network traffic yet.

## Quality checks

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Next phase

Phase 1 introduces synchronous UDP communication using `std::net::UdpSocket`.

Success criterion:

- Server binds to a localhost IPv4 address and port.
- Client sends arbitrary binary data.
- Server receives the exact bytes and identifies the sender.
- Socket and decoding errors are reported explicitly.
- Automated tests verify the basic exchange.
