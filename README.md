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