# rust_vpn

An educational, WireGuard-inspired VPN built incrementally in Rust on Linux.

This project exists to learn networking, Linux packet handling, and Rust systems programming. It is not production-ready and must not be treated as a secure VPN.

## Status

Phase 5 is in progress: reading and writing IP packets through a Linux TUN interface.

Working foundations:

- Configurable UDP client and server
- Versioned binary Data/Acknowledgment frames with strict validation
- Stop-and-wait exchanges with session IDs and packet counters
- Unit and real-socket integration tests
- Packet-capture verification with `tcpdump`
- Repeatable direct-veth and Linux-bridge namespace labs

Not implemented yet: TUN packet handling, routing/NAT, encryption, or authentication.

## Layout

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

## Quick start

Requirements: Linux, stable Rust, Cargo, iproute2, and optionally `tcpdump`.

```bash
cargo build
cargo run --bin vpn_server
# In a second terminal:
cargo run --bin vpn_client
```

The default loopback exchange sends three Data frames and validates their matching acknowledgments. Both binaries also accept configurable addresses for namespace testing.

## Labs and documentation

- [Phase 3: packet-capture verification](docs/phase3-packet-capture.md)
- [Phase 4: Linux namespaces](docs/phase4-linux-namespaces.md)
- `scripts/netns-direct.sh`: direct veth topology
- `scripts/netns-bridge.sh`: bridged topology

## Quality checks

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Roadmap

- Read and inspect raw IP packets from TUN
- Connect TUN packets to the UDP transport
- Add routing and NAT
- Add authenticated encryption and replay protection
