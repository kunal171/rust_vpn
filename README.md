# rust_vpn

An educational, WireGuard-inspired VPN built incrementally in Rust on Linux.

This project exists to learn networking, Linux packet handling, and Rust systems programming. It is not production-ready and must not be treated as a secure VPN.

## Status

Phase 7 is complete: routing and NAT through the tunnel, with allowed source addresses per peer.
Phase 8 is in progress: the cryptographic building blocks are implemented and tested, but they
are not yet connected to the running tunnel.

Working foundations:

- Configurable UDP client and server
- Versioned binary Data/Acknowledgment frames with strict validation
- Stop-and-wait exchanges with session IDs and packet counters
- Unit and real-socket integration tests
- Packet-capture verification with `tcpdump`
- Repeatable direct-veth and Linux-bridge namespace labs
- IPv4 header decoding, Internet checksum, and ICMP echo replies
- A TUN interface that answers `ping` from user space
- A two-way plaintext tunnel: TUN packets encapsulated in Data frames over UDP
- Routing to a LAN behind the server, with NAT masquerade on the server
- Allowed IPs: inner packets from unexpected source addresses are dropped
- Toy modular arithmetic and Diffie-Hellman exercises that demonstrate why unauthenticated key
  exchange is vulnerable to a man-in-the-middle attack
- HKDF-SHA256 derivation of separate client-to-server and server-to-client session keys
- ChaCha20-Poly1305 frame protection with the visible frame header authenticated as associated data
- Automatic send counters, a 64-packet replay window, secret zeroization, and stateful cryptographic
  sessions

The `vpn_tunnel` binary still transports plaintext frames. A real authenticated key exchange,
encrypted-tunnel integration, operational hardening, and full-tunnel mode are not implemented yet.
The hand-written Diffie-Hellman module is for learning only and must never protect real traffic.

## Layout

```text
src/
├── lib.rs
├── cidr.rs
├── ipv4.rs
├── protocol.rs
├── transport.rs
├── toy_crypto/
│   ├── diffie_hellman.rs
│   ├── key_derivation.rs
│   ├── modular.rs
│   ├── packet_crypto.rs
│   ├── replay_window.rs
│   ├── send_counter.rs
│   └── session.rs
└── bin/
    ├── tun_reader.rs
    ├── vpn_client.rs
    ├── vpn_server.rs
    └── vpn_tunnel.rs
tests/
└── udp_loopback.rs
docs/
├── phase3-packet-capture.md
├── phase4-linux-namespaces.md
├── phase6-tun-over-udp.md
└── phase7-routing-nat.md
scripts/
├── netns-direct.sh
├── netns-bridge.sh
└── netns-routed.sh
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

## TUN ping demo

Creating a TUN interface needs root, so build as your user and run the binary with `sudo`:

```bash
cargo build
sudo ./target/debug/tun_reader
# In a second terminal:
ping -c 3 10.210.0.2
```

`tun_reader` creates `rvpn0` with address `10.210.0.1/24`, prints the IPv4 header of each packet it reads, and answers ICMP echo requests. Ping `10.210.0.2` rather than `10.210.0.1`: the host owns `.1`, so the kernel answers that address itself and the packet never reaches the program. Stop it with Ctrl+C; the interface is removed when the process exits.

## Tunnel demo

`vpn_tunnel` connects a TUN interface to one UDP peer. It is currently a plaintext learning tunnel;
do not use it to carry sensitive traffic. Run one peer in each namespace of the direct lab:

```bash
cargo build
sudo ./scripts/netns-direct.sh up
# Terminal 1:
sudo ip netns exec rvpn-client ./target/debug/vpn_tunnel 10.210.0.1 10.200.1.1:51820 10.200.1.2:51820 10.210.0.2/32
# Terminal 2:
sudo ip netns exec rvpn-server ./target/debug/vpn_tunnel 10.210.0.2 10.200.1.2:51820 10.200.1.1:51820 10.210.0.1/32
# Terminal 3:
sudo ip netns exec rvpn-client ping -c 3 10.210.0.2
```

The arguments are the TUN address, the local UDP bind address, the peer's UDP address, and the comma-separated networks the peer may send from. The ping replies come from the kernel in `rvpn-server`, carried back through the tunnel. Remove the lab with `sudo ./scripts/netns-direct.sh down`. See [Phase 6](docs/phase6-tun-over-udp.md) for the design, the MTU calculation, and the verification captures.

## Routing and NAT demo

The routed lab adds a LAN host behind the server, which the client reaches through the tunnel:

```bash
cargo build
sudo ./scripts/netns-routed.sh up
# Terminal 1:
sudo ip netns exec rvpnr-client ./target/debug/vpn_tunnel 10.210.0.1 10.200.3.1:51820 10.200.3.2:51820 10.210.0.2/32,10.200.4.0/24
# Terminal 2:
sudo ip netns exec rvpnr-server ./target/debug/vpn_tunnel 10.210.0.2 10.200.3.2:51820 10.200.3.1:51820 10.210.0.1/32
# Terminal 3:
sudo ./scripts/netns-routed.sh route
sudo ./scripts/netns-routed.sh nat
sudo ip netns exec rvpnr-client ping -c 3 10.200.4.2
```

`route` adds the client's route into the tunnel and enables forwarding on the server; `nat` makes the server masquerade tunnel traffic, so the LAN host sees only the server's address. Remove the lab with `sudo ./scripts/netns-routed.sh down`. See [Phase 7](docs/phase7-routing-nat.md) for the step-by-step routing, NAT, and allowed-IPs checks.

## Labs and documentation

- [Phase 3: packet-capture verification](docs/phase3-packet-capture.md)
- [Phase 4: Linux namespaces](docs/phase4-linux-namespaces.md)
- [Phase 6: TUN over UDP](docs/phase6-tun-over-udp.md)
- [Phase 7: routing, NAT, and allowed IPs](docs/phase7-routing-nat.md)
- `scripts/netns-direct.sh`: direct veth topology
- `scripts/netns-bridge.sh`: bridged topology
- `scripts/netns-routed.sh`: client, gateway, and LAN host for routing and NAT

## Quality checks

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Roadmap

- Integrate the tested authenticated-encryption and replay-protection layer into `vpn_tunnel`
- Add a real authenticated X25519-based key exchange; never use the toy Diffie-Hellman module
- Add keepalives, timeouts, reconnect behavior, bounded queues, and graceful shutdown
- Recalculate the tunnel MTU for encryption overhead and test fragmentation and PMTUD
- Add a full-tunnel mode that routes all traffic without a routing loop
- Add DNS configuration and leak testing for full-tunnel operation
