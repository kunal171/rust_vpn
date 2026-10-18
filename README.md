# rust_vpn

An educational, WireGuard-inspired VPN built incrementally in Rust on Linux.

This project exists to learn networking, Linux packet handling, and Rust systems programming. It is not production-ready and must not be treated as a secure VPN.

## Status

Phase 7 is complete: routing and NAT through the tunnel, with allowed source addresses per peer.
Phase 8 is complete: the cryptographic foundations are tested and connected to the tunnel through
a deliberately insecure, reproducible lab key. Phase 9 is complete: an authenticated X25519 and
Ed25519 handshake runs over UDP, derives fresh directional keys, and returns a confirmed
`CryptoSession`. Phase 10 is in progress: `vpn_tunnel` now loads provisioned identities, performs
that handshake, and installs its fresh confirmed session before starting the data loops.

Working foundations:

- Configurable UDP client and server
- Versioned binary Data/Acknowledgment frames with strict validation
- Stop-and-wait exchanges with session IDs and packet counters
- Unit and real-socket integration tests
- Packet-capture verification with `tcpdump`
- Repeatable direct-veth and Linux-bridge namespace labs
- IPv4 header decoding, Internet checksum, and ICMP echo replies
- A TUN interface that answers `ping` from user space
- A two-way encrypted learning tunnel: TUN packets protected with ChaCha20-Poly1305 over UDP
- Routing to a LAN behind the server, with NAT masquerade on the server
- Allowed IPs: inner packets from unexpected source addresses are dropped
- Toy modular arithmetic and Diffie-Hellman exercises that demonstrate why unauthenticated key
  exchange is vulnerable to a man-in-the-middle attack
- HKDF-SHA256 derivation of separate client-to-server and server-to-client session keys
- ChaCha20-Poly1305 frame protection with the visible frame header authenticated as associated data
- Automatic send counters, a 64-packet replay window, secret zeroization, and stateful cryptographic
  sessions
- An authenticated UDP handshake with ephemeral X25519 keys, pinned Ed25519 peer identities, and an
  encrypted `HandshakeComplete` key-confirmation message
- Installation of the authenticated handshake session into the real TUN-to-UDP tunnel

The public Phase 8 lab key is no longer used by `vpn_tunnel`. Each launch performs an authenticated
ephemeral handshake and installs fresh keys and a fresh session ID. Phase 10 still needs namespace
verification, failure-path tests, and documented operational behavior before it is complete. The
hand-written Diffie-Hellman module is for learning only and is never used by the tunnel.

## Layout

```text
src/
├── lib.rs
├── authenticated_handshake.rs
├── cidr.rs
├── handshake.rs
├── handshake_transport.rs
├── identity.rs
├── ipv4.rs
├── key_exchange.rs
├── protocol.rs
├── transport.rs
├── udp_handshake.rs
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
    ├── vpn_keygen.rs
    ├── vpn_server.rs
    └── vpn_tunnel.rs
tests/
└── udp_loopback.rs
docs/
├── phase3-packet-capture.md
├── phase4-linux-namespaces.md
├── phase6-tun-over-udp.md
├── phase7-routing-nat.md
├── phase8-9-cryptography-guide.md
└── phase10-handshake-integration.md
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

Provision one long-term identity for each peer. The private files are created with mode `0600`, and
the key generator refuses to overwrite existing files:

```bash
mkdir -p keys
cargo run --bin vpn_keygen -- keys/client.key keys/client.pub
cargo run --bin vpn_keygen -- keys/server.key keys/server.pub
```

`vpn_tunnel` loads its private identity and the other peer's pinned public identity. It completes
the authenticated handshake before creating the TUN data path. Run one peer in each namespace of
the direct lab:

```bash
cargo build
sudo ./scripts/netns-direct.sh up
# Terminal 1:
sudo ip netns exec rvpn-client ./target/debug/vpn_tunnel client 10.210.0.1 10.200.1.1:51820 10.200.1.2:51820 10.210.0.2/32 keys/client.key keys/server.pub
# Terminal 2:
sudo ip netns exec rvpn-server ./target/debug/vpn_tunnel server 10.210.0.2 10.200.1.2:51820 10.200.1.1:51820 10.210.0.1/32 keys/server.key keys/client.pub
# Terminal 3:
sudo ip netns exec rvpn-client ping -c 3 10.210.0.2
```

The arguments are the cryptographic role, TUN address, local UDP bind address, peer UDP address,
comma-separated networks the peer may send from, local private-key file, and pinned peer public-key
file. The ping replies come from the kernel in
`rvpn-server`, carried back through the encrypted tunnel. The 1440-byte TUN MTU accounts for the
outer IPv4 and UDP headers, frame header, and authentication tag. Remove the lab with
`sudo ./scripts/netns-direct.sh down`.

## Routing and NAT demo

The routed lab adds a LAN host behind the server, which the client reaches through the tunnel:

```bash
cargo build
sudo ./scripts/netns-routed.sh up
# Terminal 1:
sudo ip netns exec rvpnr-client ./target/debug/vpn_tunnel client 10.210.0.1 10.200.3.1:51820 10.200.3.2:51820 10.210.0.2/32,10.200.4.0/24 keys/client.key keys/server.pub
# Terminal 2:
sudo ip netns exec rvpnr-server ./target/debug/vpn_tunnel server 10.210.0.2 10.200.3.2:51820 10.200.3.1:51820 10.210.0.1/32 keys/server.key keys/client.pub
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
- [Phases 8 and 9: cryptography, components, and data flow](docs/phase8-9-cryptography-guide.md)
- [Phase 10: authenticated-handshake integration](docs/phase10-handshake-integration.md)
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

1. Verify the authenticated tunnel and wrong-identity failure paths in Linux namespaces.
2. Add handshake retransmission, duplicate handling, reconnect behavior, bounded queues,
   and graceful shutdown.
3. Add full-tunnel routing, DNS configuration, leak testing, configurable MTU, and PMTUD tests.
4. After the classical VPN works end to end, add crypto-agile message formats and experiment with a
   hybrid post-quantum handshake: X25519 + ML-KEM for key establishment and Ed25519 + ML-DSA for
   peer authentication.

Post-quantum work is deliberately deferred. ChaCha20-Poly1305, counters, replay protection, TUN,
UDP, and routing can remain; the handshake messages, identity storage, transcript, key combiner,
packet sizing, and tests will need extension. Large ML-KEM keys and ML-DSA signatures also require
bounded handshake fragmentation rather than increasing ordinary tunnel-packet size without limits.
