# rust_vpn

An authenticated IPv4 VPN for Linux, written in Rust. It transports packets from a TUN interface
over UDP and protects them with authenticated encryption.

> [!WARNING]
> This implementation has not received an independent security audit. Do not use it to protect
> production or sensitive traffic.

## Features

- Linux TUN packet transport over connected UDP sockets
- Authenticated X25519 key exchange with pinned Ed25519 identities
- ChaCha20-Poly1305 encryption with directional session keys
- Monotonic counters and a 64-packet replay window
- Allowed-source network validation for inner IPv4 packets
- Authenticated keepalives, peer timeout detection, and fresh-session reconnection
- Bounded handshake retries and outbound packet queues
- Optional IPv4 full-tunnel routing with automatic peer bypass and cleanup
- Reproducible direct, bridged, and routed network-namespace environments

## Packet flow

```text
application
    │ IPv4 packet
    ▼
  rvpn0 ──▶ encrypt + authenticate ──▶ UDP ──▶ peer
    ▲                                           │
    └──────── validate + decrypt ◀──────────────┘
```

The UDP peer is authenticated before the TUN data path starts. Each connection receives fresh
session keys, counters, replay state, and a session ID.

## Requirements

- Linux
- Stable Rust and Cargo
- `iproute2`
- Root or `CAP_NET_ADMIN` for TUN devices, routes, and network namespaces
- `nftables` for the routed NAT environment
- `tcpdump` for optional packet inspection

## Build and test

```bash
cargo build
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Run the tunnel

Generate one long-term identity for each peer. Existing key files are never overwritten.

```bash
mkdir -p keys
cargo run --bin vpn_keygen -- keys/client.key keys/client.pub
cargo run --bin vpn_keygen -- keys/server.key keys/server.pub
cargo build
sudo ./scripts/netns-direct.sh up
```

Start the server:

```bash
sudo ip netns exec rvpn-server ./target/debug/vpn_tunnel \
  server 10.210.0.2 10.200.1.2:51820 10.200.1.1:51820 \
  10.210.0.1/32 keys/server.key keys/client.pub
```

Start the client in another terminal:

```bash
sudo ip netns exec rvpn-client ./target/debug/vpn_tunnel \
  client 10.210.0.1 10.200.1.1:51820 10.200.1.2:51820 \
  10.210.0.2/32 keys/client.key keys/server.pub
```

Verify the encrypted path:

```bash
sudo ip netns exec rvpn-client ping -c 3 10.210.0.2
sudo ./scripts/netns-direct.sh down
```

The positional arguments are:

```text
role  tun-address  bind-address  peer-address  allowed-ips  private-key  peer-public-key
```

## Full-tunnel mode

Append `--full-tunnel` to the client command to direct all IPv4 destinations into `rvpn0`:

```bash
sudo ip netns exec rvpn-client ./target/debug/vpn_tunnel \
  client 10.210.0.1 10.200.1.1:51820 10.200.1.2:51820 \
  10.210.0.2/32 keys/client.key keys/server.pub --full-tunnel
```

The client preserves the physical route to the UDP peer, then installs `0.0.0.0/1` and
`128.0.0.0/1` through the TUN interface. Partial installation is rolled back, and installed routes
are removed during shutdown. Internet access additionally requires forwarding and NAT on the
server. DNS routing is not configured yet.

## Documentation

- [Packet capture](docs/phase3-packet-capture.md)
- [Linux network namespaces](docs/phase4-linux-namespaces.md)
- [TUN over UDP](docs/phase6-tun-over-udp.md)
- [Routing, NAT, and allowed IPs](docs/phase7-routing-nat.md)
- [Cryptography and data flow](docs/phase8-9-cryptography-guide.md)
- [Authenticated handshake integration](docs/phase10-handshake-integration.md)
- [Reliable UDP handshake](docs/phase11-handshake-reliability.md)
- [Lifecycle and reconnection](docs/phase12-reconnect-lifecycle.md)
- [Full-tunnel routing](docs/phase13-full-tunnel-routing.md)

## Current status

The tunnel supports authenticated encrypted traffic, reconnection, split routing, routed LAN
access, NAT environments, and optional full-tunnel IPv4 route installation. Remaining work includes
DNS configuration, leak testing, configurable MTU handling, PMTUD tests, packaging, and security
review.
