# rust_vpn

An authenticated IPv4 VPN for Linux, written in Rust. It transports TUN packets over UDP using
authenticated encryption.

> [!WARNING]
> This project has not received an independent security audit. Do not use it for production or
> sensitive traffic.

## Features

- X25519 key exchange with pinned Ed25519 identities
- ChaCha20-Poly1305 encryption and replay protection
- Authenticated keepalives and automatic reconnection
- Allowed-source validation for inner IPv4 packets
- Optional full-tunnel routing with safe rollback and cleanup
- Direct, bridged, and routed Linux namespace environments

## Requirements

Linux, stable Rust, `iproute2`, and root or `CAP_NET_ADMIN`. DNS mode also requires
`systemd-resolved` and `resolvectl`.

## Build and test

```bash
cargo build
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Usage

```bash
mkdir -p keys
cargo run --bin vpn_keygen -- keys/client.key keys/client.pub
cargo run --bin vpn_keygen -- keys/server.key keys/server.pub
```

```text
vpn_tunnel <client|server> <tun-address> <bind-address> <peer-address> \
  <allowed-ips> <private-key> <peer-public-key> [--full-tunnel] [--dns <IPv4-address>]
```

`--full-tunnel` is client-only. `--dns` requires it and routes all DNS names through `rvpn0`.
Server forwarding and NAT remain separate requirements.

## Documentation

See [`docs/`](docs/) for protocol, cryptography, routing, lifecycle, and verification details.
