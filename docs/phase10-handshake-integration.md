# Phase 10: authenticated-handshake integration

Phase 9 proved that two UDP peers can authenticate each other, derive fresh directional keys, and
confirm possession of those keys. Phase 10 makes that result drive the real TUN-to-UDP data path.

## Why this phase exists

The project currently has two working pieces that are not yet connected:

```text
authenticated UDP handshake ──▶ fresh CryptoSession

public lab key ──▶ vpn_tunnel ──▶ encrypted TUN traffic
```

Phase 10 replaces the second input:

```text
pinned peer identity
        │
        ▼
authenticated UDP handshake
        │
        ▼
fresh confirmed CryptoSession
        │
        ▼
vpn_tunnel data loops
        │
        ├── TUN packet ──▶ protect ──▶ UDP
        └── UDP frame ──▶ unprotect ──▶ TUN
```

The tunnel must not process ordinary `Data` frames until authentication and key confirmation have
succeeded. If the handshake fails, no traffic session is installed.

## Planned implementation slices

### 1. Identity input

- Define how each peer receives its local private identity and the expected remote public identity.
- Parse and validate keys before opening the tunnel.
- Avoid logging private keys or derived session keys.

The first lab version may use explicit files or arguments. Durable key generation, rotation, and
permission hardening can follow once the data flow is proven.

### 2. Session installation

- Run `perform_client_handshake` or `perform_server_handshake` according to the selected role.
- Receive the confirmed `CryptoSession`.
- Split it into its single-owner sender and receiver halves.
- Remove the public lab-secret derivation from the executable path.

Rust ownership helps enforce an important invariant: only one sender owns the monotonically
increasing counter, while only one receiver owns and mutates the replay window.

### 3. Data-loop integration

- Give the sender half to the TUN-to-UDP loop.
- Give the receiver half to the UDP-to-TUN loop.
- Accept only protected `Data` frames after the handshake.
- Preserve allowed-source-address validation before writing decrypted packets to TUN.

### 4. Failure and lifecycle behavior

- Add a bounded handshake timeout.
- Report authentication failures without exposing secrets.
- Stop both data loops if the session becomes unusable.
- Add retransmission and reconnect behavior in a following reliability slice.

### 5. End-to-end verification

- Successful authenticated namespace ping.
- Wrong pinned server identity fails before data transport.
- Wrong pinned client identity fails before data transport.
- Modified and replayed protected frames are rejected.
- Restarting peers creates fresh keys and restarts counters safely.
- Packet capture shows ciphertext rather than the inner ICMP packet.

## Done criteria

Phase 10 is complete when `vpn_tunnel` no longer uses the public lab key, two namespace peers can
authenticate and exchange tunneled traffic, incorrect identities cannot establish a session, all
quality checks pass, and the namespace commands are documented and reproducible.

This remains an educational VPN. Reliability, full-tunnel DNS/routing, operational key management,
and post-quantum experiments are later milestones.
