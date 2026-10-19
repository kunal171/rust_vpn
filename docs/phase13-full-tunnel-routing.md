# Phase 13: full-tunnel IPv4 routing

Full-tunnel mode sends every IPv4 destination through the VPN while keeping the encrypted UDP
transport on the original physical path.

## Route design

A single replacement default route can hide the route used to reach the VPN server. The client
therefore installs three routes in this order:

```text
VPN peer/32   via the original gateway and interface
0.0.0.0/1     via rvpn0
128.0.0.0/1   via rvpn0
```

The two `/1` networks cover the entire IPv4 address space and are more specific than an existing
`0.0.0.0/0` default route. The `/32` peer bypass is more specific than both `/1` routes, preventing
the encrypted transport from being routed into itself.

```text
ordinary IPv4 traffic ─────────────▶ rvpn0 ─▶ encrypted UDP
VPN server UDP address ─▶ /32 bypass ───────▶ physical interface
```

## Components

- `FullTunnelPlan` creates the peer bypass and both split-default networks without changing the
  operating system.
- `discover_physical_route` parses `ip -4 route get` before full-tunnel routes exist.
- `InstalledFullTunnelRoutes` applies the plan and owns the resulting Linux route state.
- `vpn_tunnel --full-tunnel` enables the feature for the client role.

The server role rejects `--full-tunnel`; only the client needs to capture locally generated
traffic.

## Failure and cleanup behavior

The peer bypass is installed first. If either split-default route fails, every successfully added
route is removed in reverse order. Explicit shutdown reports cleanup errors, while the route
owner's `Drop` implementation provides best-effort cleanup for other return paths.

Commands are executed with separate process arguments rather than through a shell. Route addition
uses `ip route add`, so an existing conflicting route causes a visible failure instead of being
silently replaced.

## Run

Start the server normally, then append the flag to the client command:

```bash
sudo ip netns exec rvpn-client ./target/debug/vpn_tunnel \
  client 10.210.0.1 10.200.1.1:51820 10.200.1.2:51820 \
  10.210.0.2/32 keys/client.key keys/server.pub --full-tunnel
```

Inspect the installed routes from another terminal:

```bash
sudo ip -n rvpn-client route
sudo ip -n rvpn-client route get 10.200.1.2
sudo ip -n rvpn-client route get 8.8.8.8
```

The peer lookup must select the physical veth interface. The ordinary destination must select
`rvpn0`. Stop the client with Ctrl+C and confirm that the `/32` and both `/1` routes disappear.

## Verification

Automated tests cover route planning, Linux route-output parsing, reverse-order rollback, cleanup
order, and client-only option parsing. Run:

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Completion status

Phase 13 is complete. Full-tunnel routing is opt-in, preserves the UDP transport path, rolls back
partial changes, and removes owned routes during shutdown. Server forwarding, NAT, and DNS policy
remain separate configuration concerns.
