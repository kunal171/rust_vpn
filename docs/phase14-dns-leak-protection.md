# Phase 14: DNS routing and leak protection

Full-tunnel routes capture ordinary IPv4 destinations, but they do not control which upstream DNS
server the operating system selects. Applications commonly query the local `systemd-resolved` stub
at `127.0.0.53`; without per-link DNS policy, the resolver can still choose a server associated
with the physical interface.

Phase 14 adds an explicit DNS server to client full-tunnel mode and assigns all DNS names to the
VPN interface.

## Resolver policy

The client applies these commands after `rvpn0` and the full-tunnel routes are ready:

```text
resolvectl dns rvpn0 <IPv4 DNS server>
resolvectl domain rvpn0 ~.
resolvectl default-route rvpn0 yes
```

`~.` is a route-only root domain. It is the most specific possible catch-all DNS route, so
`systemd-resolved` selects the server attached to `rvpn0` for every name without adding a search
suffix.

The DNS server itself is an IPv4 destination covered by the two full-tunnel `/1` routes. Its query
therefore enters `rvpn0`, is encrypted, and reaches the server through the VPN. The VPN server must
provide forwarding and NAT when the resolver is outside the tunnel network.

## Lifecycle and rollback

Startup order:

```text
authenticate peer
create rvpn0
install peer bypass and split-default routes
install per-link DNS server, ~. domain, and default-route policy
```

Shutdown runs in the opposite order:

```text
resolvectl revert rvpn0
remove split-default routes and peer bypass
remove rvpn0
```

If any DNS command fails, `resolvectl revert rvpn0` rolls back partial resolver state. The DNS guard
also performs best-effort cleanup from `Drop`, while normal shutdown uses explicit cleanup so an
error can be reported.

## Command line

DNS configuration is client-only and requires full-tunnel routing:

```bash
sudo ./target/debug/vpn_tunnel \
  client <tun-address> <bind-address> <peer-address> \
  <allowed-ips> <private-key> <peer-public-key> \
  --full-tunnel --dns 1.1.1.1
```

The options may appear in either order. The program rejects DNS without `--full-tunnel`, IPv6 DNS
addresses, duplicate options, and both options in server mode.

## Leak verification

While the tunnel is running on a host using `systemd-resolved`, identify the physical interface:

```bash
ip route get <VPN-server-address>
```

Then run:

```bash
sudo ./scripts/check-dns-leaks.sh <physical-interface>
```

The script flushes resolver caches, requests a random name, and captures DNS traffic on both
interfaces. Passing means the query appeared on `rvpn0` but no UDP/TCP 53 or TCP 853 traffic
appeared on the physical interface. Encrypted VPN UDP traffic on the physical interface is
expected.

## Environment limits

- The runtime integration requires `systemd-resolved` and `resolvectl`.
- A typical `ip netns exec` namespace does not run its own resolver daemon, so the per-link DNS
  test should run on the host or in an environment with `systemd-resolved` inside the namespace.
- Phase 14 manages DNS for the IPv4 tunnel. General IPv6 traffic and a full firewall kill switch
  remain separate work.
- `resolvectl revert` is safe here because `rvpn0` is created and owned by this process.

## Verification

Automated tests cover command construction, application order, rollback, cleanup, option parsing,
and invalid policy combinations:

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

The code portion of Phase 14 is complete when these checks pass. The packet-capture command above
is the required privileged environment verification.
