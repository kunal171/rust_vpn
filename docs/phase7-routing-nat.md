# Phase 7: routing, NAT, and allowed IPs

Phase 6 connected two tunnel addresses. Phase 7 lets the client reach a whole network behind the far peer, which is what makes a VPN useful: an office LAN, or the internet for a privacy VPN. The far peer becomes a **gateway**.

Three Linux mechanisms make that work: a route on the client, forwarding on the gateway, and NAT on the gateway. Most of this phase is kernel configuration, as it is for real VPNs. The Rust part is **allowed IPs**: each peer may only send inner packets from addresses it has been given, so it cannot inject spoofed traffic into the other side's network.

The tunnel is still plaintext and unauthenticated.

## Topology

`scripts/netns-routed.sh` builds three namespaces. The client and the LAN host share no link, so the only path between them runs through the gateway:

```text
 rvpnr-client              rvpnr-server (gateway)          rvpnr-lan
 10.200.3.1/24 <== veth ==> 10.200.3.2/24
   rvpnr-c                  rvpnr-s
                            10.200.4.1/24 <== veth ==>    10.200.4.2/24
                            rvpnr-sl                       rvpnr-l
 rvpn0 10.210.0.1  ═ tunnel ═  rvpn0 10.210.0.2
```

| Network | Subnet | Purpose |
| --- | --- | --- |
| Outer link | `10.200.3.0/24` | carries the tunnel's UDP |
| Remote LAN | `10.200.4.0/24` | the network behind the gateway |
| Tunnel | `10.210.0.0/24` | inner addresses on `rvpn0` |

The names and subnets differ from the Phase 4 labs, so all three labs can coexist.

The script supports `up`, `route`, `nat`, `status`, and `down`. `route` and `nat` must run while `vpn_tunnel` is running, because the client's route attaches to `rvpn0`, which exists only while the program runs. `down` deletes the namespaces, which also removes their routes, forwarding setting, and NAT rules.

## Allowed IPs

`vpn_tunnel` now takes a fourth argument: the networks the peer may send from, comma-separated.

```text
vpn_tunnel <tun-address> <bind-address> <peer-address> <allowed-ips>
```

Before writing a received packet into TUN, `udp_to_tun` decodes its IPv4 header and drops it unless an allowed network contains its source address:

```text
recv → Frame::decode → Data? → decode_ipv4_header → source allowed? → write to TUN
```

Without this check, the client could send an inner packet with any source, for example `10.200.4.7`. The gateway would forward it into the LAN, where it would look like a packet from a LAN neighbour. The check runs on the receiving side because each peer protects its own network.

| Peer | Allowed IPs | Why |
| --- | --- | --- |
| `rvpnr-server` | `10.210.0.1/32` | the client only sends as itself |
| `rvpnr-client` | `10.210.0.2/32,10.200.4.0/24` | the gateway, and the LAN replies it forwards |

The client must allow the whole LAN because NAT rewrites only the destination of a reply. A reply from the LAN host still has source `10.200.4.2`.

Networks are written in CIDR notation and parsed by `Ipv4Cidr` in `src/cidr.rs`. Membership is one mask and one comparison: `address & mask == network`, where the mask has the first *prefix-length* bits set. The parser rejects a missing prefix, an invalid address, a prefix above 32, and a network address with host bits set, such as `10.200.4.7/24`. `/0` is handled without overflowing the shift.

Because the check decodes IPv4 headers, inner IPv6 packets are now dropped. The kernel's background IPv6 traffic appears in the log as `unsupported IP version 6`.

## Running the lab

```bash
cargo build
sudo ./scripts/netns-routed.sh up
```

Start one peer in each of the first two namespaces:

```bash
sudo ip netns exec rvpnr-client ./target/debug/vpn_tunnel \
    10.210.0.1 10.200.3.1:51820 10.200.3.2:51820 10.210.0.2/32,10.200.4.0/24
```

```bash
sudo ip netns exec rvpnr-server ./target/debug/vpn_tunnel \
    10.210.0.2 10.200.3.2:51820 10.200.3.1:51820 10.210.0.1/32
```

Then configure routing and NAT, and ping the LAN host:

```bash
sudo ./scripts/netns-routed.sh route
sudo ./scripts/netns-routed.sh nat
sudo ip netns exec rvpnr-client ping -c 3 10.200.4.2
```

Watch what the LAN host receives with:

```bash
sudo ip netns exec rvpnr-lan tcpdump -i rvpnr-l -n icmp
```

Remove the lab with `sudo ./scripts/netns-routed.sh down`.

## Verification

All checks below were run in the routed lab. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` (43 unit tests, 1 integration test) pass.

As in Phase 6, packets on the LAN link were captured with a small `AF_PACKET` raw-socket script, because `tcpdump` could not run inside the unprivileged namespaces used for this test run. The `tcpdump` command above observes the same packets in a normal `sudo` lab.

### Baseline

The gateway reaches the LAN and the client reaches the gateway, but the client cannot reach the LAN:

```text
$ ip netns exec rvpnr-server ping -c 1 10.200.4.2
1 packets transmitted, 1 received, 0% packet loss
$ ip netns exec rvpnr-client ping -c 1 10.200.3.2
1 packets transmitted, 1 received, 0% packet loss
$ ip netns exec rvpnr-client ping -c 1 10.200.4.2
ping: connect: Network is unreachable
```

### Routing, one fix at a time

With both peers running, each fix moved the failure one hop further:

| Applied | Ping result | What the LAN host saw |
| --- | --- | --- |
| nothing | `Network is unreachable` | nothing |
| client route: `ip route add 10.200.4.0/24 dev rvpn0` | 100% loss | nothing: the gateway dropped the packet |
| gateway forwarding: `sysctl -w net.ipv4.ip_forward=1` | 100% loss | `IP 10.210.0.1 > 10.200.4.2: ICMP echo request`, no reply |
| LAN return route: `ip route add 10.210.0.0/24 via 10.200.4.1` | 0% loss | the request and `IP 10.200.4.2 > 10.210.0.1: ICMP echo reply` |

Linux forwards nothing by default, so the gateway drops packets that are not addressed to itself. After forwarding was enabled, the request reached the LAN host, but it had no route to `10.210.0.0/24` and could not send the reply.

The `route` subcommand applies all three fixes, and refuses to run before the tunnel exists:

```text
$ ./scripts/netns-routed.sh route          # before starting vpn_tunnel
rvpn0 does not exist in rvpnr-client; start vpn_tunnel there first.
$ ./scripts/netns-routed.sh route          # with both peers running
Routing configured. Test: sudo ip netns exec rvpnr-client ping -c 3 10.200.4.2
$ ip netns exec rvpnr-client ping -c 3 10.200.4.2
3 packets transmitted, 3 received, 0% packet loss
```

### NAT

The `nat` subcommand removes the LAN host's return route and adds a masquerade rule on the gateway:

```text
table ip rvpn_nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 10.210.0.0/24 oifname "rvpnr-sl" masquerade
	}
}
```

The rule runs at `postrouting`, after the routing decision, because masquerade needs to know the outgoing interface. Only the request needs a rule; the kernel's connection tracking rewrites each reply back automatically.

After `nat`, the LAN host has no route to the tunnel network at all:

```text
$ ip -n rvpnr-lan route
10.200.4.0/24 dev rvpnr-l proto kernel scope link src 10.200.4.2
```

Pings still succeed, and the LAN host sees only the gateway's address:

```text
IP 10.200.4.1 > 10.200.4.2: ICMP echo request
IP 10.200.4.2 > 10.200.4.1: ICMP echo reply
2 packets transmitted, 2 received, 0% packet loss
```

Before NAT, the same capture showed `10.210.0.1` as the source. This is the mechanism a privacy VPN uses to hide your IP address: destinations only ever see the gateway.

### Allowed IPs

Each peer printed its allowed networks at startup:

```text
rvpnr-client: Accepting inner packets from 10.210.0.2/32, 10.200.4.0/24
rvpnr-server: Accepting inner packets from 10.210.0.1/32
```

To act as a malicious client posing as another LAN machine, the client's `rvpn0` was given an extra address and pinged from it:

```bash
sudo ip netns exec rvpnr-client ip addr add 10.200.4.7/32 dev rvpn0
sudo ip netns exec rvpnr-client ping -c 2 -I 10.200.4.7 10.200.4.2
```

```text
2 packets transmitted, 0 received, 100% packet loss
```

The gateway dropped both packets, and the LAN capture saw nothing:

```text
Dropping packet 8: source 10.200.4.7 is not an allowed IP
Dropping packet 9: source 10.200.4.7 is not an allowed IP
```

Legitimate pings from `10.210.0.1` kept working throughout. An allowed-IPs argument with host bits set stops the program at startup:

```text
$ vpn_tunnel 10.210.0.9 127.0.0.1:1 127.0.0.1:2 10.200.4.7/24
Error: HostBitsSet { address: 10.200.4.7, prefix_length: 24 }
```

The Phase 6 direct lab also still works with the new argument (`10.210.0.2/32` on the client, `10.210.0.1/32` on the server): 3 of 3 pings received.

## Limitations

- Routing covers one subnet. Routing everything (`default dev rvpn0`) would also send the tunnel's own UDP packets into the tunnel, an endless loop, unless a more specific route keeps the peer's outer address outside it.
- Allowed IPs check only the source of received packets. With a single peer there is no need to choose a peer for outgoing packets, which WireGuard also uses allowed IPs for.
- Inner IPv6 is dropped.
- Allowed IPs limit what a peer may claim, but anyone who can forge UDP from the peer's outer address can still send allowed sources. Authentication fixes that.
- Startup errors print in Rust's debug format, for example `Error: HostBitsSet { ... }`.
- Running `route` or `nat` twice fails or duplicates the rule; use `down` and `up` to reset.
