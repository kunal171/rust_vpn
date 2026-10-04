# Phase 6: carrying TUN packets over UDP

Phase 6 joins the two halves built so far. Phases 1 to 4 moved framed bytes between peers over UDP; Phase 5 read and wrote IP packets on a TUN interface. The `vpn_tunnel` binary connects them: a packet read from TUN on one peer travels inside a `Data` frame over UDP and is written into TUN on the other peer, where the real kernel handles it.

The tunnel is plaintext and unauthenticated. It demonstrates encapsulation, not security.

## Concepts

Every endpoint has two kinds of address:

- The **inner** (tunnel) address belongs to `rvpn0`. Applications use it; `ping 10.210.0.2` targets an inner address.
- The **outer** (transport) address belongs to the real interface. Only `vpn_tunnel` uses it, to carry inner packets inside UDP datagrams.

Wrapping one packet inside another is **encapsulation**:

```text
on the wire: | outer IPv4 | UDP | frame header | inner IPv4 packet |
               20 bytes    8      16 bytes       up to 1456 bytes
```

Both peers run the same program with mirrored arguments. Either side can send first, so there is no client or server, only two peers.

## Topology

The lab reuses the Phase 4 direct topology for the outer network:

```text
 rvpn-client                                   rvpn-server
┌─────────────────────────┐                  ┌─────────────────────────┐
│ inner: rvpn0 10.210.0.1 │                  │ inner: rvpn0 10.210.0.2 │
│           │             │                  │           ▲             │
│      vpn_tunnel         │                  │      vpn_tunnel         │
│           │             │                  │           │             │
│ outer: rvpn-c 10.200.1.1│ ═══ UDP :51820 ═►│ outer: rvpn-s 10.200.1.2│
└─────────────────────────┘                  └─────────────────────────┘
```

| Setting | `rvpn-client` | `rvpn-server` |
| --- | --- | --- |
| TUN address | `10.210.0.1` | `10.210.0.2` |
| UDP bind address | `10.200.1.1:51820` | `10.200.1.2:51820` |
| Peer UDP address | `10.200.1.2:51820` | `10.200.1.1:51820` |

Both peers name their interface `rvpn0`. That works because each namespace has its own interface list.

## How `vpn_tunnel` works

```text
vpn_tunnel <tun-address> <bind-address> <peer-address> <allowed-ips>
```

The fourth argument was added in [Phase 7](phase7-routing-nat.md#allowed-ips). It lists the source addresses the peer may send from; in this lab each peer allows only the other's tunnel address.

`read` on TUN and `recv` on UDP both block, so one loop cannot wait for both. The program runs one blocking loop per direction:

```text
              ┌──────────── vpn_tunnel ────────────┐
 rvpn0 ──read──► thread: tun_to_udp ──send─────────┼──► peer
 rvpn0 ◄─write── main:   udp_to_tun ◄─recv─────────┼─── peer
              └────────────────────────────────────┘
```

- `device.split()` turns the TUN device into a `Reader` and a `Writer` that share the same open file.
- `socket.try_clone()` gives a second handle to the same UDP socket, so one thread sends while the other receives.
- `tun_to_udp` wraps every packet, IPv6 included, in a `Data` frame with an increasing counter. It does not inspect packets.
- `udp_to_tun` decodes each frame, ignores anything that is not `Data`, and writes the payload into TUN.

Error handling separates local failures from network ones:

| Event | Response |
| --- | --- |
| TUN read fails | Fatal: the process exits, so the tunnel never runs in one direction only |
| Frame too large, or send fails | Log and drop the packet |
| `recv` returns `ConnectionRefused` | Ignore: the peer is not running yet |
| Malformed or non-`Data` frame | Log and drop |
| Kernel rejects a TUN write | Log and drop: the payload came from the network |

A peer that is down produces ICMP port-unreachable messages, which Linux reports as `ConnectionRefused` on a connected UDP socket's next `send` or `recv`. Treating that as fatal would let one missing peer crash the other.

## MTU

The veth link MTU is 1500 bytes. Encapsulation adds 44 bytes, so `rvpn0` is created with a smaller MTU, ensuring every outer packet fits in one link-sized datagram:

```text
   1500   link MTU
 −   20   outer IPv4 header
 −    8   UDP header
 −   16   frame header
 ──────
   1456   rvpn0 MTU (TUN_MTU)
```

The largest unfragmented ping through the tunnel therefore carries 1428 bytes of data (1456 − 20 inner IPv4 − 8 ICMP). Its outer packet is exactly 1500 bytes, with a 1472-byte UDP payload. A 1456-byte inner packet also stays well under the protocol's 2032-byte `MAX_PAYLOAD_SIZE`.

## Running the lab

Build as your user, then create the namespaces:

```bash
cargo build
sudo ./scripts/netns-direct.sh up
```

Start one peer in each namespace, in separate terminals:

```bash
sudo ip netns exec rvpn-client \
    ./target/debug/vpn_tunnel 10.210.0.1 10.200.1.1:51820 10.200.1.2:51820 10.210.0.2/32
```

```bash
sudo ip netns exec rvpn-server \
    ./target/debug/vpn_tunnel 10.210.0.2 10.200.1.2:51820 10.200.1.1:51820 10.210.0.1/32
```

Ping the other peer's inner address:

```bash
sudo ip netns exec rvpn-client ping -c 3 10.210.0.2
```

Each peer logs `direction=send` and `direction=receive` lines. Stop both peers with Ctrl+C, then remove the lab:

```bash
sudo ./scripts/netns-direct.sh down
```

## Verification

All checks below were run with both peers up in the direct lab. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` also pass.

The captures were taken with a small `AF_PACKET` raw-socket script rather than `tcpdump`, because `tcpdump` could not run inside the unprivileged namespaces used for this test run. The output below is that script's format. The `tcpdump` commands given with each check observe the same traffic in a normal `sudo` lab.

### Ping

`rvpn0` came up with the expected MTU, and pings to the other peer's inner address were answered by the real kernel in `rvpn-server`, not by a user-space reply like Phase 5:

```text
$ ip netns exec rvpn-client ip link show rvpn0
... mtu 1456 ...

$ ip netns exec rvpn-client ping -c 3 10.210.0.2
64 bytes from 10.210.0.2: icmp_seq=1 ttl=64 time=0.453 ms
64 bytes from 10.210.0.2: icmp_seq=2 ttl=64 time=0.178 ms
64 bytes from 10.210.0.2: icmp_seq=3 ttl=64 time=0.192 ms
3 packets transmitted, 3 received, 0% packet loss
```

Both peers logged matching `direction=send` and `direction=receive` lines; for a ping, `packet_length=84` and `frame_length=100`.

### Encapsulation

The same ping, captured at the same time on both sides of the tunnel:

```bash
sudo ip netns exec rvpn-client tcpdump -i rvpn-c -nn    # outer
sudo ip netns exec rvpn-server tcpdump -i rvpn0 -nn     # inner
```

The outer veth carried only UDP between the two peers' port 51820, never ICMP:

```text
IP 10.200.1.1.51820 > 10.200.1.2.51820: UDP udp_payload=100 ip_total=128
IP 10.200.1.2.51820 > 10.200.1.1.51820: UDP udp_payload=100 ip_total=128
```

Inside the tunnel, `rvpn0` carried the plain ICMP:

```text
IP 10.210.0.1 > 10.210.0.2: ICMP echo request ip_total=84
IP 10.210.0.2 > 10.210.0.1: ICMP echo reply ip_total=84
```

The sizes match the layer arithmetic: an 84-byte ping plus the 16-byte frame header is a 100-byte UDP payload, and 100 + 8 UDP + 20 outer IPv4 is 128. The outer capture also showed some 64-byte UDP payloads, carrying 48-byte inner packets. Those are the kernel's own background traffic on the new interfaces (likely IPv6), which the tunnel carries without inspecting it.

### TCP

An HTTP server on one peer's inner address, fetched from the other peer:

```bash
sudo ip netns exec rvpn-server python3 -m http.server 8000 --bind 10.210.0.2
sudo ip netns exec rvpn-client curl http://10.210.0.2:8000/
```

```text
$ curl http://10.210.0.2:8000/hello.txt
hello through the tunnel
$ curl -o /dev/null -w "HTTP %{http_code}, %{size_download} bytes\n" http://10.210.0.2:8000/
HTTP 200, 299 bytes
```

The tunnel carried the TCP handshake, request, response, and close without knowing they were TCP; the peers' logs showed the corresponding burst of packets of different sizes.

### MTU

The "don't fragment" flag (`-M do`) makes the kernel refuse oversized packets instead of splitting them. The largest payload that should fit passed:

```text
$ ip netns exec rvpn-client ping -c 2 -M do -s 1428 10.210.0.2
PING 10.210.0.2 (10.210.0.2) 1428(1456) bytes of data.
1436 bytes from 10.210.0.2: icmp_seq=1 ttl=64 time=0.192 ms
1436 bytes from 10.210.0.2: icmp_seq=2 ttl=64 time=0.245 ms
2 packets transmitted, 2 received, 0% packet loss
```

On the outer veth, each of those packets was exactly the link MTU, in one piece:

```text
IP 10.200.1.1.51820 > 10.200.1.2.51820: UDP udp_payload=1472 ip_total=1500
```

One byte more was refused by the client's own kernel, before `vpn_tunnel` ever saw it, because it would not fit in `rvpn0`'s 1456-byte MTU:

```text
$ ip netns exec rvpn-client ping -c 2 -M do -s 1429 10.210.0.2
PING 10.210.0.2 (10.210.0.2) 1429(1457) bytes of data.
ping: sendmsg: Message too long
ping: sendmsg: Message too long
2 packets transmitted, 0 received, +2 errors, 100% packet loss
```

### Why the smaller MTU matters

To see the problem `TUN_MTU` avoids, both `rvpn0` interfaces were set back to a 1500-byte MTU and pinged with a 1472-byte payload, giving a 1500-byte inner packet:

```bash
sudo ip netns exec rvpn-client ip link set rvpn0 mtu 1500
sudo ip netns exec rvpn-server ip link set rvpn0 mtu 1500
sudo ip netns exec rvpn-client ping -c 2 -M do -s 1472 10.210.0.2
```

The ping still succeeded, but each tunnelled packet now needed a 1516-byte UDP payload, and the outer packet would be 1544 bytes. That exceeds the veth MTU, so the kernel split every outer datagram into two fragments:

```text
IP 10.200.1.1.51820 > 10.200.1.2.51820: UDP udp_payload=1516 ip_total=1500 FRAGMENT offset=0 more=True
IP 10.200.1.1 > 10.200.1.2: UDP ip_total=64 FRAGMENT offset=1480 more=False
```

The inner packet had "don't fragment" set, but that flag is invisible to the outer layer, so the outer packet was fragmented anyway. Fragmentation doubles the packet count, and losing either fragment loses the whole packet. On real networks, fragments are also often dropped by firewalls. With the 1456-byte MTU this never happens. Restarting `vpn_tunnel` restores the MTU.

## Limitations

- No encryption or authentication: anyone on the outer path can read or inject traffic.
- One fixed peer, configured on the command line.
- The receiver does not check the session ID or counter, so duplicated, reordered, or replayed frames are accepted.
- Only the peers' own inner addresses are reachable; there is no routing or NAT to other networks.
- Every packet is logged, which limits throughput.
- `vpn_client`, `vpn_server`, and `tun_reader` remain as single-purpose demos; `vpn_tunnel` supersedes them.
