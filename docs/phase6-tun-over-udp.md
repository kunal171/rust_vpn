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
vpn_tunnel <tun-address> <bind-address> <peer-address>
```

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
    ./target/debug/vpn_tunnel 10.210.0.1 10.200.1.1:51820 10.200.1.2:51820
```

```bash
sudo ip netns exec rvpn-server \
    ./target/debug/vpn_tunnel 10.210.0.2 10.200.1.2:51820 10.200.1.1:51820
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

### Verified

- Pings from `rvpn-client` to `10.210.0.2` received replies. The replies come from the real kernel in `rvpn-server`, not from a user-space reply like Phase 5.
- Both peers logged matching `direction=send` and `direction=receive` lines.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` pass.

### Further checks

These checks follow from the design but have not yet been recorded. Run them with both peers running, and move each result into the Verified list with its real output.

**Encapsulation.** Capture on the outer interface while pinging:

```bash
sudo ip netns exec rvpn-client tcpdump -i rvpn-c -nn
```

Only `UDP 10.200.1.1.51820 > 10.200.1.2.51820` traffic should appear, never ICMP. The same capture on `-i rvpn0` shows the plain ICMP inside the tunnel.

**TCP.** Serve HTTP on one peer's inner address and fetch it from the other:

```bash
sudo ip netns exec rvpn-server python3 -m http.server 8000 --bind 10.210.0.2
sudo ip netns exec rvpn-client curl http://10.210.0.2:8000/
```

`curl` should print a directory listing. The tunnel carries the TCP handshake, request, response, and close without knowing they are TCP.

**MTU.** The "don't fragment" flag (`-M do`) makes the kernel refuse oversized packets instead of splitting them:

```bash
sudo ip netns exec rvpn-client ping -c 2 -M do -s 1428 10.210.0.2
sudo ip netns exec rvpn-client ping -c 2 -M do -s 1429 10.210.0.2
```

The first should succeed, with `length 1472` UDP datagrams in the outer capture. The second should fail locally with a message reporting `mtu=1456`.

## Limitations

- No encryption or authentication: anyone on the outer path can read or inject traffic.
- One fixed peer, configured on the command line.
- The receiver does not check the session ID or counter, so duplicated, reordered, or replayed frames are accepted.
- Only the peers' own inner addresses are reachable; there is no routing or NAT to other networks.
- Every packet is logged, which limits throughput.
- `vpn_client`, `vpn_server`, and `tun_reader` remain as single-purpose demos; `vpn_tunnel` supersedes them.
