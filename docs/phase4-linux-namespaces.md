# Phase 4: Linux network namespaces

Phase 4 runs the UDP client and server in separate Linux network stacks on one host. It verifies that the protocol works across virtual interfaces instead of relying on a shared loopback interface.

## Concepts

A network namespace has its own interfaces, addresses, routes, neighbor table, firewall state, and sockets. Consequently, `127.0.0.1` inside the client namespace is different from `127.0.0.1` inside the server namespace.

A veth pair behaves like a virtual Ethernet cable: a frame entering one endpoint exits the peer endpoint. A Linux bridge behaves like a Layer 2 switch and learns which MAC addresses are reachable through its ports.

The two scripts use different names and subnets, so their labs can coexist:

| Topology | Namespaces | Subnet |
| --- | --- | --- |
| Direct | `rvpn-client`, `rvpn-server` | `10.200.1.0/24` |
| Bridged | `rvpnb-client`, `rvpnb-server` | `10.200.2.0/24` |

Both scripts support `up`, `status`, and `down`. They require root because creating namespaces and network interfaces needs Linux network-administration privileges.

## Direct topology

The direct lab connects one endpoint in each namespace:

```text
rvpn-client                 rvpn-server
10.200.1.1/24               10.200.1.2/24
    rvpn-c <===== veth =====> rvpn-s
```

Create and inspect it:

```bash
sudo ./scripts/netns-direct.sh up
sudo ./scripts/netns-direct.sh status
sudo ip netns exec rvpn-client ping -c 3 10.200.1.2
```

Run the server in one terminal:

```bash
sudo ip netns exec rvpn-server \
    ./target/debug/vpn_server 10.200.1.2:51820
```

Run the client in another terminal:

```bash
sudo ip netns exec rvpn-client \
    ./target/debug/vpn_client 10.200.1.2:51820 10.200.1.1:0
```

The client argument order is the server endpoint followed by the local bind address. Port `0` asks Linux to select an available ephemeral client port.

Remove the direct lab:

```bash
sudo ./scripts/netns-direct.sh down
```

## Bridged topology

The bridged lab gives each namespace a separate veth pair. Their host-side endpoints are ports on a Linux bridge:

```text
rvpnb-client                                      rvpnb-server
10.200.2.1/24                                     10.200.2.2/24
  rvpnb-c <==> rvpnb-c-br -- rvpnb-br -- rvpnb-s-br <==> rvpnb-s
```

Create and inspect it:

```bash
sudo ./scripts/netns-bridge.sh up
sudo ./scripts/netns-bridge.sh status
sudo ip netns exec rvpnb-client ping -c 3 10.200.2.2
bridge fdb show br rvpnb-br
```

The forwarding database (`bridge fdb`) shows which source MAC addresses the bridge learned on each port.

Run the server in one terminal:

```bash
sudo ip netns exec rvpnb-server \
    ./target/debug/vpn_server 10.200.2.2:51820
```

Run the client in another terminal:

```bash
sudo ip netns exec rvpnb-client \
    ./target/debug/vpn_client 10.200.2.2:51820 10.200.2.1:0
```

Remove the bridged lab and confirm that its resources disappeared:

```bash
sudo ./scripts/netns-bridge.sh down
sudo ./scripts/netns-bridge.sh status
```

## Verified behavior

Both topologies were tested with three successful ICMP echo requests and the application's three stop-and-wait Data/Acknowledgment exchanges. The bridge cleanup left no `rvpnb-*` namespaces, bridge, or bridge ports.

These labs isolate network stacks, but they do not yet tunnel operating-system IP traffic. Phase 5 introduces a TUN interface for that purpose.
