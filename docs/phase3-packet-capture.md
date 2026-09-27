# Phase 3: Packet-capture verification

This phase proves the VPN prototype packet path using `tcpdump`. The capture contains plaintext educational traffic over IPv4 loopback; it does not prove security, confidentiality, reliability, or production readiness.

## What is verified

- The client reuses one ephemeral UDP port for three stop-and-wait exchanges.
- The server listens on UDP port `51820`.
- Data frames carry counters `1`, `2`, and `3`.
- Every acknowledgment echoes the corresponding session ID and counter.
- Data frames have a 21-byte UDP payload; acknowledgments have 16 bytes.
- The application payload remains visible in plaintext.

## Capture procedure

Start the server:

```bash
cargo run --bin vpn_server
```

In a second terminal, capture the six logical UDP packets:

```bash
sudo tcpdump -i lo -nn -vvv -XX -c 6 "udp port 51820"
```

Wait for `listening on lo`, then run the client in a third terminal:

```bash
cargo run --bin vpn_client
```

The expected order is:

| Packet | Direction | Message | Counter | UDP payload | IPv4 total |
|---:|---|---|---:|---:|---:|
| 1 | Client to server | Data | 1 | 21 bytes | 49 bytes |
| 2 | Server to client | Acknowledgment | 1 | 16 bytes | 44 bytes |
| 3 | Client to server | Data | 2 | 21 bytes | 49 bytes |
| 4 | Server to client | Acknowledgment | 2 | 16 bytes | 44 bytes |
| 5 | Client to server | Data | 3 | 21 bytes | 49 bytes |
| 6 | Server to client | Acknowledgment | 3 | 16 bytes | 44 bytes |

## Layer sizes

With the headers observed in this loopback capture:

```text
Ethernet-style capture header: 14 bytes
IPv4 header:                    20 bytes
UDP header:                      8 bytes
Application frame:        21 or 16 bytes
```

The Data packet calculation is:

```text
20-byte IPv4 header + 8-byte UDP header + 21-byte frame = 49 bytes
```

The acknowledgment calculation is:

```text
20-byte IPv4 header + 8-byte UDP header + 16-byte frame = 44 bytes
```

Linux loopback has no physical Ethernet hardware. `libpcap` nevertheless presents an Ethernet-style 14-byte capture header with placeholder MAC addresses and EtherType `0x0800` for IPv4.

## Application-frame offsets

In this capture, the application frame begins at capture offset `0x2a`:

```text
14-byte link header + 20-byte IPv4 header + 8-byte UDP header = 42 (0x2a)
```

| Capture offset | Frame offset | Field | Size |
|---:|---:|---|---:|
| `0x2a` | 0 | Version | 1 byte |
| `0x2b` | 1 | Message type | 1 byte |
| `0x2c..0x2f` | 2..5 | Session ID | 4 bytes |
| `0x30..0x37` | 6..13 | Counter | 8 bytes |
| `0x38..0x39` | 14..15 | Payload length | 2 bytes |
| `0x3a..` | 16.. | Payload | variable |

These capture offsets are evidence from this specific layout, not general parser constants. IPv4 options or another link type would move them.

## Representative Data frame

```text
01 01
00 00 00 01
00 00 00 00 00 00 00 01
00 05
00 01 ff 48 69
```

This decodes to version `1`, Data type `1`, session `1`, counter `1`, payload length `5`, and payload bytes `00 01 ff 48 69`. Only `48 69` is printable ASCII (`Hi`); the entire payload is arbitrary binary data, not valid UTF-8 text.

## Representative acknowledgment frame

```text
01 02
00 00 00 01
00 00 00 00 00 00 00 01
00 00
```

Message type `2` identifies an acknowledgment. Its session and counter match the Data frame, and its payload length is zero. Later pairs change the final counter byte from `01` to `02` and `03` in both directions.

## Checksum warning

Local captures may report `bad udp cksum`. Linux can expose a packet to the capture path before completing checksum work, so this commonly reflects checksum offloading or internal loopback handling. Successful decoding by both applications confirms that this observation is not application-data damage.

## Saving a PCAP safely

To save full packet records for local Wireshark analysis:

```bash
sudo tcpdump -i lo -nn -s 0 -c 6 \
  -w /tmp/rust-vpn-phase3.pcap "udp port 51820"
```

Read it without Wireshark:

```bash
tcpdump -nn -vvv -XX -r /tmp/rust-vpn-phase3.pcap
```

Capture files are intentionally ignored by Git because they may contain sensitive payloads, addresses, ports, or future authentication material.

## Completion evidence

The capture demonstrates IPv4/UDP encapsulation, exact frame lengths, big-endian header fields, increasing application counters, matching acknowledgments, stop-and-wait ordering, visible plaintext, and zero packets dropped by the kernel during the observed run.
