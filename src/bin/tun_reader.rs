//! Creates a temporary Linux TUN interface and answers pings sent through it.
//!
//! Reading from the device returns packets the kernel routed out through the
//! interface. Writing to it injects a packet as if it had arrived from the
//! network. This binary reads each packet, prints its IPv4 header, and writes
//! back an echo reply when the packet is an ICMP echo request.
//!
//! This is a Phase 5 diagnostic binary. It does not yet forward, encrypt, or
//! transport packets over UDP. It runs until interrupted, and the interface
//! disappears when the process exits.
use rust_vpn::ipv4::{decode_ipv4_header, icmp_echo_reply};
use std::io::{Read, Write};
use tun::{Configuration, Layer};

const TUN_NAME: &str = "rvpn0";
// The host owns this address, so the kernel answers pings to it directly.
// Ping any other address in the /24, such as 10.210.0.2, to reach this program.
const TUN_ADDRESS: &str = "10.210.0.1";
const TUN_NETMASK: &str = "255.255.255.0";

// An IPv4 packet's total-length field is 16 bits, so the largest
// representable IPv4 packet is 65,535 bytes.
const PACKET_BUFFER_SIZE: usize = 65_535;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut configuration = Configuration::default();

    configuration
        .tun_name(TUN_NAME)
        .address(TUN_ADDRESS)
        .netmask(TUN_NETMASK)
        .layer(Layer::L3)
        .up();

    let mut device = tun::create(&configuration)?;
    println!("Created {TUN_NAME} with address {TUN_ADDRESS}/24");
    println!("Waiting for IP packets; press Ctrl+C to stop...");

    let mut buffer = vec![0_u8; PACKET_BUFFER_SIZE];

    loop {
        // Layer 3 mode delivers exactly one whole IP packet per read.
        let packet_length = device.read(&mut buffer)?;
        let packet = &buffer[..packet_length];

        // Never use packet[0] without checking that the slice contains a byte.
        let Some(first_byte) = packet.first() else {
            eprintln!("Ignoring an empty TUN packet");
            continue;
        };

        let version = first_byte >> 4;

        match version {
            4 => match decode_ipv4_header(packet) {
                Ok(header) => {
                    println!(
                        "IPv4 source={} destination={} header_length={} total_length={} ttl={} protocol={}",
                        header.source(),
                        header.destination(),
                        header.header_length(),
                        header.total_length(),
                        header.ttl(),
                        header.protocol(),
                    );
                    // Anything that is not an echo request is reported and
                    // dropped; only pings are answered in this phase.
                    match icmp_echo_reply(packet) {
                        Ok(reply) => {
                            device.write_all(&reply)?;
                            println!("Sent echo reply to {}", header.source());
                        }
                        Err(error) => {
                            eprintln!("Not replying: {error}");
                        }
                    }
                }
                Err(error) => {
                    eprintln!("Ignoring IPv4 packet: {error}");
                    continue;
                }
            },
            // The kernel sends IPv6 housekeeping traffic on every new interface.
            6 => {
                println!("Ignoring IPv6 packet: {packet_length} bytes");
            }
            unsupported_version => {
                eprintln!(
                    "Ignoring packet with unsupported IP version: \
                    {unsupported_version}"
                );
            }
        }
    }
}
