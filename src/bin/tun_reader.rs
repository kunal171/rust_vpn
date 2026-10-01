//! Creates a temporary Linux TUN interface and reads one IP packet.
//!
//! This is a Phase 5 diagnostic binary. It does not yet forward,
//! encrypt, or transport the captured packet.
use rust_vpn::ipv4::decode_ipv4_header;
use std::io::Read;
use tun::{Configuration, Layer};

const TUN_NAME: &str = "rvpn0";
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
    println!("Waiting for one IP packet...");

    let mut buffer = vec![0_u8; PACKET_BUFFER_SIZE];

    loop {
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
                    break;
                }
                Err(error) => {
                    eprintln!("Ignoring IPv4 packet: {error}");
                    continue;
                }
            },
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

    Ok(())
}
