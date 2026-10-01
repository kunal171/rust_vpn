//! Creates a temporary Linux TUN interface and reads one IP packet.
//!
//! This is a Phase 5 diagnostic binary. It does not yet forward,
//! encrypt, or transport the captured packet.
use std::io::Read;
use std::net::Ipv4Addr;
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
            4 => {
                const MINIMUM_IPV4_HEADER_LENGTH: usize = 20;
                if packet.len() < MINIMUM_IPV4_HEADER_LENGTH {
                    eprintln!("Ignoring truncated IPv4 packet");
                    continue;
                }

                let ihl_words = packet[0] & 0x0f;

                let header_length = usize::from(ihl_words) * 4;

                if header_length < MINIMUM_IPV4_HEADER_LENGTH {
                    eprintln!("Ignoring IPv4 packet with invalid header length");
                    continue;
                }

                if packet.len() < header_length {
                    eprintln!("Ignoring truncated IPv4 header");
                    continue;
                }

                let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));

                if total_length < header_length || total_length > packet.len() {
                    eprintln!("Ignoring IPv4 packet with invalid total length");
                    continue;
                }

                let ttl = packet[8];
                let protocol = packet[9];

                let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

                let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                println!(
                    "IPv4 source={source} destination={destination} \
                    header_length={header_length} total_length={total_length} \
                    ttl={ttl} protocol={protocol}"
                );
                break;
            }
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
