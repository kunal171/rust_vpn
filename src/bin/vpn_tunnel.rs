//! Connects a Linux TUN interface to a UDP peer.
//!
//! One thread reads packets from TUN and sends them to the peer in Data
//! frames; the main thread receives frames from the peer and writes their
//! payloads into TUN. Both ends run this same program with mirrored
//! arguments.

use rust_vpn::cidr::{CidrError, Ipv4Cidr};
use rust_vpn::ipv4::decode_ipv4_header;
use rust_vpn::protocol::{Frame, MessageType};
use rust_vpn::toy_crypto::{
    key_derivation::{SessionRole, derive_session_keys},
    session::{CryptoReceiver, CryptoSender, CryptoSession},
};
use rust_vpn::transport::RECEIVE_BUFFER_SIZE;
use std::env;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use tun::{Configuration, Layer, Reader, Writer};

const TUN_NAME: &str = "rvpn0";
const TUN_NETMASK: &str = "255.255.255.0";

const USAGE: &str = "usage: vpn_tunnel <client|server> <tun-address> <bind-address> \
     <peer-address> <allowed-ips>";

const LAB_SHARED_SECRET: &[u8] = b"phase-8-public-lab-secret-not-secure";

const LAB_SESSION_SALT: &[u8] = b"phase-8-tunnel-session";

/// Link MTU (1500) minus outer IPv4 (20), UDP (8), and frame header (16),
/// so an encapsulated packet still fits in one link-sized datagram.
const TUN_MTU: u16 = 1440;
const SESSION_ID: u32 = 1;
// Same reasoning as tun_reader: the largest possible IPv4 packet.
const PACKET_BUFFER_SIZE: usize = 65_535;

fn parse_role(value: &str) -> io::Result<SessionRole> {
    match value {
        "client" => Ok(SessionRole::Client),
        "server" => Ok(SessionRole::Server),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "role must be client or server",
        )),
    }
}

/// Parses a comma-separated list such as `10.210.0.2/32,10.200.4.0/24`.
fn parse_allowed_ips(text: &str) -> Result<Vec<Ipv4Cidr>, CidrError> {
    text.split(',').map(str::parse).collect()
}

/// Returns the next command-line argument, or an error that names it.
fn required_argument(
    arguments: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, Box<dyn Error>> {
    arguments
        .next()
        .ok_or_else(|| format!("missing {name}\n{USAGE}").into())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);

    let role = parse_role(&required_argument(&mut arguments, "role")?)?;
    let keys = derive_session_keys(LAB_SHARED_SECRET, LAB_SESSION_SALT)?;

    let (sender, receiver) = CryptoSession::new(SESSION_ID, role, keys).into_split();

    let tun_address: Ipv4Addr = required_argument(&mut arguments, "tun-address")?.parse()?;
    let bind_address: SocketAddr = required_argument(&mut arguments, "bind-address")?.parse()?;
    let peer_address: SocketAddr = required_argument(&mut arguments, "peer-address")?.parse()?;
    let allowed_ips = parse_allowed_ips(&required_argument(&mut arguments, "allowed-ips")?)?;

    let mut configuration = Configuration::default();

    configuration
        .tun_name(TUN_NAME)
        .address(tun_address)
        .netmask(TUN_NETMASK)
        .mtu(TUN_MTU)
        .layer(Layer::L3)
        .up();

    let device = tun::create(&configuration)?;

    let socket = UdpSocket::bind(bind_address)?;
    // As in vpn_client: no handshake, just a default peer for send/recv.
    socket.connect(peer_address)?;

    println!("Created {TUN_NAME} with address {tun_address}/24");
    println!(
        "UDP bound to {} with peer {peer_address}",
        socket.local_addr()?
    );

    let allowed_list: Vec<String> = allowed_ips.iter().map(ToString::to_string).collect();
    println!("Accepting inner packets from {}", allowed_list.join(", "));

    let (reader, writer) = device.split();
    let send_socket = socket.try_clone()?;

    thread::spawn(move || {
        if let Err(error) = tun_to_udp(reader, send_socket, peer_address, sender) {
            eprintln!("TUN to UDP stopped: {error}");
            // A tunnel that can only receive is broken; stop the whole process.
            std::process::exit(1);
        }
    });

    udp_to_tun(socket, writer, &allowed_ips, receiver)?;

    Ok(())
}

/// Reads packets from TUN and sends each one to the peer in a Data frame.
fn tun_to_udp(
    mut reader: Reader,
    socket: UdpSocket,
    peer_address: SocketAddr,
    mut sender: CryptoSender,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; PACKET_BUFFER_SIZE];

    loop {
        let packet_length = reader.read(&mut buffer)?;
        let packet = &buffer[..packet_length];

        let frame = sender
            .protect(MessageType::Data, packet.to_vec())
            .map_err(io::Error::other)?;

        let counter = frame.counter();
        let encoded_frame = frame.encode();

        // A missing peer must not stop the tunnel; drop the packet and go on.
        match socket.send(&encoded_frame) {
            Ok(sent_length) => println!(
                "direction=send peer={peer_address} counter={counter} \
                packet_length={packet_length} frame_length={sent_length}"
            ),
            Err(error) => eprintln!("Dropping packet {counter}: send failed: {error}"),
        }
    }
}

/// Receives Data frames from the peer and writes their payloads into TUN.
fn udp_to_tun(
    socket: UdpSocket,
    mut writer: Writer,
    allowed_ips: &[Ipv4Cidr],
    mut receiver: CryptoReceiver,
) -> io::Result<()> {
    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    loop {
        let received_length = match socket.recv(&mut buffer) {
            Ok(length) => length,
            // The peer is not running yet; keep waiting for it.
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => continue,
            Err(error) => return Err(error),
        };

        let protected_frame = match Frame::decode(&buffer[..received_length]) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("Rejected malformed frame: {error}");
                continue;
            }
        };

        let frame = match receiver.unprotect(&protected_frame) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!(
                    "Rejected protected frame counter={}: {error}",
                    protected_frame.counter()
                );
                continue;
            }
        };

        if frame.message_type() != MessageType::Data {
            eprintln!("Ignoring unexpected {:?} frame", frame.message_type());
            continue;
        }

        // The peer may only send from its allowed addresses; anything else
        // would let it inject spoofed traffic into this side's network.
        let source = match decode_ipv4_header(frame.payload()) {
            Ok(header) => header.source(),
            Err(error) => {
                eprintln!("Dropping packet {}: {error}", frame.counter());
                continue;
            }
        };

        if !allowed_ips.iter().any(|network| network.contains(source)) {
            eprintln!(
                "Dropping packet {}: source {source} is not an allowed IP",
                frame.counter()
            );
            continue;
        }

        // The payload came from the network, so the kernel may still reject it.
        match writer.write_all(frame.payload()) {
            Ok(()) => println!(
                "direction=receive counter={} packet_length={}",
                frame.counter(),
                frame.payload().len()
            ),
            Err(error) => eprintln!(
                "Dropping packet {}: TUN write failed: {error}",
                frame.counter()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_role;
    use rust_vpn::toy_crypto::key_derivation::SessionRole;

    #[test]
    fn parses_client_and_server_roles() {
        assert_eq!(parse_role("client").unwrap(), SessionRole::Client);
        assert_eq!(parse_role("server").unwrap(), SessionRole::Server);
    }

    #[test]
    fn rejects_unknown_roles() {
        assert!(parse_role("peer").is_err());
    }
}
