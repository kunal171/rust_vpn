//! Connects a Linux TUN interface to a UDP peer.
//!
//! One thread reads packets from TUN, encrypts them, and sends protected Data
//! frames to the peer. The main thread authenticates and decrypts received
//! frames before writing their inner IP packets into TUN. Both ends run this
//! same program with mirrored roles and addresses.

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

// These public, fixed bytes make the encrypted data path reproducible while
// learning. They provide no secrecy, peer authentication, or safe key renewal.
// Restarting also resets the counter and therefore reuses nonces with this key.
const LAB_SHARED_SECRET: &[u8] = b"phase-8-public-lab-secret-not-secure";

// Both peers must use the same salt so HKDF derives matching directional keys.
const LAB_SESSION_SALT: &[u8] = b"phase-8-tunnel-session";

/// Link MTU (1500) minus outer IPv4 (20), UDP (8), frame header (16),
/// and authentication tag (16), avoiding outer IP fragmentation.
const TUN_MTU: u16 = 1440;
// The fixed ID is sufficient for the one-session lab. A future handshake will
// negotiate fresh session identity and key material.
const SESSION_ID: u32 = 1;
// Same reasoning as tun_reader: the largest possible IPv4 packet.
const PACKET_BUFFER_SIZE: usize = 65_535;

/// Converts the command-line role into directional send and receive key usage.
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

    // HKDF turns the shared lab bytes into independent keys for each traffic
    // direction. The role decides which key this peer sends and receives with.
    let keys = derive_session_keys(LAB_SHARED_SECRET, LAB_SESSION_SALT)?;

    // The sending thread owns the only send counter, while the receiving loop
    // independently owns replay-window state for authenticated inbound packets.
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
    // UDP connect performs no handshake; it only fixes the peer used by
    // send/recv. Cryptographic key agreement is also not implemented yet.
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

/// Reads inner IP packets from TUN and sends each in a protected Data frame.
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

        // CryptoSender allocates a unique counter, encrypts the inner packet,
        // and authenticates the visible frame header as associated data.
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

/// Authenticates received Data frames and writes their inner IP packets to TUN.
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

        // Structural decoding is safe before decryption, but none of these
        // peer-controlled header fields are trusted until unprotect succeeds.
        let protected_frame = match Frame::decode(&buffer[..received_length]) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("Rejected malformed frame: {error}");
                continue;
            }
        };

        // Authentication happens before replay-window mutation and before the
        // decrypted payload reaches IPv4 validation or the kernel's TUN input.
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
