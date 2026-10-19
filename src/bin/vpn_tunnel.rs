//! A TUN-reader thread queues inner packets, one sender thread protects all
//! outbound messages, and the main thread authenticates inbound frames before
//! writing Data packets to TUN or handling control messages.

use rust_vpn::cidr::{CidrError, Ipv4Cidr};
use rust_vpn::identity::{IDENTITY_PUBLIC_KEY_LENGTH, IDENTITY_SECRET_KEY_LENGTH, IdentityKeyPair};
use rust_vpn::ipv4::decode_ipv4_header;
use rust_vpn::keepalive::{KeepaliveAction, classify_authenticated_keepalive};
use rust_vpn::liveness::{LivenessAction, LivenessTracker};
use rust_vpn::outbound::OutboundMessage;
use rust_vpn::protocol::{Frame, MessageType};
use rust_vpn::toy_crypto::{
    key_derivation::SessionRole,
    session::{CryptoReceiver, CryptoSender},
};
use rust_vpn::transport::RECEIVE_BUFFER_SIZE;
use rust_vpn::udp_handshake::{
    ServerConfirmationCache, perform_client_handshake, perform_server_handshake,
};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU8;
use std::path::Path;
use std::sync::mpsc::{Receiver as OutboundReceiver, SyncSender, sync_channel};
use std::thread;
use std::time::Duration;
use tun::{Configuration, Layer, Reader, Writer};

const TUN_NAME: &str = "rvpn0";
const TUN_NETMASK: &str = "255.255.255.0";
/// Limits memory use when producers are faster than UDP transmission.
const OUTBOUND_QUEUE_CAPACITY: usize = 64;

const USAGE: &str = "usage: vpn_tunnel <client|server> <tun-address> <bind-address> \
     <peer-address> <allowed-ips> <identity-private-key> <peer-public-key>";

/// Link MTU (1500) minus outer IPv4 (20), UDP (8), frame header (16),
/// and authentication tag (16), avoiding outer IP fragmentation.
const TUN_MTU: u16 = 1440;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
// Same reasoning as tun_reader: the largest possible IPv4 packet.
const PACKET_BUFFER_SIZE: usize = 65_535;

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const MAX_MISSED_KEEPALIVES: u8 = 3;

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

/// Reads an exact-size raw key without first placing secret bytes in a heap vector.
fn read_fixed_key<const LENGTH: usize>(path: &Path, name: &str) -> io::Result<[u8; LENGTH]> {
    let mut file = File::open(path)?;
    let mut key = [0_u8; LENGTH];

    file.read_exact(&mut key).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} must contain exactly {LENGTH} bytes: {error}"),
        )
    })?;

    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} must contain exactly {LENGTH} bytes"),
        ));
    }

    Ok(key)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);

    let role = parse_role(&required_argument(&mut arguments, "role")?)?;
    let tun_address: Ipv4Addr = required_argument(&mut arguments, "tun-address")?.parse()?;
    let bind_address: SocketAddr = required_argument(&mut arguments, "bind-address")?.parse()?;
    let peer_address: SocketAddr = required_argument(&mut arguments, "peer-address")?.parse()?;
    let allowed_ips = parse_allowed_ips(&required_argument(&mut arguments, "allowed-ips")?)?;
    let identity_private_path = required_argument(&mut arguments, "identity-private-key")?;
    let peer_public_path = required_argument(&mut arguments, "peer-public-key")?;

    if arguments.next().is_some() {
        return Err(format!("too many arguments\n{USAGE}").into());
    }

    let mut identity_secret = read_fixed_key::<IDENTITY_SECRET_KEY_LENGTH>(
        Path::new(&identity_private_path),
        "identity private key",
    )?;
    let identity = IdentityKeyPair::from_secret_bytes(&mut identity_secret);
    let peer_public_key = read_fixed_key::<IDENTITY_PUBLIC_KEY_LENGTH>(
        Path::new(&peer_public_path),
        "peer public key",
    )?;

    let socket = UdpSocket::bind(bind_address)?;
    // UDP connect restricts datagrams to one network address. The handshake
    // independently authenticates the identity pinned in peer_public_key.
    socket.connect(peer_address)?;
    socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

    println!("Authenticating UDP peer {peer_address} as {role:?}...");

    let (session, confirmation_cache) = match role {
        SessionRole::Client => {
            let session = perform_client_handshake(&socket, &identity, peer_public_key)?;

            (session, None)
        }

        SessionRole::Server => {
            let (session, cache) = perform_server_handshake(&socket, &identity, peer_public_key)?;

            (session, Some(cache))
        }
    };

    socket.set_read_timeout(Some(KEEPALIVE_INTERVAL))?;

    // The sending thread exclusively owns the send counter, while the receive
    // loop owns replay state for this freshly authenticated session.
    let (crypto_sender, crypto_receiver) = session.into_split();

    println!("Authenticated UDP peer {peer_address}");

    let mut configuration = Configuration::default();

    configuration
        .tun_name(TUN_NAME)
        .address(tun_address)
        .netmask(TUN_NETMASK)
        .mtu(TUN_MTU)
        .layer(Layer::L3)
        .up();

    let device = tun::create(&configuration)?;

    println!("Created {TUN_NAME} with address {tun_address}/24");
    println!(
        "UDP bound to {} with peer {peer_address}",
        socket.local_addr()?
    );

    let allowed_list: Vec<String> = allowed_ips.iter().map(ToString::to_string).collect();
    println!("Accepting inner packets from {}", allowed_list.join(", "));

    let (reader, writer) = device.split();
    let send_socket = socket.try_clone()?;

    let (outbound_sender, outbound_receiver) = sync_channel(OUTBOUND_QUEUE_CAPACITY);

    let receive_outbound_sender = outbound_sender.clone();

    thread::spawn(move || {
        if let Err(error) =
            send_outbound_messages(send_socket, peer_address, crypto_sender, outbound_receiver)
        {
            eprintln!("Outbound sender stopped: {error}");
            std::process::exit(1);
        }
    });

    thread::spawn(move || {
        if let Err(error) = read_tun_packets(reader, outbound_sender) {
            eprintln!("TUN reader stopped: {error}");
            std::process::exit(1);
        }
    });

    udp_to_tun(
        socket,
        writer,
        &allowed_ips,
        crypto_receiver,
        confirmation_cache,
        receive_outbound_sender,
    )?;

    Ok(())
}

/// Reads inner IP packets from TUN and queues owned copies for encryption.
fn read_tun_packets(
    mut reader: Reader,
    outbound_sender: SyncSender<OutboundMessage>,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; PACKET_BUFFER_SIZE];

    loop {
        let packet_length = reader.read(&mut buffer)?;

        let message = OutboundMessage::Data(buffer[..packet_length].to_vec());

        outbound_sender.send(message).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "outbound sender disconnected")
        })?;
    }
}

/// Authenticates inbound frames, handles keepalive controls, and writes
/// allowed inner IP packets to TUN.
fn udp_to_tun(
    socket: UdpSocket,
    mut writer: Writer,
    allowed_ips: &[Ipv4Cidr],
    mut receiver: CryptoReceiver,
    mut confirmation_cache: Option<ServerConfirmationCache>,
    outbound_sender: SyncSender<OutboundMessage>,
) -> io::Result<()> {
    let mut liveness = LivenessTracker::new(
        NonZeroU8::new(MAX_MISSED_KEEPALIVES)
            .expect("maximum missed keepalives must be greater than zero"),
    );

    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    loop {
        let received_length = match socket.recv(&mut buffer) {
            Ok(length) => length,
            // The peer is not running yet; keep waiting for it.
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                match liveness.on_interval_elapsed() {
                    LivenessAction::SendKeepalive => {
                        outbound_sender
                            .send(OutboundMessage::Keepalive)
                            .map_err(|_| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "outbound tunnel sender stopped",
                                )
                            })?;

                        println!("No authenticated traffic; queued keepalive");
                        continue;
                    }
                    LivenessAction::PeerTimedOut => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "authenticated peer missed the keepalive limit",
                        ));
                    }
                }
            }
            Err(error) => return Err(error),
        };

        if let Some(cache) = &mut confirmation_cache
            && let Some(response) = cache.response_for(&buffer[..received_length])
        {
            socket.send(response)?;

            println!("Resent HandshakeComplete for duplicate ClientAuth");

            continue;
        }

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

        liveness.record_authenticated_activity();

        if matches!(
            frame.message_type(),
            MessageType::Keepalive | MessageType::KeepaliveResponse
        ) {
            let action = match classify_authenticated_keepalive(&frame) {
                Ok(action) => action,

                Err(error) => {
                    eprintln!("Rejected keepalive counter={}: {error}", frame.counter());
                    continue;
                }
            };

            // An authenticated post-handshake control frame proves that the
            // peer entered the established session.
            confirmation_cache = None;

            match action {
                KeepaliveAction::SendResponse => {
                    outbound_sender
                        .send(OutboundMessage::KeepaliveResponse)
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "outbound sender disconnected",
                            )
                        })?;

                    println!("Queued KeepaliveResponse for counter={}", frame.counter());
                }

                KeepaliveAction::ResponseReceived => {
                    println!(
                        "Received authenticated KeepaliveResponse \
                        counter={}",
                        frame.counter()
                    );
                }
            }

            continue;
        }

        if frame.message_type() != MessageType::Data {
            eprintln!("Ignoring unexpected {:?} frame", frame.message_type());
            continue;
        }

        // Authenticated Data proves the client received HandshakeComplete.
        confirmation_cache = None;

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

/// Protects and sends every queued message using one monotonically
/// increasing cryptographic counter.
fn send_outbound_messages(
    socket: UdpSocket,
    peer_address: SocketAddr,
    mut crypto_sender: CryptoSender,
    outbound_receiver: OutboundReceiver<OutboundMessage>,
) -> io::Result<()> {
    loop {
        let message = outbound_receiver.recv().map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "outbound queue disconnected")
        })?;

        let (message_type, payload) = message.into_parts();

        let payload_length = payload.len();

        let frame = crypto_sender
            .protect(message_type, payload)
            .map_err(io::Error::other)?;

        let counter = frame.counter();
        let encoded_frame = frame.encode();

        match socket.send(&encoded_frame) {
            Ok(sent_length) if sent_length == encoded_frame.len() => {
                println!(
                    "direction=send peer={peer_address} \
                     type={message_type:?} counter={counter} \
                     payload_length={payload_length} \
                     frame_length={sent_length}"
                );
            }

            Ok(sent_length) => {
                eprintln!(
                    "Dropping {message_type:?} counter={counter}: \
                     sent {sent_length} of {} bytes",
                    encoded_frame.len()
                );
            }

            Err(error) => {
                eprintln!(
                    "Dropping {message_type:?} \
                     counter={counter}: send failed: {error}"
                );
            }
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
