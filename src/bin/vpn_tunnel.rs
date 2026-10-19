//! A TUN-reader thread queues inner packets, one sender thread protects all
//! outbound messages, and the main thread authenticates inbound frames before
//! writing Data packets to TUN or handling control messages. The main thread
//! also owns lifecycle transitions and installs fresh sessions after timeout.

use rust_vpn::cidr::{CidrError, Ipv4Cidr};
use rust_vpn::identity::{IDENTITY_PUBLIC_KEY_LENGTH, IDENTITY_SECRET_KEY_LENGTH, IdentityKeyPair};
use rust_vpn::ipv4::decode_ipv4_header;
use rust_vpn::keepalive::{KeepaliveAction, classify_authenticated_keepalive};
use rust_vpn::liveness::{LivenessAction, LivenessTracker};
use rust_vpn::outbound::OutboundMessage;
use rust_vpn::protocol::{Frame, MessageType};
use rust_vpn::toy_crypto::{
    key_derivation::SessionRole,
    session::{CryptoReceiver, CryptoSender, CryptoSession},
};
use rust_vpn::transport::RECEIVE_BUFFER_SIZE;
use rust_vpn::tunnel_lifecycle::{TunnelEvent, TunnelState};
use rust_vpn::udp_handshake::{
    ServerConfirmationCache, UdpHandshakeError, perform_client_handshake, perform_server_handshake,
};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU8;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver as OutboundReceiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
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
/// Maximum wait for one expected handshake response.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
// Same reasoning as tun_reader: the largest possible IPv4 packet.
const PACKET_BUFFER_SIZE: usize = 65_535;

/// Quiet period before the receiver requests authenticated proof of life.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Consecutive unanswered probes allowed before discarding a session.
const MAX_MISSED_KEEPALIVES: u8 = 3;
/// Prevents repeated failed reconnect handshakes from spinning.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Replaceable sender slot shared by the lifecycle supervisor and send worker.
type SharedCryptoSender = Arc<Mutex<Option<CryptoSender>>>;

/// Normal reasons for returning control from the established receive loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiveLoopExit {
    /// Authenticated traffic remained absent through the configured probes.
    PeerTimedOut,
    /// Ctrl+C requested an orderly lifecycle transition.
    Shutdown,
}

/// Fresh cryptographic state plus the server-only confirmation retry cache.
struct HandshakeOutput {
    session: CryptoSession,
    confirmation_cache: Option<ServerConfirmationCache>,
}

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

/// Runs the role-specific authenticated handshake without duplicating it in
/// the initial-connection and reconnection paths.
fn perform_authenticated_handshake(
    socket: &UdpSocket,
    role: SessionRole,
    identity: &IdentityKeyPair,
    peer_public_key: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
) -> Result<HandshakeOutput, UdpHandshakeError> {
    match role {
        SessionRole::Client => {
            let session = perform_client_handshake(socket, identity, peer_public_key)?;

            Ok(HandshakeOutput {
                session,
                confirmation_cache: None,
            })
        }

        SessionRole::Server => {
            let (session, confirmation_cache) =
                perform_server_handshake(socket, identity, peer_public_key)?;

            Ok(HandshakeOutput {
                session,
                confirmation_cache: Some(confirmation_cache),
            })
        }
    }
}

/// Replaces or removes the only sender allowed to consume session counters.
fn set_outbound_session(
    shared_sender: &SharedCryptoSender,
    sender: Option<CryptoSender>,
) -> io::Result<()> {
    let mut current_sender = shared_sender
        .lock()
        .map_err(|_| io::Error::other("outbound crypto session lock was poisoned"))?;

    *current_sender = sender;

    Ok(())
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

    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let signal_shutdown_requested = Arc::clone(&shutdown_requested);

    ctrlc::set_handler(move || {
        signal_shutdown_requested.store(true, Ordering::Relaxed);
    })?;

    let socket = UdpSocket::bind(bind_address)?;
    // UDP connect restricts datagrams to one network address. The handshake
    // independently authenticates the identity pinned in peer_public_key.
    socket.connect(peer_address)?;
    socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

    println!("Authenticating UDP peer {peer_address} as {role:?}...");

    let mut tunnel_state = TunnelState::Handshaking;

    let handshake = perform_authenticated_handshake(&socket, role, &identity, peer_public_key)?;

    socket.set_read_timeout(Some(KEEPALIVE_INTERVAL))?;

    tunnel_state = tunnel_state.transition(TunnelEvent::HandshakeSucceeded)?;

    println!("Tunnel state: {tunnel_state:?}");

    // The sending thread exclusively owns the send counter, while the receive
    // loop owns replay state for this freshly authenticated session.
    let (crypto_sender, mut crypto_receiver) = handshake.session.into_split();
    let mut confirmation_cache = handshake.confirmation_cache;

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

    let (reader, mut writer) = device.split();
    let send_socket = socket.try_clone()?;

    let (outbound_sender, outbound_receiver) = sync_channel(OUTBOUND_QUEUE_CAPACITY);

    let receive_outbound_sender = outbound_sender.clone();
    let shared_crypto_sender = Arc::new(Mutex::new(Some(crypto_sender)));
    let send_crypto_sender = Arc::clone(&shared_crypto_sender);

    thread::spawn(move || {
        if let Err(error) = send_outbound_messages(
            send_socket,
            peer_address,
            send_crypto_sender,
            outbound_receiver,
        ) {
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

    loop {
        match udp_to_tun(
            &socket,
            &mut writer,
            &allowed_ips,
            crypto_receiver,
            confirmation_cache,
            &receive_outbound_sender,
            &shutdown_requested,
        )? {
            ReceiveLoopExit::PeerTimedOut => {
                tunnel_state = tunnel_state.transition(TunnelEvent::PeerTimedOut)?;
                set_outbound_session(&shared_crypto_sender, None)?;

                println!("Tunnel state: {tunnel_state:?}");
            }

            ReceiveLoopExit::Shutdown => {
                set_outbound_session(&shared_crypto_sender, None)?;
                tunnel_state = tunnel_state.transition(TunnelEvent::Shutdown)?;

                println!("Tunnel state: {tunnel_state:?}");
                break;
            }
        }

        let reconnected = loop {
            if shutdown_requested.load(Ordering::Relaxed) {
                tunnel_state = tunnel_state.transition(TunnelEvent::Shutdown)?;

                println!("Tunnel state: {tunnel_state:?}");
                return Ok(());
            }

            socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

            println!("Reauthenticating UDP peer {peer_address} as {role:?}...");

            match perform_authenticated_handshake(&socket, role, &identity, peer_public_key) {
                Ok(handshake) => break handshake,
                Err(error) => {
                    eprintln!(
                        "Reconnect handshake failed: {error}; retrying in {} seconds",
                        RECONNECT_DELAY.as_secs()
                    );
                    thread::sleep(RECONNECT_DELAY);
                }
            }
        };

        socket.set_read_timeout(Some(KEEPALIVE_INTERVAL))?;

        let (new_crypto_sender, new_crypto_receiver) = reconnected.session.into_split();
        set_outbound_session(&shared_crypto_sender, Some(new_crypto_sender))?;

        crypto_receiver = new_crypto_receiver;
        confirmation_cache = reconnected.confirmation_cache;
        tunnel_state = tunnel_state.transition(TunnelEvent::HandshakeSucceeded)?;

        println!("Tunnel state: {tunnel_state:?}");
        println!("Reauthenticated UDP peer {peer_address}");
    }

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
    socket: &UdpSocket,
    writer: &mut Writer,
    allowed_ips: &[Ipv4Cidr],
    mut receiver: CryptoReceiver,
    mut confirmation_cache: Option<ServerConfirmationCache>,
    outbound_sender: &SyncSender<OutboundMessage>,
    shutdown_requested: &AtomicBool,
) -> io::Result<ReceiveLoopExit> {
    let mut liveness = LivenessTracker::new(
        NonZeroU8::new(MAX_MISSED_KEEPALIVES)
            .expect("maximum missed keepalives must be greater than zero"),
    );

    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    loop {
        if shutdown_requested.load(Ordering::Relaxed) {
            return Ok(ReceiveLoopExit::Shutdown);
        }

        let received_length = match socket.recv(&mut buffer) {
            Ok(length) => length,
            Err(error)
                if error.kind() == io::ErrorKind::Interrupted
                    && shutdown_requested.load(Ordering::Relaxed) =>
            {
                return Ok(ReceiveLoopExit::Shutdown);
            }
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
                        println!("Peer missed the authenticated keepalive limit");
                        return Ok(ReceiveLoopExit::PeerTimedOut);
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
    shared_crypto_sender: SharedCryptoSender,
    outbound_receiver: OutboundReceiver<OutboundMessage>,
) -> io::Result<()> {
    loop {
        let message = outbound_receiver.recv().map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "outbound queue disconnected")
        })?;

        let (message_type, payload) = message.into_parts();

        let payload_length = payload.len();

        // Keep the lock through UDP send. Once the supervisor clears this
        // slot, no old-session frame can race with a new handshake datagram.
        let mut current_sender = shared_crypto_sender
            .lock()
            .map_err(|_| io::Error::other("outbound crypto session lock was poisoned"))?;

        let Some(crypto_sender) = current_sender.as_mut() else {
            eprintln!(
                "Dropping {message_type:?} payload_length={payload_length}: \
                 tunnel is reconnecting"
            );
            continue;
        };

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
    use super::{SharedCryptoSender, parse_role, set_outbound_session};
    use rust_vpn::protocol::MessageType;
    use rust_vpn::toy_crypto::{
        key_derivation::{SessionRole, derive_session_keys},
        session::CryptoSession,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn parses_client_and_server_roles() {
        assert_eq!(parse_role("client").unwrap(), SessionRole::Client);
        assert_eq!(parse_role("server").unwrap(), SessionRole::Server);
    }

    #[test]
    fn rejects_unknown_roles() {
        assert!(parse_role("peer").is_err());
    }

    #[test]
    fn replaces_an_expired_outbound_session() {
        let old_keys = derive_session_keys(b"old secret", b"old salt").unwrap();
        let (old_sender, _) = CryptoSession::new(41, SessionRole::Client, old_keys).into_split();
        let shared_sender: SharedCryptoSender = Arc::new(Mutex::new(Some(old_sender)));

        set_outbound_session(&shared_sender, None).unwrap();
        assert!(shared_sender.lock().unwrap().is_none());

        let new_keys = derive_session_keys(b"new secret", b"new salt").unwrap();
        let (new_sender, _) = CryptoSession::new(42, SessionRole::Client, new_keys).into_split();

        set_outbound_session(&shared_sender, Some(new_sender)).unwrap();

        let protected = shared_sender
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .protect(MessageType::Keepalive, Vec::new())
            .unwrap();

        assert_eq!(protected.session_id(), 42);
        assert_eq!(protected.counter(), 1);
    }
}
