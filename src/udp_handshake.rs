use std::{error::Error, fmt, io, net::UdpSocket};

use crate::{
    authenticated_handshake::{AuthenticatedHandshakeError, ClientHandshake, ServerHandshake},
    handshake_transport::{
        HandshakeTransportError, decode_client_auth, decode_client_hello, decode_server_hello,
        encode_client_auth, encode_client_hello, encode_server_hello,
    },
    identity::{IDENTITY_PUBLIC_KEY_LENGTH, IdentityKeyPair},
    protocol::{Frame, MessageType, ProtocolError},
    toy_crypto::{
        key_derivation::SessionRole,
        session::{CryptoSession, CryptoSessionError},
    },
    transport::RECEIVE_BUFFER_SIZE,
};

#[derive(Debug)]
pub enum UdpHandshakeError {
    Io(io::Error),
    Transport(HandshakeTransportError),
    Authentication(AuthenticatedHandshakeError),

    PartialDatagram { expected: usize, sent: usize },

    RandomSessionId(getrandom::Error),

    Protocol(ProtocolError),

    Session(CryptoSessionError),

    UnexpectedConfirmationType { received: MessageType },

    NonEmptyConfirmation { actual: usize },
}

impl fmt::Display for UdpHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "UDP handshake I/O failed: {error}"),
            Self::Transport(error) => write!(formatter, "UDP handshake frame failed: {error}"),
            Self::Authentication(error) => {
                write!(formatter, "UDP peer authentication failed: {error}")
            }
            Self::PartialDatagram { expected, sent } => write!(
                formatter,
                "UDP handshake attempted to send {expected} bytes, but sent {sent}"
            ),
            Self::RandomSessionId(error) => {
                write!(formatter, "failed to generate a session ID: {error}")
            }
            Self::Protocol(error) => {
                write!(formatter, "invalid confirmation frame: {error}")
            }

            Self::Session(error) => {
                write!(formatter, "protected confirmation failed: {error}")
            }

            Self::UnexpectedConfirmationType { received } => write!(
                formatter,
                "expected HandshakeComplete, received {received:?}"
            ),

            Self::NonEmptyConfirmation { actual } => write!(
                formatter,
                "HandshakeComplete payload must be empty, received {actual} bytes"
            ),
        }
    }
}

impl Error for UdpHandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Authentication(error) => Some(error),
            Self::RandomSessionId(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Session(error) => Some(error),

            Self::UnexpectedConfirmationType { .. }
            | Self::NonEmptyConfirmation { .. }
            | Self::PartialDatagram { .. } => None,
        }
    }
}

impl From<io::Error> for UdpHandshakeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<HandshakeTransportError> for UdpHandshakeError {
    fn from(error: HandshakeTransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<AuthenticatedHandshakeError> for UdpHandshakeError {
    fn from(error: AuthenticatedHandshakeError) -> Self {
        Self::Authentication(error)
    }
}

impl From<getrandom::Error> for UdpHandshakeError {
    fn from(error: getrandom::Error) -> Self {
        Self::RandomSessionId(error)
    }
}
impl From<ProtocolError> for UdpHandshakeError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<CryptoSessionError> for UdpHandshakeError {
    fn from(error: CryptoSessionError) -> Self {
        Self::Session(error)
    }
}

fn generate_session_id() -> Result<u32, getrandom::Error> {
    loop {
        let mut bytes = [0_u8; 4];

        getrandom::fill(&mut bytes)?;

        let session_id = u32::from_be_bytes(bytes);

        if session_id != 0 {
            return Ok(session_id);
        }
    }
}

fn send_datagram(socket: &UdpSocket, bytes: &[u8]) -> Result<(), UdpHandshakeError> {
    let sent = socket.send(bytes)?;

    if sent != bytes.len() {
        return Err(UdpHandshakeError::PartialDatagram {
            expected: bytes.len(),
            sent,
        });
    }

    Ok(())
}

fn accept_confirmation(session: &mut CryptoSession, bytes: &[u8]) -> Result<(), UdpHandshakeError> {
    // Decoding validates only the generic frame structure. Do not trust any
    // decoded field until the session authenticates the complete frame.
    let protected_confirmation = Frame::decode(bytes)?;
    let confirmation = session.unprotect(&protected_confirmation)?;

    if confirmation.message_type() != MessageType::HandshakeComplete {
        return Err(UdpHandshakeError::UnexpectedConfirmationType {
            received: confirmation.message_type(),
        });
    }

    if !confirmation.payload().is_empty() {
        return Err(UdpHandshakeError::NonEmptyConfirmation {
            actual: confirmation.payload().len(),
        });
    }

    Ok(())
}

pub fn perform_client_handshake(
    socket: &UdpSocket,
    client_identity: &IdentityKeyPair,
    expected_server_identity: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
) -> Result<CryptoSession, UdpHandshakeError> {
    // 1. Create the client's ephemeral X25519 state.
    let (client_state, client_hello) = ClientHandshake::start();

    // 2. Send ClientHello.
    let client_hello_bytes = encode_client_hello(client_hello)?;

    send_datagram(socket, &client_hello_bytes)?;

    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    // 3. Receive ServerHello.
    let received_length = socket.recv(&mut buffer)?;

    let (session_id, server_hello) = decode_server_hello(&buffer[..received_length])?;

    // 4. Verify the server, derive keys, and sign ClientAuth.
    let (client_auth, result) = client_state.complete(
        session_id,
        server_hello,
        client_identity,
        expected_server_identity,
    )?;

    // 5. Send ClientAuth.
    let client_auth_bytes = encode_client_auth(session_id, client_auth)?;

    send_datagram(socket, &client_auth_bytes)?;

    // 6. Turn the derived keys into a stateful session.
    let (session_id, session_keys) = result.into_parts();

    let mut session = CryptoSession::new(session_id, SessionRole::Client, session_keys);

    // 7. Wait for the server's encrypted confirmation.
    let received_length = socket.recv(&mut buffer)?;

    // 8. Authenticate and decrypt before checking the confirmation type and
    // payload. Success also records server counter 1 in the replay window.
    accept_confirmation(&mut session, &buffer[..received_length])?;

    // Return the same session whose replay window contains counter 1.
    Ok(session)
}

pub fn perform_server_handshake(
    socket: &UdpSocket,
    server_identity: &IdentityKeyPair,
    expected_client_identity: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
) -> Result<CryptoSession, UdpHandshakeError> {
    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    // 1. Receive and validate ClientHello.
    let received_length = socket.recv(&mut buffer)?;

    let client_hello = decode_client_hello(&buffer[..received_length])?;

    // 2. Choose a fresh session ID.
    let session_id = generate_session_id()?;

    // 3. Create ServerHello and pending server state.
    let (server_state, server_hello) =
        ServerHandshake::respond(client_hello, session_id, server_identity)?;

    // 4. Send ServerHello.
    let server_hello_bytes = encode_server_hello(session_id, server_hello)?;

    send_datagram(socket, &server_hello_bytes)?;

    // 5. Receive ClientAuth.
    let received_length = socket.recv(&mut buffer)?;

    let client_auth = decode_client_auth(&buffer[..received_length], session_id)?;

    // 6. Verify the client identity.
    //
    // No CryptoSession is created unless this succeeds.
    let result = server_state.complete(client_auth, expected_client_identity)?;

    // 7. Extract the authenticated session ID and keys.
    let (session_id, session_keys) = result.into_parts();

    // 8. Create the stateful cryptographic session.
    let mut session = CryptoSession::new(session_id, SessionRole::Server, session_keys);

    // 9. Create an encrypted empty confirmation.
    //
    // This consumes server send counter 1.
    let confirmation = session.protect(MessageType::HandshakeComplete, Vec::new())?;

    // 10. Send the protected confirmation.
    send_datagram(socket, &confirmation.encode())?;

    // Return the same session whose counter is now 2.
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::{
        UdpHandshakeError, accept_confirmation, perform_client_handshake, perform_server_handshake,
    };
    use crate::{
        identity::IdentityKeyPair,
        protocol::{Frame, MessageType},
        toy_crypto::{
            key_derivation::{SessionRole, derive_session_keys},
            session::CryptoSession,
        },
    };
    use std::{net::UdpSocket, thread, time::Duration};

    #[test]
    fn connected_udp_peers_complete_an_authenticated_handshake() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();

        server_socket
            .connect(client_socket.local_addr().unwrap())
            .unwrap();
        client_socket
            .connect(server_socket.local_addr().unwrap())
            .unwrap();

        let timeout = Some(Duration::from_secs(2));
        server_socket.set_read_timeout(timeout).unwrap();
        client_socket.set_read_timeout(timeout).unwrap();

        let client_identity = IdentityKeyPair::generate().unwrap();
        let server_identity = IdentityKeyPair::generate().unwrap();
        let client_public_key = client_identity.public_key();
        let server_public_key = server_identity.public_key();

        let server_thread = thread::spawn(move || {
            perform_server_handshake(&server_socket, &server_identity, client_public_key).unwrap()
        });

        let mut client_session =
            perform_client_handshake(&client_socket, &client_identity, server_public_key).unwrap();
        let mut server_session = server_thread.join().unwrap();

        let client_frame = client_session
            .protect(MessageType::Data, b"client packet".to_vec())
            .unwrap();

        assert_eq!(client_frame.counter(), 1);

        let opened_by_server = server_session.unprotect(&client_frame).unwrap();

        assert_eq!(opened_by_server.message_type(), MessageType::Data);
        assert_eq!(opened_by_server.payload(), b"client packet");

        // Counter 1 carried HandshakeComplete, so the server's first data
        // frame must use counter 2.
        let server_frame = server_session
            .protect(MessageType::Data, b"server packet".to_vec())
            .unwrap();

        assert_eq!(server_frame.counter(), 2);

        let opened_by_client = client_session.unprotect(&server_frame).unwrap();

        assert_eq!(opened_by_client.message_type(), MessageType::Data);
        assert_eq!(opened_by_client.payload(), b"server packet");
    }

    fn confirmation_sessions() -> (CryptoSession, CryptoSession) {
        let shared_secret = b"confirmation-test-secret";
        let context = b"confirmation-test-context";
        let client_keys = derive_session_keys(shared_secret, context).unwrap();
        let server_keys = derive_session_keys(shared_secret, context).unwrap();

        (
            CryptoSession::new(42, SessionRole::Client, client_keys),
            CryptoSession::new(42, SessionRole::Server, server_keys),
        )
    }

    #[test]
    fn rejects_a_plaintext_confirmation() {
        let (mut client, _) = confirmation_sessions();
        let plaintext = Frame::new(MessageType::HandshakeComplete, 42, 1, Vec::new()).unwrap();

        let error = accept_confirmation(&mut client, &plaintext.encode()).unwrap_err();

        assert!(matches!(error, UdpHandshakeError::Session(_)));
    }

    #[test]
    fn rejects_a_confirmation_protected_with_the_wrong_key() {
        let (mut client, _) = confirmation_sessions();
        let wrong_keys = derive_session_keys(b"wrong-secret", b"wrong-context").unwrap();
        let mut wrong_server = CryptoSession::new(42, SessionRole::Server, wrong_keys);
        let confirmation = wrong_server
            .protect(MessageType::HandshakeComplete, Vec::new())
            .unwrap();

        let error = accept_confirmation(&mut client, &confirmation.encode()).unwrap_err();

        assert!(matches!(error, UdpHandshakeError::Session(_)));
    }

    #[test]
    fn rejects_protected_data_when_confirmation_is_expected() {
        let (mut client, mut server) = confirmation_sessions();
        let data = server.protect(MessageType::Data, Vec::new()).unwrap();

        let error = accept_confirmation(&mut client, &data.encode()).unwrap_err();

        assert!(matches!(
            error,
            UdpHandshakeError::UnexpectedConfirmationType {
                received: MessageType::Data
            }
        ));
    }

    #[test]
    fn rejects_a_confirmation_with_a_payload() {
        let (mut client, mut server) = confirmation_sessions();
        let confirmation = server
            .protect(MessageType::HandshakeComplete, b"unexpected".to_vec())
            .unwrap();

        let error = accept_confirmation(&mut client, &confirmation.encode()).unwrap_err();

        assert!(matches!(
            error,
            UdpHandshakeError::NonEmptyConfirmation { actual: 10 }
        ));
    }

    #[test]
    fn rejects_a_replayed_confirmation() {
        let (mut client, mut server) = confirmation_sessions();
        let confirmation = server
            .protect(MessageType::HandshakeComplete, Vec::new())
            .unwrap();
        let encoded = confirmation.encode();

        accept_confirmation(&mut client, &encoded).unwrap();
        let error = accept_confirmation(&mut client, &encoded).unwrap_err();

        assert!(matches!(error, UdpHandshakeError::Session(_)));
    }
}
