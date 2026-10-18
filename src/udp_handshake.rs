use std::{error::Error, fmt, io, net::UdpSocket};

use crate::{
    authenticated_handshake::{AuthenticatedHandshakeError, ClientHandshake, ServerHandshake},
    handshake::{ClientAuth, ClientHello},
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

const MAX_HANDSHAKE_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStage {
    ClientHello,
    ServerHello,
    ClientAuth,
    HandshakeComplete,
}

impl fmt::Display for HandshakeStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientHello => formatter.write_str("ClientHello"),
            Self::ServerHello => formatter.write_str("ServerHello"),
            Self::ClientAuth => formatter.write_str("ClientAuth"),
            Self::HandshakeComplete => formatter.write_str("HandshakeComplete"),
        }
    }
}

#[derive(Debug)]
pub enum UdpHandshakeError {
    Io(io::Error),
    Timeout { waiting_for: HandshakeStage },
    Transport(HandshakeTransportError),
    Authentication(AuthenticatedHandshakeError),

    PartialDatagram { expected: usize, sent: usize },

    RandomSessionId(getrandom::Error),

    Protocol(ProtocolError),

    Session(CryptoSessionError),

    UnexpectedConfirmationType { received: MessageType },

    NonEmptyConfirmation { actual: usize },

    ConflictingClientHello,

    TooManyDuplicateClientHellos { maximum: usize },
}

impl fmt::Display for UdpHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "UDP handshake I/O failed: {error}"),
            Self::Timeout { waiting_for } => {
                write!(
                    formatter,
                    "UDP handshake timed out waiting for {waiting_for}"
                )
            }
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
            Self::ConflictingClientHello => {
                formatter.write_str("duplicate ClientHello changed the ephemeral public key")
            }
            Self::TooManyDuplicateClientHellos { maximum } => write!(
                formatter,
                "received more than {maximum} duplicate ClientHello messages"
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
            | Self::ConflictingClientHello
            | Self::TooManyDuplicateClientHellos { .. }
            | Self::Timeout { .. }
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

fn receive_datagram(
    socket: &UdpSocket,
    buffer: &mut [u8],
    waiting_for: HandshakeStage,
) -> Result<usize, UdpHandshakeError> {
    socket.recv(buffer).map_err(|error| match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            UdpHandshakeError::Timeout { waiting_for }
        }
        _ => UdpHandshakeError::Io(error),
    })
}

fn send_and_receive_with_retry(
    socket: &UdpSocket,
    request: &[u8],
    buffer: &mut [u8],
    waiting_for: HandshakeStage,
) -> Result<usize, UdpHandshakeError> {
    let mut attempts = 0;

    loop {
        attempts += 1;
        send_datagram(socket, request)?;

        match receive_datagram(socket, buffer, waiting_for) {
            Err(UdpHandshakeError::Timeout { .. }) if attempts < MAX_HANDSHAKE_ATTEMPTS => {
                // Retransmit the identical encoded request. Regenerating
                // ephemeral state would create a different transcript.
            }
            result => return result,
        }
    }
}

fn receive_client_auth_with_duplicate_handling(
    socket: &UdpSocket,
    buffer: &mut [u8],
    original_client_hello: ClientHello,
    cached_server_hello: &[u8],
    session_id: u32,
) -> Result<ClientAuth, UdpHandshakeError> {
    let maximum_duplicates = MAX_HANDSHAKE_ATTEMPTS - 1;
    let mut duplicate_count = 0;

    loop {
        let received_length = receive_datagram(socket, buffer, HandshakeStage::ClientAuth)?;
        let datagram = &buffer[..received_length];

        match decode_client_auth(datagram, session_id) {
            Ok(client_auth) => return Ok(client_auth),
            Err(HandshakeTransportError::UnexpectedMessageType {
                received: MessageType::ClientHello,
                ..
            }) => {
                let duplicate = decode_client_hello(datagram)?;

                if duplicate != original_client_hello {
                    return Err(UdpHandshakeError::ConflictingClientHello);
                }

                if duplicate_count == maximum_duplicates {
                    return Err(UdpHandshakeError::TooManyDuplicateClientHellos {
                        maximum: maximum_duplicates,
                    });
                }

                duplicate_count += 1;
                send_datagram(socket, cached_server_hello)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
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

    // 2. Encode ClientHello once so every retry uses the same ephemeral key
    // and therefore the same handshake transcript.
    let client_hello_bytes = encode_client_hello(client_hello)?;
    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    // 3. Retransmit ClientHello after a timeout while waiting for ServerHello.
    let received_length = send_and_receive_with_retry(
        socket,
        &client_hello_bytes,
        &mut buffer,
        HandshakeStage::ServerHello,
    )?;

    let (session_id, server_hello) = decode_server_hello(&buffer[..received_length])?;

    // 4. Verify the server, derive keys, and sign ClientAuth.
    let (client_auth, result) = client_state.complete(
        session_id,
        server_hello,
        client_identity,
        expected_server_identity,
    )?;

    // 5. Retransmit the identical ClientAuth after a timeout while waiting for
    // the server's protected confirmation.
    let client_auth_bytes = encode_client_auth(session_id, client_auth)?;
    let received_length = send_and_receive_with_retry(
        socket,
        &client_auth_bytes,
        &mut buffer,
        HandshakeStage::HandshakeComplete,
    )?;

    // 6. Turn the derived keys into a stateful session.
    let (session_id, session_keys) = result.into_parts();

    let mut session = CryptoSession::new(session_id, SessionRole::Client, session_keys);

    // 7. Authenticate and decrypt before checking the confirmation type and
    // payload. Success also records server counter 1 in the replay window.
    accept_confirmation(&mut session, &buffer[..received_length])?;

    // Return the same session whose replay window contains counter 1.
    Ok(session)
}

pub fn perform_server_handshake(
    socket: &UdpSocket,
    server_identity: &IdentityKeyPair,
    expected_client_identity: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
) -> Result<(CryptoSession, ServerConfirmationCache), UdpHandshakeError> {
    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    // 1. Receive and validate ClientHello.
    let received_length = receive_datagram(socket, &mut buffer, HandshakeStage::ClientHello)?;

    let client_hello = decode_client_hello(&buffer[..received_length])?;

    // 2. Choose a fresh session ID.
    let session_id = generate_session_id()?;

    // 3. Create ServerHello and pending server state.
    let (server_state, server_hello) =
        ServerHandshake::respond(client_hello, session_id, server_identity)?;

    // 4. Send ServerHello.
    let server_hello_bytes = encode_server_hello(session_id, server_hello)?;

    send_datagram(socket, &server_hello_bytes)?;

    // 5. Receive ClientAuth. If the cached ServerHello was lost, an identical
    // repeated ClientHello causes the same ServerHello bytes to be resent.
    let client_auth = receive_client_auth_with_duplicate_handling(
        socket,
        &mut buffer,
        client_hello,
        &server_hello_bytes,
        session_id,
    )?;

    let client_auth_bytes = encode_client_auth(session_id, client_auth)?;

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

    let confirmation_bytes = confirmation.encode();

    // 10. Send the protected confirmation.
    send_datagram(socket, &confirmation_bytes)?;

    let retry_cache = ServerConfirmationCache::new(client_auth_bytes, confirmation_bytes);

    Ok((session, retry_cache))
}

pub struct ServerConfirmationCache {
    expected_client_auth: Vec<u8>,
    confirmation: Vec<u8>,
    remaining_responses: usize,
}

impl ServerConfirmationCache {
    fn new(expected_client_auth: Vec<u8>, confirmation: Vec<u8>) -> Self {
        Self {
            expected_client_auth,
            confirmation,
            remaining_responses: MAX_HANDSHAKE_ATTEMPTS - 1,
        }
    }

    pub fn response_for(&mut self, datagram: &[u8]) -> Option<&[u8]> {
        if self.remaining_responses == 0 {
            return None;
        }

        if datagram != self.expected_client_auth {
            return None;
        }

        self.remaining_responses -= 1;

        Some(&self.confirmation)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HandshakeStage, MAX_HANDSHAKE_ATTEMPTS, ServerConfirmationCache, UdpHandshakeError,
        accept_confirmation, perform_client_handshake, perform_server_handshake,
        receive_client_auth_with_duplicate_handling, receive_datagram, send_and_receive_with_retry,
    };
    use crate::{
        handshake::{ClientAuth, ClientHello},
        handshake_transport::{encode_client_auth, encode_client_hello},
        identity::{IDENTITY_SIGNATURE_LENGTH, IdentityKeyPair},
        protocol::{Frame, MessageType},
        toy_crypto::{
            key_derivation::{SessionRole, derive_session_keys},
            session::CryptoSession,
        },
    };
    use std::{net::UdpSocket, thread, time::Duration};

    #[test]
    fn timeout_error_names_the_waiting_handshake_stage() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(1)))
            .unwrap();
        let mut buffer = [0_u8; 1];

        let error =
            receive_datagram(&socket, &mut buffer, HandshakeStage::ServerHello).unwrap_err();

        assert!(matches!(
            error,
            UdpHandshakeError::Timeout {
                waiting_for: HandshakeStage::ServerHello
            }
        ));
        assert_eq!(
            error.to_string(),
            "UDP handshake timed out waiting for ServerHello"
        );
    }

    #[test]
    fn retry_resends_identical_bytes_after_the_first_datagram_is_lost() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();

        server_socket
            .connect(client_socket.local_addr().unwrap())
            .unwrap();
        client_socket
            .connect(server_socket.local_addr().unwrap())
            .unwrap();

        client_socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        server_socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let server_thread = thread::spawn(move || {
            let mut first = [0_u8; 32];
            let first_length = server_socket.recv(&mut first).unwrap();

            // Simulate loss by deliberately sending no response.
            let mut second = [0_u8; 32];
            let second_length = server_socket.recv(&mut second).unwrap();

            assert_eq!(&first[..first_length], &second[..second_length]);
            server_socket.send(b"ServerHello").unwrap();
        });

        let mut response = [0_u8; 32];
        let response_length = send_and_receive_with_retry(
            &client_socket,
            b"ClientHello",
            &mut response,
            HandshakeStage::ServerHello,
        )
        .unwrap();

        assert_eq!(&response[..response_length], b"ServerHello");
        server_thread.join().unwrap();
    }

    #[test]
    fn server_resends_cached_hello_for_an_identical_client_hello() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();

        server_socket
            .connect(client_socket.local_addr().unwrap())
            .unwrap();
        client_socket
            .connect(server_socket.local_addr().unwrap())
            .unwrap();

        let timeout = Some(Duration::from_secs(1));
        server_socket.set_read_timeout(timeout).unwrap();
        client_socket.set_read_timeout(timeout).unwrap();

        let client_hello = ClientHello::new([0x11; 32]);
        let client_hello_bytes = encode_client_hello(client_hello).unwrap();
        let client_auth = ClientAuth::new([0x22; IDENTITY_SIGNATURE_LENGTH]);
        let client_auth_bytes = encode_client_auth(42, client_auth).unwrap();
        let cached_server_hello = b"cached ServerHello".to_vec();
        let expected_server_hello = cached_server_hello.clone();

        let client_thread = thread::spawn(move || {
            client_socket.send(&client_hello_bytes).unwrap();

            let mut response = [0_u8; 32];
            let response_length = client_socket.recv(&mut response).unwrap();
            assert_eq!(&response[..response_length], expected_server_hello);

            client_socket.send(&client_auth_bytes).unwrap();
        });

        let mut buffer = [0_u8; 2048];
        let received_auth = receive_client_auth_with_duplicate_handling(
            &server_socket,
            &mut buffer,
            client_hello,
            &cached_server_hello,
            42,
        )
        .unwrap();

        assert_eq!(received_auth, client_auth);
        client_thread.join().unwrap();
    }

    #[test]
    fn server_rejects_a_changed_duplicate_client_hello() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();

        server_socket
            .connect(client_socket.local_addr().unwrap())
            .unwrap();
        client_socket
            .connect(server_socket.local_addr().unwrap())
            .unwrap();

        let original = ClientHello::new([0x11; 32]);
        let changed = encode_client_hello(ClientHello::new([0x22; 32])).unwrap();
        client_socket.send(&changed).unwrap();

        let mut buffer = [0_u8; 2048];
        let error = receive_client_auth_with_duplicate_handling(
            &server_socket,
            &mut buffer,
            original,
            b"cached ServerHello",
            42,
        )
        .unwrap_err();

        assert!(matches!(error, UdpHandshakeError::ConflictingClientHello));
    }

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
        let (mut server_session, _) = server_thread.join().unwrap();

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

    #[test]
    fn confirmation_cache_only_answers_matching_client_auth() {
        let expected_client_auth = b"expected ClientAuth".to_vec();
        let confirmation = b"protected HandshakeComplete".to_vec();
        let mut cache =
            ServerConfirmationCache::new(expected_client_auth.clone(), confirmation.clone());

        assert_eq!(cache.response_for(b"changed ClientAuth"), None);
        assert_eq!(
            cache.response_for(&expected_client_auth),
            Some(confirmation.as_slice())
        );
    }

    #[test]
    fn confirmation_cache_enforces_the_retry_limit() {
        let expected_client_auth = b"expected ClientAuth".to_vec();
        let confirmation = b"protected HandshakeComplete".to_vec();
        let mut cache =
            ServerConfirmationCache::new(expected_client_auth.clone(), confirmation.clone());

        for _ in 0..MAX_HANDSHAKE_ATTEMPTS - 1 {
            assert_eq!(
                cache.response_for(&expected_client_auth),
                Some(confirmation.as_slice())
            );
        }

        assert_eq!(cache.response_for(&expected_client_auth), None);
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
