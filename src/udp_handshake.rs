use std::{error::Error, fmt, io, net::UdpSocket};

use crate::{
    authenticated_handshake::{
        AuthenticatedHandshakeError, ClientHandshake, HandshakeResult, ServerHandshake,
    },
    handshake_transport::{
        HandshakeTransportError, decode_client_auth, decode_client_hello, decode_server_hello,
        encode_client_auth, encode_client_hello, encode_server_hello,
    },
    identity::{IDENTITY_PUBLIC_KEY_LENGTH, IdentityKeyPair},
    transport::RECEIVE_BUFFER_SIZE,
};

#[derive(Debug)]
pub enum UdpHandshakeError {
    Io(io::Error),
    Transport(HandshakeTransportError),
    Authentication(AuthenticatedHandshakeError),

    PartialDatagram { expected: usize, sent: usize },

    RandomSessionId(getrandom::Error),
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
            Self::PartialDatagram { .. } => None,
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

pub fn perform_client_handshake(
    socket: &UdpSocket,
    client_identity: &IdentityKeyPair,
    expected_server_identity: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
) -> Result<HandshakeResult, UdpHandshakeError> {
    let (client_state, client_hello) = ClientHandshake::start();

    let client_hello_bytes = encode_client_hello(client_hello)?;

    send_datagram(socket, &client_hello_bytes)?;

    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    let received_length = socket.recv(&mut buffer)?;

    let (session_id, server_hello) = decode_server_hello(&buffer[..received_length])?;

    let (client_auth, result) = client_state.complete(
        session_id,
        server_hello,
        client_identity,
        expected_server_identity,
    )?;

    let client_auth_bytes = encode_client_auth(session_id, client_auth)?;

    send_datagram(socket, &client_auth_bytes)?;

    Ok(result)
}

pub fn perform_server_handshake(
    socket: &UdpSocket,
    server_identity: &IdentityKeyPair,
    expected_client_identity: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
) -> Result<HandshakeResult, UdpHandshakeError> {
    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    let received_length = socket.recv(&mut buffer)?;

    let client_hello = decode_client_hello(&buffer[..received_length])?;

    let session_id = generate_session_id()?;

    let (server_state, server_hello) =
        ServerHandshake::respond(client_hello, session_id, server_identity)?;

    let server_hello_bytes = encode_server_hello(session_id, server_hello)?;

    send_datagram(socket, &server_hello_bytes)?;

    let received_length = socket.recv(&mut buffer)?;

    let client_auth = decode_client_auth(&buffer[..received_length], session_id)?;

    server_state
        .complete(client_auth, expected_client_identity)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{perform_client_handshake, perform_server_handshake};
    use crate::identity::IdentityKeyPair;
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

        let client_result =
            perform_client_handshake(&client_socket, &client_identity, server_public_key).unwrap();
        let server_result = server_thread.join().unwrap();

        assert_ne!(client_result.session_id(), 0);
        assert_eq!(client_result.session_id(), server_result.session_id());
        assert_eq!(
            client_result.session_keys().client_to_server(),
            server_result.session_keys().client_to_server()
        );
        assert_eq!(
            client_result.session_keys().server_to_client(),
            server_result.session_keys().server_to_client()
        );
    }
}
