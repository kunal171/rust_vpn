use std::{error::Error, fmt};

use crate::{
    handshake::{ClientAuth, ClientHello, HandshakeError, ServerHello},
    protocol::{Frame, MessageType, ProtocolError},
};

pub const HANDSHAKE_COUNTER: u64 = 0;
pub const UNASSIGNED_SESSION_ID: u32 = 0;

#[derive(Debug)]
pub enum HandshakeTransportError {
    Protocol(ProtocolError),
    Handshake(HandshakeError),

    UnexpectedMessageType {
        expected: MessageType,
        received: MessageType,
    },

    UnexpectedSessionId {
        expected: u32,
        received: u32,
    },

    UnassignedSessionId,

    UnexpectedCounter {
        received: u64,
    },

}

impl fmt::Display for HandshakeTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "invalid handshake frame: {error}"),
            Self::Handshake(error) => write!(formatter, "invalid handshake payload: {error}"),
            Self::UnexpectedMessageType { expected, received } => write!(
                formatter,
                "expected {expected:?} handshake message, received {received:?}"
            ),
            Self::UnexpectedSessionId { expected, received } => write!(
                formatter,
                "expected handshake session ID {expected}, received {received}"
            ),
            Self::UnassignedSessionId => {
                write!(formatter, "server-assigned session ID must not be zero")
            }
            Self::UnexpectedCounter { received } => write!(
                formatter,
                "handshake counter must be {HANDSHAKE_COUNTER}, received {received}"
            ),
        }
    }
}

impl Error for HandshakeTransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Handshake(error) => Some(error),
            Self::UnexpectedMessageType { .. }
            | Self::UnexpectedSessionId { .. }
            | Self::UnassignedSessionId
            | Self::UnexpectedCounter { .. } => None,
        }
    }
}

impl From<ProtocolError> for HandshakeTransportError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<HandshakeError> for HandshakeTransportError {
    fn from(error: HandshakeError) -> Self {
        Self::Handshake(error)
    }
}

fn validate_type_and_counter(
    frame: &Frame,
    expected_type: MessageType,
) -> Result<(), HandshakeTransportError> {
    if frame.message_type() != expected_type {
        return Err(HandshakeTransportError::UnexpectedMessageType {
            expected: expected_type,
            received: frame.message_type(),
        });
    }

    if frame.counter() != HANDSHAKE_COUNTER {
        return Err(HandshakeTransportError::UnexpectedCounter {
            received: frame.counter(),
        });
    }

    Ok(())
}

pub fn encode_client_hello(hello: ClientHello) -> Result<Vec<u8>, HandshakeTransportError> {
    let frame = Frame::new(
        MessageType::ClientHello,
        UNASSIGNED_SESSION_ID,
        HANDSHAKE_COUNTER,
        hello.encode().to_vec(),
    )?;

    Ok(frame.encode())
}

pub fn decode_client_hello(datagram: &[u8]) -> Result<ClientHello, HandshakeTransportError> {
    let frame = Frame::decode(datagram)?;

    validate_type_and_counter(&frame, MessageType::ClientHello)?;

    if frame.session_id() != UNASSIGNED_SESSION_ID {
        return Err(HandshakeTransportError::UnexpectedSessionId {
            expected: UNASSIGNED_SESSION_ID,
            received: frame.session_id(),
        });
    }

    Ok(ClientHello::decode(frame.payload())?)
}

pub fn encode_server_hello(
    session_id: u32,
    hello: ServerHello,
) -> Result<Vec<u8>, HandshakeTransportError> {
    if session_id == UNASSIGNED_SESSION_ID {
        return Err(HandshakeTransportError::UnassignedSessionId);
    }

    let frame = Frame::new(
        MessageType::ServerHello,
        session_id,
        HANDSHAKE_COUNTER,
        hello.encode().to_vec(),
    )?;

    Ok(frame.encode())
}

pub fn decode_server_hello(datagram: &[u8]) -> Result<(u32, ServerHello), HandshakeTransportError> {
    let frame = Frame::decode(datagram)?;

    validate_type_and_counter(&frame, MessageType::ServerHello)?;

    if frame.session_id() == UNASSIGNED_SESSION_ID {
        return Err(HandshakeTransportError::UnassignedSessionId);
    }

    let hello = ServerHello::decode(frame.payload())?;

    Ok((frame.session_id(), hello))
}

pub fn encode_client_auth(
    session_id: u32,
    auth: ClientAuth,
) -> Result<Vec<u8>, HandshakeTransportError> {
    if session_id == UNASSIGNED_SESSION_ID {
        return Err(HandshakeTransportError::UnassignedSessionId);
    }

    let frame = Frame::new(
        MessageType::ClientAuth,
        session_id,
        HANDSHAKE_COUNTER,
        auth.encode().to_vec(),
    )?;

    Ok(frame.encode())
}

pub fn decode_client_auth(
    datagram: &[u8],
    expected_session_id: u32,
) -> Result<ClientAuth, HandshakeTransportError> {
    let frame = Frame::decode(datagram)?;

    validate_type_and_counter(&frame, MessageType::ClientAuth)?;

    if frame.session_id() != expected_session_id {
        return Err(HandshakeTransportError::UnexpectedSessionId {
            expected: expected_session_id,
            received: frame.session_id(),
        });
    }

    Ok(ClientAuth::decode(frame.payload())?)
}

#[cfg(test)]
mod tests {
    use super::{
        HANDSHAKE_COUNTER, HandshakeTransportError, UNASSIGNED_SESSION_ID, decode_client_auth,
        decode_client_hello, decode_server_hello, encode_client_auth, encode_client_hello,
        encode_server_hello,
    };
    use crate::{
        handshake::{
            CLIENT_AUTH_LENGTH, CLIENT_HELLO_LENGTH, ClientAuth, ClientHello, HandshakeError,
            SERVER_HELLO_LENGTH, ServerHello,
        },
        identity::IDENTITY_SIGNATURE_LENGTH,
        key_exchange::PUBLIC_KEY_LENGTH,
        protocol::{Frame, HEADER_SIZE, MessageType, ProtocolError},
    };

    const SESSION_ID: u32 = 0x0102_0304;

    fn frame_bytes(
        message_type: MessageType,
        session_id: u32,
        counter: u64,
        payload: Vec<u8>,
    ) -> Vec<u8> {
        Frame::new(message_type, session_id, counter, payload)
            .unwrap()
            .encode()
    }

    #[test]
    fn all_handshake_messages_round_trip_through_frames() {
        let client_hello = ClientHello::new([0x11; PUBLIC_KEY_LENGTH]);
        let decoded_client_hello =
            decode_client_hello(&encode_client_hello(client_hello).unwrap()).unwrap();

        assert_eq!(decoded_client_hello, client_hello);

        let server_hello =
            ServerHello::new([0x22; PUBLIC_KEY_LENGTH], [0x33; IDENTITY_SIGNATURE_LENGTH]);
        let (decoded_session_id, decoded_server_hello) =
            decode_server_hello(&encode_server_hello(SESSION_ID, server_hello).unwrap()).unwrap();

        assert_eq!(decoded_session_id, SESSION_ID);
        assert_eq!(decoded_server_hello, server_hello);

        let client_auth = ClientAuth::new([0x44; IDENTITY_SIGNATURE_LENGTH]);
        let decoded_client_auth = decode_client_auth(
            &encode_client_auth(SESSION_ID, client_auth).unwrap(),
            SESSION_ID,
        )
        .unwrap();

        assert_eq!(decoded_client_auth, client_auth);
    }

    #[test]
    fn client_hello_rejects_a_nonzero_session_id() {
        let bytes = frame_bytes(
            MessageType::ClientHello,
            SESSION_ID,
            HANDSHAKE_COUNTER,
            ClientHello::new([0x11; PUBLIC_KEY_LENGTH])
                .encode()
                .to_vec(),
        );

        assert!(matches!(
            decode_client_hello(&bytes),
            Err(HandshakeTransportError::UnexpectedSessionId {
                expected: UNASSIGNED_SESSION_ID,
                received: SESSION_ID,
            })
        ));
    }

    #[test]
    fn server_hello_rejects_an_unassigned_session_id() {
        let hello = ServerHello::new([0x22; PUBLIC_KEY_LENGTH], [0x33; IDENTITY_SIGNATURE_LENGTH]);

        assert!(matches!(
            encode_server_hello(UNASSIGNED_SESSION_ID, hello),
            Err(HandshakeTransportError::UnassignedSessionId)
        ));

        let bytes = frame_bytes(
            MessageType::ServerHello,
            UNASSIGNED_SESSION_ID,
            HANDSHAKE_COUNTER,
            hello.encode().to_vec(),
        );

        assert!(matches!(
            decode_server_hello(&bytes),
            Err(HandshakeTransportError::UnassignedSessionId)
        ));
    }

    #[test]
    fn client_auth_rejects_the_wrong_session_id() {
        let bytes = encode_client_auth(
            SESSION_ID,
            ClientAuth::new([0x44; IDENTITY_SIGNATURE_LENGTH]),
        )
        .unwrap();

        assert!(matches!(
            decode_client_auth(&bytes, SESSION_ID + 1),
            Err(HandshakeTransportError::UnexpectedSessionId {
                expected,
                received: SESSION_ID,
            }) if expected == SESSION_ID + 1
        ));
    }

    #[test]
    fn every_decoder_rejects_a_nonzero_handshake_counter() {
        let client_hello = frame_bytes(
            MessageType::ClientHello,
            UNASSIGNED_SESSION_ID,
            1,
            ClientHello::new([0x11; PUBLIC_KEY_LENGTH])
                .encode()
                .to_vec(),
        );
        let server_hello = frame_bytes(
            MessageType::ServerHello,
            SESSION_ID,
            2,
            ServerHello::new([0x22; PUBLIC_KEY_LENGTH], [0x33; IDENTITY_SIGNATURE_LENGTH])
                .encode()
                .to_vec(),
        );
        let client_auth = frame_bytes(
            MessageType::ClientAuth,
            SESSION_ID,
            3,
            ClientAuth::new([0x44; IDENTITY_SIGNATURE_LENGTH])
                .encode()
                .to_vec(),
        );

        assert!(matches!(
            decode_client_hello(&client_hello),
            Err(HandshakeTransportError::UnexpectedCounter { received: 1 })
        ));
        assert!(matches!(
            decode_server_hello(&server_hello),
            Err(HandshakeTransportError::UnexpectedCounter { received: 2 })
        ));
        assert!(matches!(
            decode_client_auth(&client_auth, SESSION_ID),
            Err(HandshakeTransportError::UnexpectedCounter { received: 3 })
        ));
    }

    #[test]
    fn every_decoder_rejects_the_wrong_message_type() {
        let client_hello = frame_bytes(
            MessageType::ServerHello,
            UNASSIGNED_SESSION_ID,
            HANDSHAKE_COUNTER,
            ClientHello::new([0x11; PUBLIC_KEY_LENGTH])
                .encode()
                .to_vec(),
        );
        let server_hello = frame_bytes(
            MessageType::ClientAuth,
            SESSION_ID,
            HANDSHAKE_COUNTER,
            ServerHello::new([0x22; PUBLIC_KEY_LENGTH], [0x33; IDENTITY_SIGNATURE_LENGTH])
                .encode()
                .to_vec(),
        );
        let client_auth = frame_bytes(
            MessageType::ClientHello,
            SESSION_ID,
            HANDSHAKE_COUNTER,
            ClientAuth::new([0x44; IDENTITY_SIGNATURE_LENGTH])
                .encode()
                .to_vec(),
        );

        assert!(matches!(
            decode_client_hello(&client_hello),
            Err(HandshakeTransportError::UnexpectedMessageType {
                expected: MessageType::ClientHello,
                received: MessageType::ServerHello,
            })
        ));
        assert!(matches!(
            decode_server_hello(&server_hello),
            Err(HandshakeTransportError::UnexpectedMessageType {
                expected: MessageType::ServerHello,
                received: MessageType::ClientAuth,
            })
        ));
        assert!(matches!(
            decode_client_auth(&client_auth, SESSION_ID),
            Err(HandshakeTransportError::UnexpectedMessageType {
                expected: MessageType::ClientAuth,
                received: MessageType::ClientHello,
            })
        ));
    }

    #[test]
    fn malformed_payload_lengths_are_reported_as_handshake_errors() {
        let client_hello = frame_bytes(
            MessageType::ClientHello,
            UNASSIGNED_SESSION_ID,
            HANDSHAKE_COUNTER,
            vec![0; CLIENT_HELLO_LENGTH - 1],
        );
        let server_hello = frame_bytes(
            MessageType::ServerHello,
            SESSION_ID,
            HANDSHAKE_COUNTER,
            vec![0; SERVER_HELLO_LENGTH - 1],
        );
        let client_auth = frame_bytes(
            MessageType::ClientAuth,
            SESSION_ID,
            HANDSHAKE_COUNTER,
            vec![0; CLIENT_AUTH_LENGTH - 1],
        );

        assert!(matches!(
            decode_client_hello(&client_hello),
            Err(HandshakeTransportError::Handshake(
                HandshakeError::InvalidClientHelloLength { .. }
            ))
        ));
        assert!(matches!(
            decode_server_hello(&server_hello),
            Err(HandshakeTransportError::Handshake(
                HandshakeError::InvalidServerHelloLength { .. }
            ))
        ));
        assert!(matches!(
            decode_client_auth(&client_auth, SESSION_ID),
            Err(HandshakeTransportError::Handshake(
                HandshakeError::InvalidClientAuthLength { .. }
            ))
        ));
    }

    #[test]
    fn malformed_frames_are_reported_as_protocol_errors() {
        let bytes = [0_u8; HEADER_SIZE - 1];

        assert!(matches!(
            decode_client_hello(&bytes),
            Err(HandshakeTransportError::Protocol(
                ProtocolError::FrameTooShort { .. }
            ))
        ));
        assert!(matches!(
            decode_server_hello(&bytes),
            Err(HandshakeTransportError::Protocol(
                ProtocolError::FrameTooShort { .. }
            ))
        ));
        assert!(matches!(
            decode_client_auth(&bytes, SESSION_ID),
            Err(HandshakeTransportError::Protocol(
                ProtocolError::FrameTooShort { .. }
            ))
        ));
    }
}
