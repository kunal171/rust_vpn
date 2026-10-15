//! Stateful cryptographic operations for one VPN session.

use super::{
    key_derivation::{SessionKeys, SessionRole},
    packet_crypto::{MAX_PLAINTEXT_SIZE, PacketCryptoError, protect_frame, unprotect_frame_once},
    replay_window::ReplayWindow,
    send_counter::{SendCounter, SendCounterError},
};
use crate::protocol::{Frame, MessageType, ProtocolError};
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSessionError {
    Counter(SendCounterError),
    Protocol(ProtocolError),
    Crypto(PacketCryptoError),
    WrongSessionId { expected: u32, received: u32 },
}

impl fmt::Display for CryptoSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Counter(error) => {
                write!(formatter, "send counter failure: {error}")
            }
            Self::Protocol(error) => {
                write!(formatter, "protocol failure: {error}")
            }
            Self::Crypto(error) => {
                write!(formatter, "cryptographic failure: {error}")
            }
            Self::WrongSessionId { expected, received } => {
                write!(
                    formatter,
                    "frame session ID {received} does not match expected session ID {expected}"
                )
            }
        }
    }
}

impl Error for CryptoSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Counter(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::WrongSessionId { .. } => None,
        }
    }
}

impl From<SendCounterError> for CryptoSessionError {
    fn from(error: SendCounterError) -> Self {
        Self::Counter(error)
    }
}

impl From<ProtocolError> for CryptoSessionError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<PacketCryptoError> for CryptoSessionError {
    fn from(error: PacketCryptoError) -> Self {
        Self::Crypto(error)
    }
}

pub struct CryptoSession {
    session_id: u32,
    role: SessionRole,
    keys: SessionKeys,
    send_counter: SendCounter,
    receive_window: ReplayWindow,
}

impl CryptoSession {
    pub fn new(session_id: u32, role: SessionRole, keys: SessionKeys) -> Self {
        Self {
            session_id,
            role,
            keys,
            send_counter: SendCounter::new(),
            receive_window: ReplayWindow::new(),
        }
    }

    pub fn protect(
        &mut self,
        message_type: MessageType,
        payload: Vec<u8>,
    ) -> Result<Frame, CryptoSessionError> {
        if payload.len() > MAX_PLAINTEXT_SIZE {
            return Err(PacketCryptoError::PlaintextTooLarge {
                actual: payload.len(),
                maximum: MAX_PLAINTEXT_SIZE,
            }
            .into());
        }

        let counter = self.send_counter.take_next()?;

        let plaintext = Frame::new(message_type, self.session_id, counter, payload)?;

        protect_frame(&plaintext, self.keys.send_key(self.role)).map_err(Into::into)
    }

    pub fn unprotect(&mut self, frame: &Frame) -> Result<Frame, CryptoSessionError> {
        if frame.session_id() != self.session_id {
            return Err(CryptoSessionError::WrongSessionId {
                expected: self.session_id,
                received: frame.session_id(),
            });
        }

        unprotect_frame_once(
            frame,
            self.keys.receive_key(self.role),
            &mut self.receive_window,
        )
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::{CryptoSession, CryptoSessionError};
    use crate::toy_crypto::{packet_crypto::PacketCryptoError, replay_window::ReplayError};
    use crate::{
        protocol::MessageType,
        toy_crypto::key_derivation::{SessionRole, derive_session_keys},
    };

    #[test]
    fn assigns_unique_counters_automatically() {
        let shared_secret = 2_u64.to_be_bytes();

        let keys = derive_session_keys(&shared_secret, b"session-test").unwrap();

        let mut session = CryptoSession::new(42, SessionRole::Client, keys);

        let first = session.protect(MessageType::Data, b"one".to_vec()).unwrap();

        let second = session.protect(MessageType::Data, b"two".to_vec()).unwrap();

        assert_eq!(first.session_id(), 42);
        assert_eq!(first.counter(), 1);
        assert_eq!(second.counter(), 2);
    }

    #[test]
    fn client_and_server_exchange_protected_frames() {
        let shared_secret = 2_u64.to_be_bytes();
        let salt = b"session-test";

        let client_keys = derive_session_keys(&shared_secret, salt).unwrap();

        let server_keys = derive_session_keys(&shared_secret, salt).unwrap();

        let mut client = CryptoSession::new(42, SessionRole::Client, client_keys);

        let mut server = CryptoSession::new(42, SessionRole::Server, server_keys);

        let request = client
            .protect(MessageType::Data, b"request".to_vec())
            .unwrap();

        let received_request = server.unprotect(&request).unwrap();

        assert_eq!(received_request.payload(), b"request");

        let response = server
            .protect(MessageType::Data, b"response".to_vec())
            .unwrap();

        let received_response = client.unprotect(&response).unwrap();

        assert_eq!(received_response.payload(), b"response");
    }

    #[test]
    fn rejects_a_frame_for_another_session() {
        let shared_secret = 2_u64.to_be_bytes();
        let salt = b"session-test";

        let client_keys = derive_session_keys(&shared_secret, salt).unwrap();

        let server_keys = derive_session_keys(&shared_secret, salt).unwrap();

        let mut client = CryptoSession::new(42, SessionRole::Client, client_keys);

        let mut server = CryptoSession::new(99, SessionRole::Server, server_keys);

        let protected = client
            .protect(MessageType::Data, b"packet".to_vec())
            .unwrap();

        assert_eq!(
            server.unprotect(&protected),
            Err(CryptoSessionError::WrongSessionId {
                expected: 99,
                received: 42,
            }),
        );
    }

    #[test]
    fn rejects_a_replayed_frame() {
        let shared_secret = 2_u64.to_be_bytes();
        let salt = b"session-test";

        let client_keys = derive_session_keys(&shared_secret, salt).unwrap();

        let server_keys = derive_session_keys(&shared_secret, salt).unwrap();

        let mut client = CryptoSession::new(42, SessionRole::Client, client_keys);

        let mut server = CryptoSession::new(42, SessionRole::Server, server_keys);

        let protected = client
            .protect(MessageType::Data, b"packet".to_vec())
            .unwrap();

        assert!(server.unprotect(&protected).is_ok());

        assert_eq!(
            server.unprotect(&protected),
            Err(CryptoSessionError::Crypto(
                PacketCryptoError::ReplayRejected(ReplayError::Duplicate,),
            )),
        );
    }

    #[test]
    fn preserves_nested_error_sources() {
        use std::error::Error;

        let error =
            CryptoSessionError::Crypto(PacketCryptoError::ReplayRejected(ReplayError::Duplicate));

        let packet_error = error.source().unwrap();
        let replay_error = packet_error.source().unwrap();

        assert_eq!(
            replay_error.to_string(),
            "packet counter has already been received",
        );
    }
}
