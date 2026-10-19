//! Validates authenticated keepalive control messages.
//!
//! Call this module only after `CryptoReceiver::unprotect` succeeds.

use std::{error::Error, fmt};

use crate::protocol::{Frame, MessageType};

/// Tells the tunnel how to handle one authenticated keepalive control frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveAction {
    /// Send a protected response using a fresh outbound counter.
    SendResponse,
    /// Record that the peer answered the outstanding liveness probe.
    ResponseReceived,
}

/// Describes invalid semantics in an authenticated keepalive control frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveError {
    /// The caller supplied a frame that is not part of the keepalive exchange.
    UnexpectedMessageType {
        /// Authenticated type supplied by the caller.
        received: MessageType,
    },

    /// Keepalive control messages do not carry application data.
    NonEmptyPayload {
        /// Keepalive type carrying the forbidden payload.
        message_type: MessageType,
        /// Number of unexpected payload bytes.
        actual: usize,
    },
}

impl fmt::Display for KeepaliveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedMessageType { received } => {
                write!(
                    formatter,
                    "expected a keepalive message, received {received:?}"
                )
            }

            Self::NonEmptyPayload {
                message_type,
                actual,
            } => {
                write!(
                    formatter,
                    "{message_type:?} payload must be empty, received {actual} bytes"
                )
            }
        }
    }
}

impl Error for KeepaliveError {}

/// Validates an already-authenticated keepalive frame and selects its action.
///
/// The caller must first pass the received frame through
/// `CryptoReceiver::unprotect`. Structural decoding alone does not prove that
/// the peer created the message and must never refresh its liveness state.
pub fn classify_authenticated_keepalive(frame: &Frame) -> Result<KeepaliveAction, KeepaliveError> {
    let action = match frame.message_type() {
        MessageType::Keepalive => KeepaliveAction::SendResponse,

        MessageType::KeepaliveResponse => KeepaliveAction::ResponseReceived,

        received => {
            return Err(KeepaliveError::UnexpectedMessageType { received });
        }
    };

    if !frame.payload().is_empty() {
        return Err(KeepaliveError::NonEmptyPayload {
            message_type: frame.message_type(),
            actual: frame.payload().len(),
        });
    }

    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::{KeepaliveAction, KeepaliveError, classify_authenticated_keepalive};
    use crate::protocol::{Frame, MessageType};

    #[test]
    fn keepalive_requests_a_response() {
        let frame = Frame::new(MessageType::Keepalive, 42, 1, Vec::new()).unwrap();

        assert_eq!(
            classify_authenticated_keepalive(&frame),
            Ok(KeepaliveAction::SendResponse)
        );
    }

    #[test]
    fn keepalive_response_marks_the_peer_alive() {
        let frame = Frame::new(MessageType::KeepaliveResponse, 42, 2, Vec::new()).unwrap();

        assert_eq!(
            classify_authenticated_keepalive(&frame),
            Ok(KeepaliveAction::ResponseReceived)
        );
    }

    #[test]
    fn rejects_nonempty_keepalive_payload() {
        let frame = Frame::new(MessageType::Keepalive, 42, 1, vec![0xaa]).unwrap();

        assert_eq!(
            classify_authenticated_keepalive(&frame),
            Err(KeepaliveError::NonEmptyPayload {
                message_type: MessageType::Keepalive,
                actual: 1,
            })
        );
    }

    #[test]
    fn rejects_data_as_a_keepalive_message() {
        let frame = Frame::new(MessageType::Data, 42, 1, Vec::new()).unwrap();

        assert_eq!(
            classify_authenticated_keepalive(&frame),
            Err(KeepaliveError::UnexpectedMessageType {
                received: MessageType::Data,
            })
        );
    }
}
