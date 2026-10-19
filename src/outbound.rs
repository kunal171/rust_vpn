//! Owned messages waiting for protection by the tunnel's sender thread.
//!
//! Multiple producers may create these values, but exactly one thread owns
//! `CryptoSender` and converts them into protected frames.

use crate::protocol::MessageType;

/// One logical message waiting to be encrypted and sent over UDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundMessage {
    /// An inner IP packet read from TUN.
    Data(Vec<u8>),

    /// An authenticated liveness probe.
    Keepalive,

    /// The response to an authenticated liveness probe.
    KeepaliveResponse,
}

impl OutboundMessage {
    /// Consumes the message and returns the frame type and plaintext payload.
    ///
    /// Consuming `self` moves a Data packet's `Vec<u8>` without cloning it.
    pub fn into_parts(self) -> (MessageType, Vec<u8>) {
        match self {
            Self::Data(packet) => (MessageType::Data, packet),

            Self::Keepalive => (MessageType::Keepalive, Vec::new()),

            Self::KeepaliveResponse => (MessageType::KeepaliveResponse, Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OutboundMessage;
    use crate::protocol::MessageType;

    #[test]
    fn data_preserves_the_inner_packet() {
        let packet = vec![0x45, 0x00, 0xff];

        let (message_type, payload) = OutboundMessage::Data(packet.clone()).into_parts();

        assert_eq!(message_type, MessageType::Data);
        assert_eq!(payload, packet);
    }

    #[test]
    fn keepalive_has_an_empty_payload() {
        let (message_type, payload) = OutboundMessage::Keepalive.into_parts();

        assert_eq!(message_type, MessageType::Keepalive);
        assert!(payload.is_empty());
    }

    #[test]
    fn keepalive_response_has_an_empty_payload() {
        let (message_type, payload) = OutboundMessage::KeepaliveResponse.into_parts();

        assert_eq!(message_type, MessageType::KeepaliveResponse);
        assert!(payload.is_empty());
    }
}
