//! Defines the binary frame format shared by the VPN client and server.
//!
//! Version 1 uses a fixed header followed by an arbitrary byte payload:
//! `version | message type | session ID | packet counter | payload length`.
//!
//! Every peer-controlled value must be validated before use. Multi-byte
//! integers will be encoded explicitly in network byte order (big-endian).

use std::fmt;

/// Identifies the wire-format version understood by this implementation.
pub const PROTOCOL_VERSION: u8 = 1;

/// Number of bytes occupied by the fixed fields before the payload.
pub const HEADER_SIZE: usize = 16;
/// Largest frame this educational protocol currently accepts.
pub const MAX_FRAME_SIZE: usize = 2048;
/// Payload capacity left after subtracting the fixed header.
pub const MAX_PAYLOAD_SIZE: usize = MAX_FRAME_SIZE - HEADER_SIZE;

/// Describes how the receiver should interpret a frame's payload.
///
/// Explicit discriminants keep these values stable on the wire.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Carries tunnel data; later this will be an inner IP packet.
    Data = 1,
    /// Confirms receipt of a previously sent data message.
    Acknowledgment = 2,
}

impl MessageType {
    /// Returns the stable byte value written into the frame header.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Describes why peer-controlled frame bytes could not be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// The message-type byte is not assigned by this protocol version.
    UnknownMessageType(u8),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMessageType(value) => {
                write!(formatter, "unknown message type: {value}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        // Match every peer-controlled value instead of assuming that every `u8`
        // represents a valid Rust enum discriminant.
        match value {
            value if value == Self::Data.as_u8() => Ok(Self::Data),
            value if value == Self::Acknowledgment.as_u8() => Ok(Self::Acknowledgment),
            value => Err(ProtocolError::UnknownMessageType(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HEADER_SIZE, MAX_FRAME_SIZE, MAX_PAYLOAD_SIZE, MessageType, PROTOCOL_VERSION, ProtocolError,
    };

    #[test]
    fn protocol_constants_are_consistent() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(HEADER_SIZE, 16);
        assert_eq!(MAX_FRAME_SIZE, 2048);
        assert_eq!(MAX_PAYLOAD_SIZE, 2032);
    }

    #[test]
    fn message_types_have_stable_wire_values() {
        assert_eq!(MessageType::Data.as_u8(), 1);
        assert_eq!(MessageType::Acknowledgment.as_u8(), 2);
    }

    #[test]
    fn converts_known_wire_values_to_message_types() {
        assert_eq!(MessageType::try_from(1), Ok(MessageType::Data));

        assert_eq!(MessageType::try_from(2), Ok(MessageType::Acknowledgment));
    }

    #[test]
    fn rejects_unknown_message_type() {
        assert_eq!(
            MessageType::try_from(0),
            Err(ProtocolError::UnknownMessageType(0))
        );

        assert_eq!(
            MessageType::try_from(255),
            Err(ProtocolError::UnknownMessageType(255))
        );
    }
}
