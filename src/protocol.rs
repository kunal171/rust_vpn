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

/// One logical message exchanged between VPN peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    version: u8,
    message_type: MessageType,
    session_id: u32,
    counter: u64,
    payload: Vec<u8>,
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

    /// The payload cannot fit inside the configured maximum frame size.
    PayloadTooLarge {
        actual: usize,
        maximum: usize,
    },

    FrameTooShort {
        actual: usize,
        minimum: usize,
    },
    FrameTooLarge {
        actual: usize,
        maximum: usize,
    },
    UnsupportedVersion {
        received: u8,
        supported: u8,
    },
    PayloadLengthMismatch {
        declared: usize,
        actual: usize,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMessageType(value) => {
                write!(formatter, "unknown message type: {value}")
            }
            Self::PayloadTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "payload contains {actual} bytes, but the maximum is {maximum}"
                )
            }
            Self::FrameTooShort { actual, minimum } => {
                write!(
                    formatter,
                    "frame contains {actual} bytes, but at least {minimum} are required"
                )
            }
            Self::FrameTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "frame contains {actual} bytes, but the maximum is {maximum}"
                )
            }
            Self::UnsupportedVersion {
                received,
                supported,
            } => {
                write!(
                    formatter,
                    "unsupported protocol version {received}; supported version is {supported}"
                )
            }
            Self::PayloadLengthMismatch { declared, actual } => {
                write!(
                    formatter,
                    "header declares {declared} payload bytes, but {actual} were received"
                )
            }
        }
    }
}

impl Frame {
    pub fn new(
        message_type: MessageType,
        session_id: u32,
        counter: u64,
        payload: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: payload.len(),
                maximum: MAX_PAYLOAD_SIZE,
            });
        }

        Ok(Self {
            version: PROTOCOL_VERSION,
            message_type,
            session_id,
            counter,
            payload,
        })
    }

    /// Serializes this frame using the protocol's network byte order.
    pub fn encode(&self) -> Vec<u8> {
        let payload_length =
            u16::try_from(self.payload.len()).expect("validated payload length fits in u16");

        let mut bytes = Vec::with_capacity(HEADER_SIZE + self.payload.len());

        bytes.push(self.version);
        bytes.push(self.message_type.as_u8());
        bytes.extend_from_slice(&self.session_id.to_be_bytes());
        bytes.extend_from_slice(&self.counter.to_be_bytes());
        bytes.extend_from_slice(&payload_length.to_be_bytes());
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    /// Parses and validates one complete binary frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ProtocolError::FrameTooShort {
                actual: bytes.len(),
                minimum: HEADER_SIZE,
            });
        }

        if bytes.len() > MAX_FRAME_SIZE {
            return Err(ProtocolError::FrameTooLarge {
                actual: bytes.len(),
                maximum: MAX_FRAME_SIZE,
            });
        }

        let version = bytes[0];

        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                received: version,
                supported: PROTOCOL_VERSION,
            });
        }

        let message_type = MessageType::try_from(bytes[1])?;

        let session_id = u32::from_be_bytes(
            bytes[2..6]
                .try_into()
                .expect("frame header contains four session ID bytes"),
        );

        let counter = u64::from_be_bytes(
            bytes[6..14]
                .try_into()
                .expect("frame header contains eight counter bytes"),
        );

        let declared_payload_length = usize::from(u16::from_be_bytes(
            bytes[14..16]
                .try_into()
                .expect("frame header contains two payload-length bytes"),
        ));

        if declared_payload_length > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                actual: declared_payload_length,
                maximum: MAX_PAYLOAD_SIZE,
            });
        }

        let actual_payload_length = bytes.len() - HEADER_SIZE;

        if declared_payload_length != actual_payload_length {
            return Err(ProtocolError::PayloadLengthMismatch {
                declared: declared_payload_length,
                actual: actual_payload_length,
            });
        }

        Ok(Self {
            version,
            message_type,
            session_id,
            counter,
            payload: bytes[HEADER_SIZE..].to_vec(),
        })
    }

    /// Returns the protocol version stored in this frame.
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the frame's message type.
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// Returns the session that owns this frame.
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Returns this frame's packet counter.
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Borrows the payload without copying it.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Builds the acknowledgment for a data frame.
    ///
    /// Acknowledgment frames return `None` so peers cannot create an ACK loop.
    pub fn acknowledgment(&self) -> Option<Self> {
        if self.message_type != MessageType::Data {
            return None;
        }

        Some(Self {
            version: self.version,
            message_type: MessageType::Acknowledgment,
            session_id: self.session_id,
            counter: self.counter,
            payload: Vec::new(),
        })
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
        Frame, HEADER_SIZE, MAX_FRAME_SIZE, MAX_PAYLOAD_SIZE, MessageType, PROTOCOL_VERSION,
        ProtocolError,
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

    #[test]
    fn creates_frame_with_maximum_payload() {
        let payload = vec![0xaa; MAX_PAYLOAD_SIZE];

        let result = Frame::new(MessageType::Data, 42, 1, payload);

        assert!(result.is_ok());
    }

    #[test]
    fn rejects_payload_larger_than_maximum() {
        let payload = vec![0xaa; MAX_PAYLOAD_SIZE + 1];

        let result = Frame::new(MessageType::Data, 42, 1, payload);

        assert_eq!(
            result,
            Err(ProtocolError::PayloadTooLarge {
                actual: MAX_PAYLOAD_SIZE + 1,
                maximum: MAX_PAYLOAD_SIZE,
            })
        );
    }

    #[test]
    fn encodes_frame_in_network_byte_order() {
        let frame = Frame::new(
            MessageType::Data,
            0x0102_0304,
            0x0506_0708_090a_0b0c,
            vec![0xde, 0xad],
        )
        .unwrap();

        assert_eq!(
            frame.encode(),
            vec![
                0x01, 0x01, // version and type
                0x01, 0x02, 0x03, 0x04, // session ID
                0x05, 0x06, 0x07, 0x08, // counter
                0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x02, // payload length
                0xde, 0xad, // payload
            ]
        );
    }

    #[test]
    fn encoded_frame_decodes_without_losing_information() {
        let original = Frame::new(MessageType::Data, 0x0102_0304, 42, vec![0xde, 0xad]).unwrap();

        let encoded = original.encode();
        let decoded = Frame::decode(&encoded);

        assert_eq!(decoded, Ok(original));
    }

    #[test]
    fn rejects_frame_shorter_than_header() {
        let bytes = [PROTOCOL_VERSION];

        assert_eq!(
            Frame::decode(&bytes),
            Err(ProtocolError::FrameTooShort {
                actual: 1,
                minimum: HEADER_SIZE,
            })
        );
    }

    #[test]
    fn rejects_frame_larger_than_maximum() {
        let bytes = vec![0_u8; MAX_FRAME_SIZE + 1];

        assert_eq!(
            Frame::decode(&bytes),
            Err(ProtocolError::FrameTooLarge {
                actual: MAX_FRAME_SIZE + 1,
                maximum: MAX_FRAME_SIZE,
            })
        );
    }

    #[test]
    fn rejects_unsupported_protocol_version() {
        let frame = Frame::new(MessageType::Data, 42, 1, vec![0xaa]).unwrap();
        let mut bytes = frame.encode();

        bytes[0] = 2;

        assert_eq!(
            Frame::decode(&bytes),
            Err(ProtocolError::UnsupportedVersion {
                received: 2,
                supported: PROTOCOL_VERSION,
            })
        );
    }

    #[test]
    fn rejects_unknown_message_type_in_frame() {
        let frame = Frame::new(MessageType::Data, 42, 1, vec![0xaa]).unwrap();
        let mut bytes = frame.encode();

        bytes[1] = 0xff;

        assert_eq!(
            Frame::decode(&bytes),
            Err(ProtocolError::UnknownMessageType(0xff))
        );
    }

    #[test]
    fn rejects_payload_length_mismatch() {
        let frame = Frame::new(MessageType::Data, 42, 1, vec![0xaa, 0xbb]).unwrap();

        let mut bytes = frame.encode();

        // The frame contains two payload bytes, but the header claims three.
        bytes[14..16].copy_from_slice(&3_u16.to_be_bytes());

        assert_eq!(
            Frame::decode(&bytes),
            Err(ProtocolError::PayloadLengthMismatch {
                declared: 3,
                actual: 2,
            })
        );
    }

    #[test]
    fn rejects_declared_payload_larger_than_maximum() {
        let frame = Frame::new(MessageType::Data, 42, 1, Vec::new()).unwrap();
        let mut bytes = frame.encode();

        let oversized_length = u16::try_from(MAX_PAYLOAD_SIZE + 1).unwrap();

        bytes[14..16].copy_from_slice(&oversized_length.to_be_bytes());

        assert_eq!(
            Frame::decode(&bytes),
            Err(ProtocolError::PayloadTooLarge {
                actual: MAX_PAYLOAD_SIZE + 1,
                maximum: MAX_PAYLOAD_SIZE,
            })
        );
    }

    #[test]
    fn data_frame_creates_matching_empty_acknowledgment() {
        let data = Frame::new(MessageType::Data, 42, 7, vec![0xaa]).unwrap();

        let acknowledgment = data.acknowledgment().unwrap();

        assert_eq!(acknowledgment.message_type(), MessageType::Acknowledgment);
        assert_eq!(acknowledgment.session_id(), 42);
        assert_eq!(acknowledgment.counter(), 7);
        assert!(acknowledgment.payload().is_empty());
    }

    #[test]
    fn acknowledgment_frame_does_not_create_another_acknowledgment() {
        let acknowledgment = Frame::new(MessageType::Acknowledgment, 42, 7, Vec::new()).unwrap();

        assert_eq!(acknowledgment.acknowledgment(), None);
    }
}
