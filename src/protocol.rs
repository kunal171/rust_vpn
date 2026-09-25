pub const PROTOCOL_VERSION: u8 = 1;

pub const HEADER_SIZE: usize = 16;
pub const MAX_FRAME_SIZE: usize = 2048;
pub const MAX_PAYLOAD_SIZE: usize = MAX_FRAME_SIZE - HEADER_SIZE;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Data = 1,
    Acknowledgment = 2,
}

impl MessageType {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HEADER_SIZE, MAX_FRAME_SIZE, MAX_PAYLOAD_SIZE, MessageType,
        PROTOCOL_VERSION,
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
}