//! Parses IPv4 packets read from the TUN interface and answers ICMP pings.
//!
//! Byte offsets used throughout this module, for a packet whose IPv4 header
//! has no options (20 bytes):
//!
//! ```text
//! IPv4 header                          ICMP message
//!  0      version (4 bits) | IHL (4)   20     type
//!  2..4   total length                 21     code
//!  8      TTL                          22..24 checksum
//!  9      protocol                     24..26 identifier
//! 10..12  header checksum              26..28 sequence number
//! 12..16  source address               28..   data
//! 16..20  destination address
//! ```
//!
//! Every length and offset comes from the packet itself, so each one is
//! validated before it is used to index into the buffer.

use std::fmt;
use std::net::Ipv4Addr;

/// Size of an IPv4 header that carries no options.
const MINIMUM_IPV4_HEADER_LENGTH: usize = 20;
/// Value of the IPv4 protocol field when the payload is an ICMP message.
const ICMP_PROTOCOL: u8 = 1;
/// Fixed ICMP fields before the data: type, code, checksum, identifier, sequence.
const ICMP_HEADER_LENGTH: usize = 8;
/// ICMP type sent by `ping`.
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP type that answers an echo request.
const ICMP_ECHO_REPLY: u8 = 0;

/// The IPv4 header fields this project currently needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    /// Header size in bytes, including any options.
    pub header_length: usize,
    /// Size of the whole packet in bytes: header plus payload.
    pub total_length: usize,
    /// Remaining hops before routers discard the packet.
    pub ttl: u8,
    /// Identifies the payload, for example 1 for ICMP or 17 for UDP.
    pub protocol: u8,
}

/// Describes why packet bytes could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4Error {
    /// The buffer cannot hold even a header without options.
    PacketTooShort { actual: usize, minimum: usize },
    /// The IHL field claims a header smaller than the 20-byte minimum.
    InvalidHeaderLength {
        header_length: usize,
        minimum: usize,
    },
    /// The IHL field claims more header bytes than the buffer contains.
    TruncatedHeader { actual: usize, header_length: usize },
    /// The total length is smaller than the header or larger than the buffer.
    InvalidTotalLength {
        total_length: usize,
        header_length: usize,
        packet_length: usize,
    },
    /// The version field is not 4.
    UnsupportedVersion { version: u8 },
    /// The packet carries something other than ICMP.
    UnexpectedProtocol { protocol: u8 },
    /// The payload is too short to hold the fixed ICMP fields.
    TruncatedIcmp { actual: usize, minimum: usize },
    /// The ICMP message is valid but is not an echo request.
    NotEchoRequest { icmp_type: u8, code: u8 },
}

impl fmt::Display for Ipv4Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort { actual, minimum } => {
                write!(
                    formatter,
                    "IPv4 packet is {actual} bytes; at least {minimum} are required"
                )
            }
            Self::InvalidHeaderLength {
                header_length,
                minimum,
            } => {
                write!(
                    formatter,
                    "IPv4 header length {header_length} is below {minimum}"
                )
            }
            Self::TruncatedHeader {
                actual,
                header_length,
            } => {
                write!(
                    formatter,
                    "IPv4 packet is {actual} bytes, but the header claims {header_length}"
                )
            }
            Self::InvalidTotalLength {
                total_length,
                header_length,
                packet_length,
            } => {
                write!(
                    formatter,
                    "IPv4 total length {total_length} is outside header {header_length} and packet {packet_length}"
                )
            }
            Self::UnsupportedVersion { version } => {
                write!(formatter, "unsupported IP version {version}")
            }
            Self::UnexpectedProtocol { protocol } => {
                write!(formatter, "IPv4 protocol {protocol} is not ICMP")
            }
            Self::TruncatedIcmp { actual, minimum } => {
                write!(formatter, "ICMP Message length {actual} is below {minimum}")
            }
            Self::NotEchoRequest { icmp_type, code } => {
                write!(
                    formatter,
                    "ICMP Type {icmp_type} is not an Echo Request has code {code}"
                )
            }
        }
    }
}

impl std::error::Error for Ipv4Error {}

/// Validates and decodes the IPv4 header at the start of `packet`.
///
/// The buffer may be longer than the packet's declared total length; the
/// extra bytes are ignored. The header checksum is not verified.
pub fn decode_ipv4_header(packet: &[u8]) -> Result<Ipv4Header, Ipv4Error> {
    // Checking for 20 bytes first makes every fixed-offset read below safe.
    if packet.len() < MINIMUM_IPV4_HEADER_LENGTH {
        return Err(Ipv4Error::PacketTooShort {
            actual: packet.len(),
            minimum: MINIMUM_IPV4_HEADER_LENGTH,
        });
    }

    // Byte 0 holds two 4-bit fields: the version in the high half and the
    // header length (IHL) in the low half.
    let version = packet[0] >> 4;
    if version != 4 {
        return Err(Ipv4Error::UnsupportedVersion { version });
    }

    let ihl_words = packet[0] & 0x0f;

    // IHL counts 32-bit words, so multiply by 4 to get bytes.
    let header_length = usize::from(ihl_words) * 4;

    if header_length < MINIMUM_IPV4_HEADER_LENGTH {
        return Err(Ipv4Error::InvalidHeaderLength {
            header_length,
            minimum: MINIMUM_IPV4_HEADER_LENGTH,
        });
    }

    if packet.len() < header_length {
        return Err(Ipv4Error::TruncatedHeader {
            actual: packet.len(),
            header_length,
        });
    }

    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));

    if total_length < header_length || total_length > packet.len() {
        return Err(Ipv4Error::InvalidTotalLength {
            total_length,
            header_length,
            packet_length: packet.len(),
        });
    }

    let ttl = packet[8];
    let protocol = packet[9];

    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    Ok(Ipv4Header {
        source,
        destination,
        header_length,
        total_length,
        ttl,
        protocol,
    })
}

/// Computes the Internet checksum (RFC 1071) used by IPv4 and ICMP.
///
/// To produce a checksum, zero the checksum field first and store the result
/// there. To verify one, run this over the data with its checksum in place:
/// intact data yields 0.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    // A `u32` leaves room for the carries out of the 16-bit additions.
    let mut sum: u32 = 0;
    let (pairs, remainder) = bytes.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    // An odd trailing byte is padded with a zero byte on its right.
    if let [last] = remainder {
        sum += u32::from(*last) << 8;
    }

    // Fold the carries back into the low 16 bits (ones' complement addition).
    // Folding can itself carry, so repeat until the sum fits.
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds the echo reply for an IPv4 packet containing an ICMP echo request.
///
/// The reply is the request with the addresses swapped, the ICMP type changed
/// to echo reply, and both checksums recomputed. The identifier, sequence
/// number, and data are returned unchanged so `ping` can match the reply.
pub fn icmp_echo_reply(packet: &[u8]) -> Result<Vec<u8>, Ipv4Error> {
    let header = decode_ipv4_header(packet)?;

    if header.protocol() != ICMP_PROTOCOL {
        return Err(Ipv4Error::UnexpectedProtocol {
            protocol: header.protocol(),
        });
    }

    // The ICMP message fills the packet from the end of the IPv4 header to
    // the declared total length. The decoder guarantees end >= offset.
    let icmp_offset = header.header_length();
    let icmp_end = header.total_length();
    if icmp_end - icmp_offset < ICMP_HEADER_LENGTH {
        return Err(Ipv4Error::TruncatedIcmp {
            actual: icmp_end - icmp_offset,
            minimum: ICMP_HEADER_LENGTH,
        });
    }

    let icmp_type = packet[icmp_offset];
    let icmp_code = packet[icmp_offset + 1];
    if icmp_type != ICMP_ECHO_REQUEST || icmp_code != 0 {
        return Err(Ipv4Error::NotEchoRequest {
            icmp_type,
            code: icmp_code,
        });
    }

    // Copy only the declared packet, dropping any extra bytes in the buffer.
    let mut reply = packet[..icmp_end].to_vec();

    // Swap source (12..16) and destination (16..20) so the reply returns to
    // the sender.
    for offset in 0..4 {
        reply.swap(12 + offset, 16 + offset)
    }

    reply[icmp_offset] = ICMP_ECHO_REPLY;

    // The bytes changed, so both checksums are stale. Each field must be zero
    // while its checksum is computed. The IPv4 checksum covers only the header.
    reply[10] = 0;
    reply[11] = 0;
    let ip_checksum = internet_checksum(&reply[..icmp_offset]);

    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // The ICMP checksum covers the whole ICMP message, including its data.
    let checksum_offset = icmp_offset + 2;
    reply[checksum_offset] = 0;
    reply[checksum_offset + 1] = 0;
    let icmp_checksum = internet_checksum(&reply[icmp_offset..icmp_end]);
    reply[checksum_offset..checksum_offset + 2].copy_from_slice(&icmp_checksum.to_be_bytes());

    Ok(reply)
}

impl Ipv4Header {
    pub fn source(&self) -> Ipv4Addr {
        self.source
    }
    pub fn destination(&self) -> Ipv4Addr {
        self.destination
    }
    pub fn header_length(&self) -> usize {
        self.header_length
    }
    pub fn total_length(&self) -> usize {
        self.total_length
    }
    pub fn ttl(&self) -> u8 {
        self.ttl
    }
    pub fn protocol(&self) -> u8 {
        self.protocol
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        Ipv4Error, MINIMUM_IPV4_HEADER_LENGTH, decode_ipv4_header, icmp_echo_reply,
        internet_checksum,
    };

    /// A 20-byte IPv4 header: version 4, IHL 5, TTL 64, UDP, 10.210.0.1 → 10.210.0.2.
    fn valid_header() -> [u8; 20] {
        let mut packet = [0_u8; MINIMUM_IPV4_HEADER_LENGTH];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 210, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 210, 0, 2]);
        packet
    }

    #[test]
    fn decodes_a_minimum_length_header() {
        let header = decode_ipv4_header(&valid_header()).unwrap();

        assert_eq!(header.source(), Ipv4Addr::new(10, 210, 0, 1));
        assert_eq!(header.destination(), Ipv4Addr::new(10, 210, 0, 2));
        assert_eq!(header.header_length(), MINIMUM_IPV4_HEADER_LENGTH);
        assert_eq!(header.total_length(), 20);
        assert_eq!(header.ttl(), 64);
        assert_eq!(header.protocol(), 17);
    }

    #[test]
    fn decodes_a_header_with_options() {
        let mut packet = valid_header().to_vec();
        packet[0] = 0x46;
        packet.extend_from_slice(&[0; 4]);
        packet[2..4].copy_from_slice(&24_u16.to_be_bytes());

        let header = decode_ipv4_header(&packet).unwrap();

        assert_eq!(header.header_length(), 24);
        assert_eq!(header.total_length(), 24);
    }

    #[test]
    fn accepts_a_buffer_longer_than_the_declared_total_length() {
        let mut packet = valid_header().to_vec();
        packet.push(0xff);

        let header = decode_ipv4_header(&packet).unwrap();

        assert_eq!(header.total_length(), 20);
    }

    #[test]
    fn rejects_a_packet_shorter_than_the_minimum_header() {
        assert_eq!(
            decode_ipv4_header(&[]),
            Err(Ipv4Error::PacketTooShort {
                actual: 0,
                minimum: MINIMUM_IPV4_HEADER_LENGTH,
            })
        );

        assert_eq!(
            decode_ipv4_header(&[0_u8; 19]),
            Err(Ipv4Error::PacketTooShort {
                actual: 19,
                minimum: MINIMUM_IPV4_HEADER_LENGTH,
            })
        );
    }

    #[test]
    fn rejects_a_version_other_than_4() {
        let mut packet = valid_header();
        packet[0] = 0x65;

        assert_eq!(
            decode_ipv4_header(&packet),
            Err(Ipv4Error::UnsupportedVersion { version: 6 })
        );
    }

    #[test]
    fn rejects_a_header_length_below_the_minimum() {
        let mut packet = valid_header();
        packet[0] = 0x44;

        assert_eq!(
            decode_ipv4_header(&packet),
            Err(Ipv4Error::InvalidHeaderLength {
                header_length: 16,
                minimum: MINIMUM_IPV4_HEADER_LENGTH,
            })
        );
    }

    #[test]
    fn rejects_a_packet_shorter_than_the_claimed_header() {
        let mut packet = valid_header();
        packet[0] = 0x46;

        assert_eq!(
            decode_ipv4_header(&packet),
            Err(Ipv4Error::TruncatedHeader {
                actual: 20,
                header_length: 24,
            })
        );
    }

    #[test]
    fn rejects_a_total_length_smaller_than_the_header() {
        let mut packet = valid_header();
        packet[2..4].copy_from_slice(&10_u16.to_be_bytes());

        assert_eq!(
            decode_ipv4_header(&packet),
            Err(Ipv4Error::InvalidTotalLength {
                total_length: 10,
                header_length: MINIMUM_IPV4_HEADER_LENGTH,
                packet_length: 20,
            })
        );
    }

    #[test]
    fn rejects_a_total_length_larger_than_the_packet() {
        let mut packet = valid_header();
        packet[2..4].copy_from_slice(&21_u16.to_be_bytes());

        assert_eq!(
            decode_ipv4_header(&packet),
            Err(Ipv4Error::InvalidTotalLength {
                total_length: 21,
                header_length: MINIMUM_IPV4_HEADER_LENGTH,
                packet_length: 20,
            })
        );
    }

    /// A real 20-byte header with its checksum field (bytes 10..12) zeroed.
    const HEADER_WITHOUT_CHECKSUM: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];

    #[test]
    fn computes_the_checksum_of_a_known_header() {
        assert_eq!(internet_checksum(&HEADER_WITHOUT_CHECKSUM), 0xb861);
    }

    #[test]
    fn a_header_containing_its_checksum_sums_to_zero() {
        let mut header = HEADER_WITHOUT_CHECKSUM;
        header[10..12].copy_from_slice(&0xb861_u16.to_be_bytes());

        assert_eq!(internet_checksum(&header), 0);
    }

    #[test]
    fn pads_an_odd_trailing_byte_with_zero() {
        // 0x01 is treated as the 16-bit word 0x0100; its complement is 0xfeff.
        assert_eq!(internet_checksum(&[0x01]), 0xfeff);
    }

    /// Echo request 10.210.0.1 → 10.210.0.2, id 0x1234, seq 1, no data.
    fn echo_request() -> Vec<u8> {
        vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x65, 0x3a, 0x0a, 0xd2,
            0x00, 0x01, 0x0a, 0xd2, 0x00, 0x02, 0x08, 0x00, 0xe5, 0xca, 0x12, 0x34, 0x00, 0x01,
        ]
    }

    #[test]
    fn builds_an_echo_reply_from_an_echo_request() {
        let reply = icmp_echo_reply(&echo_request()).unwrap();

        assert_eq!(
            reply,
            vec![
                0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x65, 0x3a, 0x0a, 0xd2,
                0x00, 0x02, 0x0a, 0xd2, 0x00, 0x01, 0x00, 0x00, 0xed, 0xca, 0x12, 0x34, 0x00, 0x01,
            ]
        );
    }

    #[test]
    fn echo_reply_checksums_verify_to_zero() {
        let reply = icmp_echo_reply(&echo_request()).unwrap();

        assert_eq!(internet_checksum(&reply[..20]), 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
    }

    #[test]
    fn rejects_a_packet_that_is_not_icmp() {
        let mut packet = echo_request();
        packet[9] = 17;

        assert_eq!(
            icmp_echo_reply(&packet),
            Err(Ipv4Error::UnexpectedProtocol { protocol: 17 })
        );
    }

    #[test]
    fn rejects_an_icmp_message_shorter_than_its_header() {
        let mut packet = echo_request();
        // Claim only 4 ICMP bytes: total length 24 instead of 28.
        packet[2..4].copy_from_slice(&24_u16.to_be_bytes());

        assert_eq!(
            icmp_echo_reply(&packet),
            Err(Ipv4Error::TruncatedIcmp {
                actual: 4,
                minimum: 8,
            })
        );
    }

    #[test]
    fn rejects_an_icmp_message_that_is_not_an_echo_request() {
        let mut packet = echo_request();
        packet[20] = 0;

        assert_eq!(
            icmp_echo_reply(&packet),
            Err(Ipv4Error::NotEchoRequest {
                icmp_type: 0,
                code: 0,
            })
        );
    }
}
