use std::fmt;
use std::net::Ipv4Addr;
const MINIMUM_IPV4_HEADER_LENGTH: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub header_length: usize,
    pub total_length: usize,
    pub ttl: u8,
    pub protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4Error {
    PacketTooShort {
        actual: usize,
        minimum: usize,
    },
    InvalidHeaderLength {
        header_length: usize,
        minimum: usize,
    },
    TruncatedHeader {
        actual: usize,
        header_length: usize,
    },
    InvalidTotalLength {
        total_length: usize,
        header_length: usize,
        packet_length: usize,
    },
    UnsupportedVersion {
        version: u8,
    },
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
        }
    }
}

impl std::error::Error for Ipv4Error {}

pub fn decode_ipv4_header(packet: &[u8]) -> Result<Ipv4Header, Ipv4Error> {
    if packet.len() < MINIMUM_IPV4_HEADER_LENGTH {
        return Err(Ipv4Error::PacketTooShort {
            actual: packet.len(),
            minimum: MINIMUM_IPV4_HEADER_LENGTH,
        });
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return Err(Ipv4Error::UnsupportedVersion { version });
    }

    let ihl_words = packet[0] & 0x0f;

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
        source: source,
        destination: destination,
        header_length,
        total_length,
        ttl: ttl,
        protocol: protocol,
    })
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

    use super::{Ipv4Error, MINIMUM_IPV4_HEADER_LENGTH, decode_ipv4_header};

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
}
