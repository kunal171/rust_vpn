//! IPv4 networks written in CIDR notation, such as `10.210.0.0/24`.
//!
//! `vpn_tunnel` uses these as a peer's allowed source addresses: an inner
//! packet from the peer is accepted only if its source falls inside one.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// An IPv4 network: a base address and how many leading bits are fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_length: u8,
}

/// Describes why text could not be parsed as an IPv4 CIDR network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// The text has no `/prefix` part.
    MissingPrefix,
    /// The part before `/` is not an IPv4 address.
    InvalidAddress(String),
    /// The part after `/` is not a number from 0 to 32.
    InvalidPrefix(String),
    /// The address has bits set beyond the prefix, such as `10.0.0.7/24`.
    HostBitsSet {
        address: Ipv4Addr,
        prefix_length: u8,
    },
}

impl fmt::Display for CidrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => write!(formatter, "missing /prefix, as in 10.210.0.0/24"),
            Self::InvalidAddress(text) => write!(formatter, "{text:?} is not an IPv4 address"),
            Self::InvalidPrefix(text) => {
                write!(formatter, "{text:?} is not a prefix length from 0 to 32")
            }
            Self::HostBitsSet {
                address,
                prefix_length,
            } => write!(
                formatter,
                "{address}/{prefix_length} has host bits set; use the network address"
            ),
        }
    }
}

impl std::error::Error for CidrError {}

/// Returns a 32-bit mask with the first `prefix_length` bits set.
fn mask(prefix_length: u8) -> u32 {
    // `u32::MAX << 32` would overflow, so /0 is handled by `checked_shl`.
    u32::MAX
        .checked_shl(32 - u32::from(prefix_length))
        .unwrap_or(0)
}

impl Ipv4Cidr {
    /// Returns true when `address` lies inside this network.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        let mask = mask(self.prefix_length);
        u32::from(address) & mask == u32::from(self.network)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = CidrError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address_text, prefix_text) = text.split_once('/').ok_or(CidrError::MissingPrefix)?;

        let network: Ipv4Addr = address_text
            .parse()
            .map_err(|_| CidrError::InvalidAddress(address_text.to_owned()))?;

        let prefix_length: u8 = prefix_text
            .parse()
            .ok()
            .filter(|length| *length <= 32)
            .ok_or_else(|| CidrError::InvalidPrefix(prefix_text.to_owned()))?;

        if u32::from(network) & !mask(prefix_length) != 0 {
            return Err(CidrError::HostBitsSet {
                address: network,
                prefix_length,
            });
        }

        Ok(Self {
            network,
            prefix_length,
        })
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_length)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{CidrError, Ipv4Cidr};

    fn cidr(text: &str) -> Ipv4Cidr {
        text.parse().unwrap()
    }

    #[test]
    fn contains_addresses_inside_the_network() {
        let network = cidr("10.200.4.0/24");

        assert!(network.contains(Ipv4Addr::new(10, 200, 4, 0)));
        assert!(network.contains(Ipv4Addr::new(10, 200, 4, 2)));
        assert!(network.contains(Ipv4Addr::new(10, 200, 4, 255)));
    }

    #[test]
    fn excludes_addresses_outside_the_network() {
        let network = cidr("10.200.4.0/24");

        assert!(!network.contains(Ipv4Addr::new(10, 200, 5, 2)));
        assert!(!network.contains(Ipv4Addr::new(10, 210, 0, 1)));
    }

    #[test]
    fn a_slash_32_contains_exactly_one_address() {
        let network = cidr("10.210.0.1/32");

        assert!(network.contains(Ipv4Addr::new(10, 210, 0, 1)));
        assert!(!network.contains(Ipv4Addr::new(10, 210, 0, 2)));
    }

    #[test]
    fn a_slash_0_contains_every_address() {
        let network = cidr("0.0.0.0/0");

        assert!(network.contains(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(network.contains(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn displays_in_cidr_notation() {
        assert_eq!(cidr("10.200.4.0/24").to_string(), "10.200.4.0/24");
    }

    #[test]
    fn rejects_text_without_a_prefix() {
        assert_eq!(
            "10.200.4.0".parse::<Ipv4Cidr>(),
            Err(CidrError::MissingPrefix)
        );
    }

    #[test]
    fn rejects_an_invalid_address() {
        assert_eq!(
            "10.200.4.300/24".parse::<Ipv4Cidr>(),
            Err(CidrError::InvalidAddress("10.200.4.300".to_owned()))
        );
    }

    #[test]
    fn rejects_a_prefix_above_32() {
        assert_eq!(
            "10.200.4.0/33".parse::<Ipv4Cidr>(),
            Err(CidrError::InvalidPrefix("33".to_owned()))
        );
    }

    #[test]
    fn rejects_host_bits_beyond_the_prefix() {
        assert_eq!(
            "10.200.4.7/24".parse::<Ipv4Cidr>(),
            Err(CidrError::HostBitsSet {
                address: Ipv4Addr::new(10, 200, 4, 7),
                prefix_length: 24,
            })
        );
    }
}
