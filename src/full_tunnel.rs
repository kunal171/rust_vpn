//! Builds the IPv4 route policy required by a full-tunnel client.
//!
//! This module only describes routes. Applying or removing privileged Linux
//! routes belongs to a separate runtime layer.

use crate::cidr::Ipv4Cidr;
use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr},
};

/// Routes needed to capture IPv4 traffic without capturing the VPN transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullTunnelPlan {
    peer_bypass: Ipv4Addr,
    tunnel_routes: [Ipv4Cidr; 2],
}

/// Failure while creating an IPv4 full-tunnel route plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullTunnelError {
    /// Phase 13 currently supports only an IPv4 UDP peer.
    Ipv6PeerUnsupported,
}

impl fmt::Display for FullTunnelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv6PeerUnsupported => {
                formatter.write_str("full-tunnel routing currently requires an IPv4 peer")
            }
        }
    }
}

impl Error for FullTunnelError {}

impl FullTunnelPlan {
    /// Creates a peer bypass and two routes covering the complete IPv4 space.
    pub fn new(peer: IpAddr) -> Result<Self, FullTunnelError> {
        let IpAddr::V4(peer_bypass) = peer else {
            return Err(FullTunnelError::Ipv6PeerUnsupported);
        };

        let lower_half = "0.0.0.0/1"
            .parse()
            .expect("0.0.0.0/1 is a valid canonical CIDR");

        let upper_half = "128.0.0.0/1"
            .parse()
            .expect("128.0.0.0/1 is a valid canonical CIDR");

        Ok(Self {
            peer_bypass,
            tunnel_routes: [lower_half, upper_half],
        })
    }

    /// Returns the VPN server address that must bypass the tunnel.
    pub const fn peer_bypass(&self) -> Ipv4Addr {
        self.peer_bypass
    }

    /// Returns the two routes that capture the complete IPv4 address space.
    pub const fn tunnel_routes(&self) -> &[Ipv4Cidr; 2] {
        &self.tunnel_routes
    }
}

#[cfg(test)]
mod tests {
    use super::{FullTunnelError, FullTunnelPlan};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn creates_peer_bypass_and_split_default_routes() {
        let peer = Ipv4Addr::new(203, 0, 113, 10);

        let plan = FullTunnelPlan::new(IpAddr::V4(peer)).unwrap();

        assert_eq!(plan.peer_bypass(), peer);
        assert_eq!(plan.tunnel_routes()[0].to_string(), "0.0.0.0/1");
        assert_eq!(plan.tunnel_routes()[1].to_string(), "128.0.0.0/1");
    }

    #[test]
    fn split_routes_cover_both_ipv4_halves() {
        let plan = FullTunnelPlan::new(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();

        assert!(plan.tunnel_routes()[0].contains(Ipv4Addr::new(127, 255, 255, 255)));

        assert!(plan.tunnel_routes()[1].contains(Ipv4Addr::new(128, 0, 0, 0)));

        assert!(plan.tunnel_routes()[1].contains(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn rejects_an_ipv6_transport_peer() {
        let result = FullTunnelPlan::new(IpAddr::V6(Ipv6Addr::LOCALHOST));

        assert_eq!(result, Err(FullTunnelError::Ipv6PeerUnsupported));
    }
}
