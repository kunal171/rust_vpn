//! Shared library code used by the VPN binaries.
//!
//! Keeping shared types and constants in the library avoids duplicating them
//! across the binaries and lets integration tests import them.

#![warn(missing_docs)]

/// Authenticated X25519 and Ed25519 handshake state transitions.
pub mod authenticated_handshake;
/// IPv4 networks in CIDR notation, used as a peer's allowed source addresses.
pub mod cidr;
/// Pure route planning for an IPv4 full-tunnel client.
pub mod full_tunnel;
/// Canonical transcript hashed and authenticated during VPN handshakes.
pub mod handshake;
/// Encoding and validation of handshake messages carried over UDP.
pub mod handshake_transport;
/// Long-term Ed25519 identities used to authenticate peers.
pub mod identity;
/// IPv4 header decoding, the Internet checksum, and ICMP echo replies.
pub mod ipv4;
/// Semantic validation for authenticated keepalive control frames.
pub mod keepalive;
/// Ephemeral X25519 key agreement for creating fresh session secrets.
pub mod key_exchange;
/// Linux physical-route discovery for preserving the VPN transport path.
pub mod linux_route;
/// Bounded tracking of unanswered keepalive probes.
pub mod liveness;
/// Owned messages sent to the single cryptographic sender.
pub mod outbound;
/// Binary frame definitions and validation for data received from the network.
pub mod protocol;
pub mod route_manager;
/// Hand-written cryptographic math for learning. Never use it for real secrets.
pub mod toy_crypto;
/// UDP addresses, buffer sizes, timeouts, and shared transport constants.
pub mod transport;
/// Explicit state transitions for the tunnel connection lifecycle.
pub mod tunnel_lifecycle;
/// Authenticated handshake exchange over a connected UDP socket.
pub mod udp_handshake;

/// Identifies which side of the client-server example is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppRole {
    /// The process that initiates a datagram exchange with the server.
    Client,
    /// The process that listens for datagrams and sends responses.
    Server,
}

impl AppRole {
    /// Returns a human-readable name without allocating a new `String`.
    ///
    /// The returned reference is valid for the whole program because string
    /// literals are stored in the program binary.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AppRole;

    // This locks down the user-facing labels independently of socket behavior.
    #[test]
    fn returns_expected_role_labels() {
        assert_eq!(AppRole::Client.label(), "client");
        assert_eq!(AppRole::Server.label(), "server");
    }
}
