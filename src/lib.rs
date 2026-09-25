//! Shared library code used by both VPN binaries.
//!
//! Keeping shared types and constants in the library avoids duplicating them
//! in `vpn_client` and `vpn_server` and lets integration tests import them.

/// Binary frame definitions and validation for data received from the network.
pub mod protocol;
/// UDP addresses, buffer sizes, timeouts, and temporary transport constants.
pub mod transport;

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
