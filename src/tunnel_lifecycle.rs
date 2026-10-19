//! Models the lifecycle of an established VPN tunnel.

use std::{error::Error, fmt};

/// Mutually exclusive stages in the lifetime of one tunnel process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Authenticating the configured peer and deriving fresh session keys.
    Handshaking,
    /// Carrying protected tunnel traffic with an authenticated session.
    Established,
    /// The previous session expired and a fresh handshake is required.
    Reconnecting,
    /// Shutdown completed; this state cannot return to an active state.
    Stopped,
}

/// Events that may request a tunnel lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelEvent {
    /// A fresh authenticated handshake and key confirmation completed.
    HandshakeSucceeded,
    /// Bounded liveness probes received no authenticated peer activity.
    PeerTimedOut,
    /// The process was asked to terminate and release its resources.
    Shutdown,
}

/// Reports an event that is invalid for the tunnel's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleError {
    state: TunnelState,
    event: TunnelEvent,
}

impl Error for LifecycleError {}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "event {:?} is invalid while tunnel is {:?}",
            self.event, self.state
        )
    }
}

impl TunnelState {
    /// Applies one event and returns the next state without hidden mutation.
    ///
    /// Shutdown is idempotent so cleanup code may safely request it more than
    /// once. Every other unsupported state/event pair is rejected explicitly.
    pub fn transition(self, event: TunnelEvent) -> Result<Self, LifecycleError> {
        match (self, event) {
            (Self::Handshaking, TunnelEvent::HandshakeSucceeded) => Ok(Self::Established),

            (Self::Established, TunnelEvent::PeerTimedOut) => Ok(Self::Reconnecting),

            (Self::Reconnecting, TunnelEvent::HandshakeSucceeded) => Ok(Self::Established),

            (Self::Handshaking | Self::Established | Self::Reconnecting, TunnelEvent::Shutdown) => {
                Ok(Self::Stopped)
            }

            (Self::Stopped, TunnelEvent::Shutdown) => Ok(Self::Stopped),

            (state, event) => Err(LifecycleError { state, event }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TunnelEvent, TunnelState};

    #[test]
    fn successful_initial_handshake_establishes_the_tunnel() {
        let next = TunnelState::Handshaking
            .transition(TunnelEvent::HandshakeSucceeded)
            .unwrap();

        assert_eq!(next, TunnelState::Established);
    }

    #[test]
    fn peer_timeout_starts_reconnection() {
        let next = TunnelState::Established
            .transition(TunnelEvent::PeerTimedOut)
            .unwrap();

        assert_eq!(next, TunnelState::Reconnecting);
    }

    #[test]
    fn successful_reconnect_reestablishes_the_tunnel() {
        let next = TunnelState::Reconnecting
            .transition(TunnelEvent::HandshakeSucceeded)
            .unwrap();

        assert_eq!(next, TunnelState::Established);
    }

    #[test]
    fn invalid_transition_is_rejected() {
        let result = TunnelState::Handshaking.transition(TunnelEvent::PeerTimedOut);

        assert!(result.is_err());
    }

    #[test]
    fn stopped_tunnel_cannot_reconnect() {
        let result = TunnelState::Stopped.transition(TunnelEvent::HandshakeSucceeded);

        assert!(result.is_err());
    }
}
