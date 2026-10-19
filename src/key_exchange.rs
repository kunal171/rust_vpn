//! Ephemeral X25519 key agreement for VPN handshakes.
//!
//! X25519 creates shared secret material but does not authenticate either peer.
//! The authenticated-handshake layer provides identity verification and
//! transcript binding around this primitive.

use std::{error::Error, fmt};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// Serialized length of an X25519 public key.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// Failure while converting peer input into shared key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeError {
    /// The peer key produced the all-zero shared secret and contributed no key material.
    NonContributoryPublicKey,
}

impl fmt::Display for KeyExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonContributoryPublicKey => {
                write!(
                    formatter,
                    "peer public key produced an invalid shared secret"
                )
            }
        }
    }
}

impl Error for KeyExchangeError {}

/// One-use X25519 secret and its corresponding public key.
///
/// Completion consumes the value so an ephemeral secret cannot be reused.
pub struct EphemeralKeyExchange {
    secret: EphemeralSecret,
    public_key: PublicKey,
}

impl EphemeralKeyExchange {
    /// Generates a fresh operating-system-random X25519 key pair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random();
        let public_key = PublicKey::from(&secret);

        Self { secret, public_key }
    }

    /// Returns the public key that may be sent to the peer.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.public_key.to_bytes()
    }

    /// Consumes the local secret and combines it with the peer public key.
    pub fn complete(
        self,
        peer_public_key: [u8; PUBLIC_KEY_LENGTH],
    ) -> Result<SharedSecret, KeyExchangeError> {
        let peer_public_key = PublicKey::from(peer_public_key);
        let shared_secret = self.secret.diffie_hellman(&peer_public_key);

        if !shared_secret.was_contributory() {
            return Err(KeyExchangeError::NonContributoryPublicKey);
        }

        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::{EphemeralKeyExchange, KeyExchangeError, PUBLIC_KEY_LENGTH};

    #[test]
    fn both_peers_compute_the_same_shared_secret() {
        let alice = EphemeralKeyExchange::generate();
        let bob = EphemeralKeyExchange::generate();

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let alice_shared = alice.complete(bob_public).unwrap();
        let bob_shared = bob.complete(alice_public).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn rejects_a_non_contributory_public_key() {
        let alice = EphemeralKeyExchange::generate();

        let result = alice.complete([0_u8; PUBLIC_KEY_LENGTH]);

        assert!(matches!(
            result,
            Err(KeyExchangeError::NonContributoryPublicKey)
        ));
    }
}
