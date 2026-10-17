//! Ephemeral X25519 key agreement for VPN handshakes.
//!
//! X25519 creates shared secret material but does not authenticate either peer.
//! Authentication and transcript binding will be added by the handshake layer.

use std::{error::Error, fmt};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub const PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeError {
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

pub struct EphemeralKeyExchange {
    secret: EphemeralSecret,
    public_key: PublicKey,
}

impl EphemeralKeyExchange {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random();
        let public_key = PublicKey::from(&secret);

        Self { secret, public_key }
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.public_key.to_bytes()
    }

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
