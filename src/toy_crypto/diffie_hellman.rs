//! Toy Diffie-Hellman key agreement.
//!
//! This implementation uses tiny integers, is not constant-time, and provides
//! no peer authentication. It must never protect real secrets.

use super::modular::{is_generator, is_prime, mod_pow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    prime: u64,
    generator: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffieHellmanError {
    InvalidPrime(u64),
    InvalidGenerator(u64),
    GeneratorDoesNotCoverGroup(u64),
    InvalidPrivateKey(u64),
    InvalidPeerPublicKey(u64),
}

impl Parameters {
    pub fn new(prime: u64, generator: u64) -> Result<Self, DiffieHellmanError> {
        if !is_prime(prime) {
            return Err(DiffieHellmanError::InvalidPrime(prime));
        }

        if generator <= 1 || generator >= prime {
            return Err(DiffieHellmanError::InvalidGenerator(generator));
        }

        if !is_generator(generator, prime) {
            return Err(DiffieHellmanError::GeneratorDoesNotCoverGroup(generator));
        }

        Ok(Self { prime, generator })
    }

    pub fn public_key(&self, private_key: u64) -> Result<u64, DiffieHellmanError> {
        self.validate_private_key(private_key)?;

        Ok(mod_pow(self.generator, private_key, self.prime))
    }

    pub fn shared_secret(
        &self,
        private_key: u64,
        peer_public_key: u64,
    ) -> Result<u64, DiffieHellmanError> {
        self.validate_private_key(private_key)?;

        if peer_public_key <= 1 || peer_public_key >= self.prime {
            return Err(DiffieHellmanError::InvalidPeerPublicKey(peer_public_key));
        }

        Ok(mod_pow(peer_public_key, private_key, self.prime))
    }

    fn validate_private_key(&self, private_key: u64) -> Result<(), DiffieHellmanError> {
        if private_key == 0 || private_key >= self.prime - 1 {
            return Err(DiffieHellmanError::InvalidPrivateKey(private_key));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DiffieHellmanError, Parameters};

    #[test]
    fn computes_the_worked_example() {
        let parameters = Parameters::new(23, 5).unwrap();

        let alice_public = parameters.public_key(6).unwrap();
        let bob_public = parameters.public_key(15).unwrap();

        assert_eq!(alice_public, 8);
        assert_eq!(bob_public, 19);

        let alice_shared = parameters.shared_secret(6, bob_public).unwrap();

        let bob_shared = parameters.shared_secret(15, alice_public).unwrap();

        assert_eq!(alice_shared, 2);
        assert_eq!(bob_shared, 2);
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn rejects_a_composite_modulus() {
        assert_eq!(
            Parameters::new(21, 2),
            Err(DiffieHellmanError::InvalidPrime(21))
        );
    }

    #[test]
    fn different_private_keys_produce_the_same_shared_secret() {
        let parameters = Parameters::new(23, 5).unwrap();

        for alice_private in 1..22 {
            for bob_private in 1..22 {
                let alice_public = parameters.public_key(alice_private).unwrap();

                let bob_public = parameters.public_key(bob_private).unwrap();

                let alice_shared = parameters.shared_secret(alice_private, bob_public).unwrap();

                let bob_shared = parameters.shared_secret(bob_private, alice_public).unwrap();

                assert_eq!(alice_shared, bob_shared);
            }
        }
    }

    #[test]
    fn rejects_invalid_private_keys() {
        let parameters = Parameters::new(23, 5).unwrap();

        assert_eq!(
            parameters.public_key(0),
            Err(DiffieHellmanError::InvalidPrivateKey(0))
        );

        assert_eq!(
            parameters.public_key(22),
            Err(DiffieHellmanError::InvalidPrivateKey(22))
        );
    }

    #[test]
    fn rejects_invalid_peer_public_keys() {
        let parameters = Parameters::new(23, 5).unwrap();

        assert_eq!(
            parameters.shared_secret(6, 1),
            Err(DiffieHellmanError::InvalidPeerPublicKey(1))
        );

        assert_eq!(
            parameters.shared_secret(6, 23),
            Err(DiffieHellmanError::InvalidPeerPublicKey(23))
        );
    }

    #[test]
    fn rejects_a_non_generator() {
        assert_eq!(
            Parameters::new(23, 4),
            Err(DiffieHellmanError::GeneratorDoesNotCoverGroup(4))
        );
    }

    #[test]
    fn unauthenticated_exchange_allows_a_man_in_the_middle() {
        let parameters = Parameters::new(23, 5).unwrap();

        let alice_private = 6;
        let bob_private = 15;

        let alice_public = parameters.public_key(alice_private).unwrap();

        let bob_public = parameters.public_key(bob_private).unwrap();

        // Mallory uses a different private key for each side.
        let mallory_private_for_alice = 7;
        let mallory_private_for_bob = 9;

        let mallory_public_for_alice = parameters.public_key(mallory_private_for_alice).unwrap();

        let mallory_public_for_bob = parameters.public_key(mallory_private_for_bob).unwrap();

        // Alice thinks this public key belongs to Bob.
        let alice_shared = parameters
            .shared_secret(alice_private, mallory_public_for_alice)
            .unwrap();

        let mallory_shared_with_alice = parameters
            .shared_secret(mallory_private_for_alice, alice_public)
            .unwrap();

        // Bob thinks this public key belongs to Alice.
        let bob_shared = parameters
            .shared_secret(bob_private, mallory_public_for_bob)
            .unwrap();

        let mallory_shared_with_bob = parameters
            .shared_secret(mallory_private_for_bob, bob_public)
            .unwrap();

        assert_eq!(alice_shared, 12);
        assert_eq!(mallory_shared_with_alice, 12);

        assert_eq!(bob_shared, 10);
        assert_eq!(mallory_shared_with_bob, 10);

        // Alice and Bob no longer share a secret with each other.
        assert_ne!(alice_shared, bob_shared);
    }
}
