//! Long-term Ed25519 identities for authenticating handshake transcripts.
//!
//! Signing keys are private and must never be transmitted or logged.
//! Verifying keys are public and can be pinned in peer configuration.

use std::{error::Error, fmt};

use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Signer, SigningKey, VerifyingKey,
};
use zeroize::Zeroize;

pub const IDENTITY_PUBLIC_KEY_LENGTH: usize = PUBLIC_KEY_LENGTH;
pub const IDENTITY_SIGNATURE_LENGTH: usize = SIGNATURE_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    InvalidPublicKey,
    InvalidSignature,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(formatter, "invalid Ed25519 public key"),
            Self::InvalidSignature => write!(formatter, "invalid Ed25519 signature"),
        }
    }
}

impl Error for IdentityError {}

pub struct IdentityKeyPair {
    signing_key: SigningKey,
}

impl IdentityKeyPair {
    /// Generates an identity during peer provisioning, not for every handshake.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut secret_bytes = [0_u8; 32];

        getrandom::fill(&mut secret_bytes)?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);

        // SigningKey owns its copy, so erase the temporary stack buffer.
        secret_bytes.zeroize();

        Ok(Self { signing_key })
    }

    pub fn public_key(&self) -> [u8; IDENTITY_PUBLIC_KEY_LENGTH] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; IDENTITY_SIGNATURE_LENGTH] {
        self.signing_key.sign(message).to_bytes()
    }
}

pub fn verify_signature(
    public_key: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
    message: &[u8],
    signature: [u8; IDENTITY_SIGNATURE_LENGTH],
) -> Result<(), IdentityError> {
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| IdentityError::InvalidPublicKey)?;

    let signature = Signature::from_bytes(&signature);

    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::{IdentityError, IdentityKeyPair, verify_signature};

    #[test]
    fn verifies_a_signature_from_the_expected_identity() {
        let identity = IdentityKeyPair::generate().unwrap();
        let message = b"handshake transcript";
        let signature = identity.sign(message);

        assert_eq!(
            verify_signature(identity.public_key(), message, signature),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_signature_for_modified_data() {
        let identity = IdentityKeyPair::generate().unwrap();
        let signature = identity.sign(b"original transcript");

        assert_eq!(
            verify_signature(identity.public_key(), b"modified transcript", signature),
            Err(IdentityError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_a_signature_from_another_identity() {
        let expected_peer = IdentityKeyPair::generate().unwrap();
        let attacker = IdentityKeyPair::generate().unwrap();
        let message = b"handshake transcript";

        let attacker_signature = attacker.sign(message);

        assert_eq!(
            verify_signature(expected_peer.public_key(), message, attacker_signature),
            Err(IdentityError::InvalidSignature)
        );
    }
}
