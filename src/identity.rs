//! Long-term Ed25519 identities for authenticating handshake transcripts.
//!
//! Signing keys are private and must never be transmitted or logged.
//! Verifying keys are public and can be pinned in peer configuration.

use std::{error::Error, fmt};

use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Signer, SigningKey,
    VerifyingKey,
};
use zeroize::Zeroize;

/// Number of bytes in a serialized Ed25519 verifying key.
pub const IDENTITY_PUBLIC_KEY_LENGTH: usize = PUBLIC_KEY_LENGTH;
/// Number of bytes in a serialized Ed25519 signature.
pub const IDENTITY_SIGNATURE_LENGTH: usize = SIGNATURE_LENGTH;
/// Number of bytes in the private Ed25519 seed stored on disk.
pub const IDENTITY_SECRET_KEY_LENGTH: usize = SECRET_KEY_LENGTH;

/// Failure while reconstructing or verifying a peer identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// The supplied bytes are not a valid Ed25519 verifying key.
    InvalidPublicKey,
    /// The signature does not authenticate the supplied message and key.
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

/// Long-term Ed25519 signing identity owned by one VPN peer.
///
/// `Debug` and `Clone` are intentionally omitted to reduce accidental secret
/// duplication or logging.
pub struct IdentityKeyPair {
    signing_key: SigningKey,
}

impl IdentityKeyPair {
    /// Generates an identity during peer provisioning, not for every handshake.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut secret_bytes = [0_u8; IDENTITY_SECRET_KEY_LENGTH];

        getrandom::fill(&mut secret_bytes)?;

        Ok(Self::from_secret_bytes(&mut secret_bytes))
    }

    /// Returns the public verifying key that the remote peer pins.
    pub fn public_key(&self) -> [u8; IDENTITY_PUBLIC_KEY_LENGTH] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Signs a role-specific handshake transcript digest.
    pub fn sign(&self, message: &[u8]) -> [u8; IDENTITY_SIGNATURE_LENGTH] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Reconstructs an identity and erases the caller-owned temporary buffer.
    pub fn from_secret_bytes(secret_bytes: &mut [u8; IDENTITY_SECRET_KEY_LENGTH]) -> Self {
        let signing_key = SigningKey::from_bytes(secret_bytes);

        // SigningKey owns its copy, so erase our temporary copy.
        secret_bytes.zeroize();

        Self { signing_key }
    }

    /// Copies the private seed for provisioning only. The caller must erase
    /// the returned buffer immediately after storing it securely.
    pub fn secret_key_bytes(&self) -> [u8; IDENTITY_SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }
}

/// Verifies an Ed25519 signature using a pinned peer public key.
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
    use super::{IDENTITY_SECRET_KEY_LENGTH, IdentityError, IdentityKeyPair, verify_signature};

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

    #[test]
    fn reconstructs_the_same_identity_from_the_same_secret() {
        let mut first_secret = [0x42; IDENTITY_SECRET_KEY_LENGTH];
        let mut second_secret = first_secret;

        let first = IdentityKeyPair::from_secret_bytes(&mut first_secret);
        let second = IdentityKeyPair::from_secret_bytes(&mut second_secret);

        assert_eq!(first_secret, [0_u8; IDENTITY_SECRET_KEY_LENGTH]);
        assert_eq!(second_secret, [0_u8; IDENTITY_SECRET_KEY_LENGTH]);
        assert_eq!(first.public_key(), second.public_key());

        let message = b"stable identity";
        let signature = first.sign(message);

        assert_eq!(
            verify_signature(second.public_key(), message, signature),
            Ok(())
        );
    }
}
