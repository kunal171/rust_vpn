//! Canonical transcript construction for the authenticated handshake.
//!
//! Both peers must construct identical transcript bytes. Identity signatures
//! authenticate the transcript hash and bind the ephemeral keys to the pinned
//! peer identities.

use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

use crate::identity::IDENTITY_SIGNATURE_LENGTH;
use crate::key_exchange::PUBLIC_KEY_LENGTH;

/// Prevents a signature from being valid in another protocol or context.
const TRANSCRIPT_DOMAIN: &[u8] = b"rust_vpn authenticated handshake v1";

const SERVER_AUTH_DOMAIN: &[u8] = b"rust_vpn server authentication v1";

const CLIENT_AUTH_DOMAIN: &[u8] = b"rust_vpn client authentication v1";

pub const CLIENT_HELLO_LENGTH: usize = PUBLIC_KEY_LENGTH;
pub const SERVER_HELLO_LENGTH: usize = PUBLIC_KEY_LENGTH + IDENTITY_SIGNATURE_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeTranscript {
    session_id: u32,
    client_ephemeral_public: [u8; PUBLIC_KEY_LENGTH],
    server_ephemeral_public: [u8; PUBLIC_KEY_LENGTH],
}

pub const CLIENT_AUTH_LENGTH: usize = IDENTITY_SIGNATURE_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAuth {
    signature: [u8; IDENTITY_SIGNATURE_LENGTH],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello {
    ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],
    signature: [u8; IDENTITY_SIGNATURE_LENGTH],
}

/// Errors produced while decoding peer-controlled handshake messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// A ClientHello must contain exactly one 32-byte X25519 public key.
    InvalidClientHelloLength {
        expected: usize,
        actual: usize,
    },
    InvalidClientAuthLength {
        expected: usize,
        actual: usize,
    },
    InvalidServerHelloLength {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClientHelloLength { expected, actual } => write!(
                formatter,
                "ClientHello contains {actual} bytes, but exactly {expected} are required"
            ),
            Self::InvalidClientAuthLength { expected, actual } => write!(
                formatter,
                "ClientAuth contains {actual} bytes, but exactly {expected} are required"
            ),
            Self::InvalidServerHelloLength { expected, actual } => write!(
                formatter,
                "ServerHello contains {actual} bytes, but exactly {expected} are required"
            ),
        }
    }
}

impl Error for HandshakeError {}

impl HandshakeTranscript {
    pub const fn new(
        session_id: u32,
        client_ephemeral_public: [u8; PUBLIC_KEY_LENGTH],
        server_ephemeral_public: [u8; PUBLIC_KEY_LENGTH],
    ) -> Self {
        Self {
            session_id,
            client_ephemeral_public,
            server_ephemeral_public,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(TRANSCRIPT_DOMAIN);
        hasher.update(self.session_id.to_be_bytes());

        // The role-defined order is essential. Sorting the keys would lose
        // information about which peer supplied which public key.
        hasher.update(self.client_ephemeral_public);
        hasher.update(self.server_ephemeral_public);

        hasher.finalize().into()
    }

    pub fn server_authentication_hash(&self) -> [u8; 32] {
        self.authentication_hash(SERVER_AUTH_DOMAIN)
    }

    pub fn client_authentication_hash(&self) -> [u8; 32] {
        self.authentication_hash(CLIENT_AUTH_DOMAIN)
    }

    fn authentication_hash(&self, domain: &[u8]) -> [u8; 32] {
        let transcript_hash = self.hash();
        let mut hasher = Sha256::new();

        hasher.update(domain);
        hasher.update(transcript_hash);

        hasher.finalize().into()
    }
}

impl ClientHello {
    pub const fn new(ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self {
            ephemeral_public_key,
        }
    }

    pub const fn ephemeral_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.ephemeral_public_key
    }

    pub const fn encode(&self) -> [u8; CLIENT_HELLO_LENGTH] {
        self.ephemeral_public_key
    }

    /// Decodes an untrusted ClientHello payload.
    ///
    /// Requiring the exact length rejects both truncated keys and unexpected
    /// trailing bytes before the public key is used by X25519.
    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.len() != CLIENT_HELLO_LENGTH {
            return Err(HandshakeError::InvalidClientHelloLength {
                expected: CLIENT_HELLO_LENGTH,
                actual: bytes.len(),
            });
        }

        let mut ephemeral_public_key = [0_u8; PUBLIC_KEY_LENGTH];
        ephemeral_public_key.copy_from_slice(bytes);

        Ok(Self::new(ephemeral_public_key))
    }
}

impl ServerHello {
    pub const fn new(
        ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],
        signature: [u8; IDENTITY_SIGNATURE_LENGTH],
    ) -> Self {
        Self {
            ephemeral_public_key,
            signature,
        }
    }

    pub const fn ephemeral_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.ephemeral_public_key
    }

    pub const fn signature(&self) -> [u8; IDENTITY_SIGNATURE_LENGTH] {
        self.signature
    }

    pub fn encode(&self) -> [u8; SERVER_HELLO_LENGTH] {
        let mut bytes = [0_u8; SERVER_HELLO_LENGTH];

        bytes[..PUBLIC_KEY_LENGTH].copy_from_slice(&self.ephemeral_public_key);

        bytes[PUBLIC_KEY_LENGTH..].copy_from_slice(&self.signature);

        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.len() != SERVER_HELLO_LENGTH {
            return Err(HandshakeError::InvalidServerHelloLength {
                expected: SERVER_HELLO_LENGTH,
                actual: bytes.len(),
            });
        }

        let mut ephemeral_public_key = [0_u8; PUBLIC_KEY_LENGTH];
        ephemeral_public_key.copy_from_slice(&bytes[..PUBLIC_KEY_LENGTH]);

        let mut signature = [0_u8; IDENTITY_SIGNATURE_LENGTH];
        signature.copy_from_slice(&bytes[PUBLIC_KEY_LENGTH..]);

        Ok(Self::new(ephemeral_public_key, signature))
    }
}

impl ClientAuth {
    pub const fn new(signature: [u8; IDENTITY_SIGNATURE_LENGTH]) -> Self {
        Self { signature }
    }

    pub const fn signature(&self) -> [u8; IDENTITY_SIGNATURE_LENGTH] {
        self.signature
    }

    pub const fn encode(&self) -> [u8; CLIENT_AUTH_LENGTH] {
        self.signature
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HandshakeError> {
        if bytes.len() != CLIENT_AUTH_LENGTH {
            return Err(HandshakeError::InvalidClientAuthLength {
                expected: CLIENT_AUTH_LENGTH,
                actual: bytes.len(),
            });
        }

        let mut signature = [0_u8; IDENTITY_SIGNATURE_LENGTH];
        signature.copy_from_slice(bytes);

        Ok(Self::new(signature))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CLIENT_AUTH_LENGTH, CLIENT_HELLO_LENGTH, ClientAuth, ClientHello, HandshakeError,
        HandshakeTranscript, SERVER_HELLO_LENGTH, ServerHello,
    };
    use crate::identity::IDENTITY_SIGNATURE_LENGTH;
    use crate::key_exchange::PUBLIC_KEY_LENGTH;

    #[test]
    fn identical_inputs_produce_identical_hashes() {
        let first = HandshakeTranscript::new(7, [1; 32], [2; 32]);
        let second = HandshakeTranscript::new(7, [1; 32], [2; 32]);

        assert_eq!(first.hash(), second.hash());
    }

    #[test]
    fn changing_the_session_id_changes_the_hash() {
        let first = HandshakeTranscript::new(7, [1; 32], [2; 32]);
        let second = HandshakeTranscript::new(8, [1; 32], [2; 32]);

        assert_ne!(first.hash(), second.hash());
    }

    #[test]
    fn swapping_client_and_server_keys_changes_the_hash() {
        let original = HandshakeTranscript::new(7, [1; 32], [2; 32]);
        let swapped = HandshakeTranscript::new(7, [2; 32], [1; 32]);

        assert_ne!(original.hash(), swapped.hash());
    }

    #[test]
    fn encodes_a_32_byte_ephemeral_public_key() {
        let key = [0x42; CLIENT_HELLO_LENGTH];
        let hello = ClientHello::new(key);

        assert_eq!(hello.encode(), key);
        assert_eq!(hello.encode().len(), CLIENT_HELLO_LENGTH);
    }

    #[test]
    fn client_hello_round_trip_preserves_the_public_key() {
        let key = [0xa5; CLIENT_HELLO_LENGTH];
        let encoded = ClientHello::new(key).encode();

        let decoded = ClientHello::decode(&encoded).unwrap();

        assert_eq!(decoded.ephemeral_public_key(), key);
    }

    #[test]
    fn rejects_a_truncated_client_hello() {
        let bytes = [0_u8; CLIENT_HELLO_LENGTH - 1];

        assert_eq!(
            ClientHello::decode(&bytes),
            Err(HandshakeError::InvalidClientHelloLength {
                expected: CLIENT_HELLO_LENGTH,
                actual: CLIENT_HELLO_LENGTH - 1,
            })
        );
    }

    #[test]
    fn rejects_a_client_hello_with_trailing_data() {
        let bytes = [0_u8; CLIENT_HELLO_LENGTH + 1];

        assert_eq!(
            ClientHello::decode(&bytes),
            Err(HandshakeError::InvalidClientHelloLength {
                expected: CLIENT_HELLO_LENGTH,
                actual: CLIENT_HELLO_LENGTH + 1,
            })
        );
    }

    #[test]
    fn client_hello_preserves_binary_bytes() {
        let mut key = [0x55; CLIENT_HELLO_LENGTH];
        key[0] = 0x00;
        key[CLIENT_HELLO_LENGTH - 1] = 0xff;

        let decoded = ClientHello::decode(&ClientHello::new(key).encode()).unwrap();

        assert_eq!(decoded.ephemeral_public_key()[0], 0x00);
        assert_eq!(
            decoded.ephemeral_public_key()[CLIENT_HELLO_LENGTH - 1],
            0xff
        );
        assert_eq!(decoded.ephemeral_public_key(), key);
    }

    #[test]
    fn client_auth_round_trip_preserves_the_signature() {
        let signature = [0xa5; CLIENT_AUTH_LENGTH];
        let encoded = ClientAuth::new(signature).encode();

        let decoded = ClientAuth::decode(&encoded).unwrap();

        assert_eq!(decoded.signature(), signature);
    }

    #[test]
    fn rejects_a_truncated_client_auth() {
        let bytes = [0_u8; CLIENT_AUTH_LENGTH - 1];

        assert_eq!(
            ClientAuth::decode(&bytes),
            Err(HandshakeError::InvalidClientAuthLength {
                expected: CLIENT_AUTH_LENGTH,
                actual: CLIENT_AUTH_LENGTH - 1,
            })
        );
    }

    #[test]
    fn rejects_client_auth_with_trailing_data() {
        let bytes = [0_u8; CLIENT_AUTH_LENGTH + 1];

        assert_eq!(
            ClientAuth::decode(&bytes),
            Err(HandshakeError::InvalidClientAuthLength {
                expected: CLIENT_AUTH_LENGTH,
                actual: CLIENT_AUTH_LENGTH + 1,
            })
        );
    }

    #[test]
    fn client_auth_preserves_binary_signature_bytes() {
        let mut signature = [0x55; CLIENT_AUTH_LENGTH];

        signature[0] = 0x00;
        signature[CLIENT_AUTH_LENGTH - 1] = 0xff;

        let encoded = ClientAuth::new(signature).encode();
        let decoded = ClientAuth::decode(&encoded).unwrap();

        assert_eq!(decoded.signature()[0], 0x00);
        assert_eq!(decoded.signature()[CLIENT_AUTH_LENGTH - 1], 0xff);
        assert_eq!(decoded.signature(), signature);
    }

    #[test]
    fn server_hello_round_trip_preserves_all_fields() {
        let public_key = [0x42; PUBLIC_KEY_LENGTH];
        let signature = [0xa5; IDENTITY_SIGNATURE_LENGTH];

        let encoded = ServerHello::new(public_key, signature).encode();

        assert_eq!(encoded.len(), SERVER_HELLO_LENGTH);

        let decoded = ServerHello::decode(&encoded).unwrap();

        assert_eq!(decoded.ephemeral_public_key(), public_key);
        assert_eq!(decoded.signature(), signature);
    }

    #[test]
    fn client_and_server_authentication_hashes_differ() {
        let transcript =
            HandshakeTranscript::new(7, [1; PUBLIC_KEY_LENGTH], [2; PUBLIC_KEY_LENGTH]);

        assert_ne!(
            transcript.client_authentication_hash(),
            transcript.server_authentication_hash()
        );
    }
}
