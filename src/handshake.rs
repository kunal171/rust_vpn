//! Canonical transcript construction for the authenticated handshake.
//!
//! Both peers must construct identical transcript bytes. Identity signatures
//! will later authenticate the transcript hash.

use sha2::{Digest, Sha256};

use crate::key_exchange::PUBLIC_KEY_LENGTH;

/// Prevents a signature from being valid in another protocol or context.
const TRANSCRIPT_DOMAIN: &[u8] = b"rust_vpn authenticated handshake v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeTranscript {
    session_id: u32,
    client_ephemeral_public: [u8; PUBLIC_KEY_LENGTH],
    server_ephemeral_public: [u8; PUBLIC_KEY_LENGTH],
}

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
}

#[cfg(test)]
mod tests {
    use super::HandshakeTranscript;

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
}
