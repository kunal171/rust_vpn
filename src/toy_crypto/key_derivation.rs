//! Directional session-key derivation for handshake and learning experiments.
//!
//! The VPN supplies X25519 shared secret material from its authenticated
//! handshake. Tests may also use the hand-written Diffie-Hellman exercise,
//! which is educational and must not protect real traffic.

use hkdf::{Hkdf, InvalidLength};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ChaCha20-Poly1305 accepts a 256-bit (32-byte) key.
pub const SESSION_KEY_LENGTH: usize = 32;

// Distinct HKDF `info` labels provide domain separation: even with identical
// input material, the two traffic directions cannot derive the same key.
const CLIENT_TO_SERVER_INFO: &[u8] = b"rust_vpn phase8 client-to-server";

const SERVER_TO_CLIENT_INFO: &[u8] = b"rust_vpn phase8 server-to-client";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Selects which directional key a local endpoint sends and receives with.
pub enum SessionRole {
    Client,
    Server,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
/// The two independent traffic keys belonging to one session.
///
/// `Debug` is intentionally not derived, which reduces accidental key logging.
/// The key bytes are overwritten when the value is explicitly zeroized or dropped.
pub struct SessionKeys {
    client_to_server: [u8; SESSION_KEY_LENGTH],
    server_to_client: [u8; SESSION_KEY_LENGTH],
}

impl SessionKeys {
    /// Returns the key used for packets travelling from client to server.
    pub fn client_to_server(&self) -> &[u8; SESSION_KEY_LENGTH] {
        &self.client_to_server
    }

    /// Returns the key used for packets travelling from server to client.
    pub fn server_to_client(&self) -> &[u8; SESSION_KEY_LENGTH] {
        &self.server_to_client
    }

    /// Chooses the key this local role must use to send a packet.
    pub fn send_key(&self, role: SessionRole) -> &[u8; SESSION_KEY_LENGTH] {
        match role {
            SessionRole::Client => &self.client_to_server,
            SessionRole::Server => &self.server_to_client,
        }
    }

    /// Chooses the key this local role must use to receive a packet.
    pub fn receive_key(&self, role: SessionRole) -> &[u8; SESSION_KEY_LENGTH] {
        match role {
            SessionRole::Client => &self.server_to_client,
            SessionRole::Server => &self.client_to_server,
        }
    }
}

/// Derives two directional traffic keys from shared input key material.
///
/// The salt should identify the session and must be the same at both peers.
/// HKDF first extracts uniform pseudorandom key material, then expands it using
/// separate labels so the traffic directions remain cryptographically separate.
pub fn derive_session_keys(
    shared_secret: &[u8],
    salt: &[u8],
) -> Result<SessionKeys, InvalidLength> {
    // Extract the possibly uneven Diffie-Hellman bytes into HKDF's pseudorandom key.
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);

    let mut client_to_server = [0_u8; SESSION_KEY_LENGTH];

    // Expand once per direction with different context labels.
    hkdf.expand(CLIENT_TO_SERVER_INFO, &mut client_to_server)?;

    let mut server_to_client = [0_u8; SESSION_KEY_LENGTH];

    hkdf.expand(SERVER_TO_CLIENT_INFO, &mut server_to_client)?;

    Ok(SessionKeys {
        client_to_server,
        server_to_client,
    })
}

#[cfg(test)]
mod tests {
    use super::{SESSION_KEY_LENGTH, SessionKeys, SessionRole, derive_session_keys};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    const SALT: &[u8] = b"phase-8-test-session";

    #[test]
    fn both_peers_derive_the_same_directional_keys() {
        let shared_secret = 2_u64.to_be_bytes();

        let alice = derive_session_keys(&shared_secret, SALT).unwrap();

        let bob = derive_session_keys(&shared_secret, SALT).unwrap();

        assert_eq!(alice.client_to_server(), bob.client_to_server());

        assert_eq!(alice.server_to_client(), bob.server_to_client());
    }

    #[test]
    fn derives_different_keys_for_each_direction() {
        let shared_secret = 2_u64.to_be_bytes();

        let keys = derive_session_keys(&shared_secret, SALT).unwrap();

        assert_ne!(keys.client_to_server(), keys.server_to_client());
    }

    #[test]
    fn changing_the_shared_secret_changes_the_keys() {
        let first_secret = 2_u64.to_be_bytes();
        let second_secret = 3_u64.to_be_bytes();

        let first = derive_session_keys(&first_secret, SALT).unwrap();

        let second = derive_session_keys(&second_secret, SALT).unwrap();

        assert_ne!(first.client_to_server(), second.client_to_server());
    }

    #[test]
    fn changing_the_salt_changes_the_keys() {
        let shared_secret = 2_u64.to_be_bytes();

        let first = derive_session_keys(&shared_secret, b"session-one").unwrap();

        let second = derive_session_keys(&shared_secret, b"session-two").unwrap();

        assert_ne!(first.client_to_server(), second.client_to_server());
    }

    #[test]
    fn client_send_key_matches_server_receive_key() {
        let shared_secret = 2_u64.to_be_bytes();
        let keys = derive_session_keys(&shared_secret, SALT).unwrap();

        assert_eq!(
            keys.send_key(SessionRole::Client),
            keys.receive_key(SessionRole::Server),
        );
    }

    #[test]
    fn server_send_key_matches_client_receive_key() {
        let shared_secret = 2_u64.to_be_bytes();
        let keys = derive_session_keys(&shared_secret, SALT).unwrap();

        assert_eq!(
            keys.send_key(SessionRole::Server),
            keys.receive_key(SessionRole::Client),
        );
    }

    #[test]
    fn each_role_uses_different_keys_for_sending_and_receiving() {
        let shared_secret = 2_u64.to_be_bytes();
        let keys = derive_session_keys(&shared_secret, SALT).unwrap();

        assert_ne!(
            keys.send_key(SessionRole::Client),
            keys.receive_key(SessionRole::Client),
        );
        assert_ne!(
            keys.send_key(SessionRole::Server),
            keys.receive_key(SessionRole::Server),
        );
    }

    #[test]
    fn zeroize_erases_both_directional_keys() {
        let shared_secret = 2_u64.to_be_bytes();
        let mut keys = derive_session_keys(&shared_secret, SALT).unwrap();

        keys.zeroize();

        assert_eq!(keys.client_to_server(), &[0_u8; SESSION_KEY_LENGTH],);
        assert_eq!(keys.server_to_client(), &[0_u8; SESSION_KEY_LENGTH],);
    }

    #[test]
    fn session_keys_are_zeroized_on_drop() {
        fn requires_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        requires_zeroize_on_drop::<SessionKeys>();
    }
}
