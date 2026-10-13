//! Session-key derivation for the cryptography learning phase.
//!
//! HKDF-SHA256 is a real cryptographic primitive, but the toy Diffie-Hellman
//! secret used by the current experiments is not secure.

use hkdf::{Hkdf, InvalidLength};
use sha2::Sha256;

pub const SESSION_KEY_LENGTH: usize = 32;

const CLIENT_TO_SERVER_INFO: &[u8] = b"rust_vpn phase8 client-to-server";

const SERVER_TO_CLIENT_INFO: &[u8] = b"rust_vpn phase8 server-to-client";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Client,
    Server,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    client_to_server: [u8; SESSION_KEY_LENGTH],
    server_to_client: [u8; SESSION_KEY_LENGTH],
}

impl SessionKeys {
    pub fn client_to_server(&self) -> &[u8; SESSION_KEY_LENGTH] {
        &self.client_to_server
    }

    pub fn server_to_client(&self) -> &[u8; SESSION_KEY_LENGTH] {
        &self.server_to_client
    }

    pub fn send_key(&self, role: SessionRole) -> &[u8; SESSION_KEY_LENGTH] {
        match role {
            SessionRole::Client => &self.client_to_server,
            SessionRole::Server => &self.server_to_client,
        }
    }

    pub fn receive_key(&self, role: SessionRole) -> &[u8; SESSION_KEY_LENGTH] {
        match role {
            SessionRole::Client => &self.server_to_client,
            SessionRole::Server => &self.client_to_server,
        }
    }
}

pub fn derive_session_keys(
    shared_secret: &[u8],
    salt: &[u8],
) -> Result<SessionKeys, InvalidLength> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);

    let mut client_to_server = [0_u8; SESSION_KEY_LENGTH];

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
    use super::{SessionRole, derive_session_keys};

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
}
