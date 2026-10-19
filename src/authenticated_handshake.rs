//! In-memory authenticated handshake state.
//!
//! This module connects ephemeral X25519 key agreement, long-term Ed25519
//! identities, transcript binding, and HKDF session-key derivation. Network
//! transport stays outside this layer so state transitions can be unit-tested.

use std::{error::Error, fmt};

use hkdf::InvalidLength;

use crate::{
    handshake::{ClientAuth, ClientHello, HandshakeTranscript, ServerHello},
    identity::{IDENTITY_PUBLIC_KEY_LENGTH, IdentityError, IdentityKeyPair, verify_signature},
    key_exchange::{EphemeralKeyExchange, KeyExchangeError, PUBLIC_KEY_LENGTH},
    toy_crypto::key_derivation::{SessionKeys, derive_session_keys},
};

/// Authenticated session information produced independently by each peer.
///
/// `Debug` is intentionally omitted because this value owns secret keys.
pub struct HandshakeResult {
    session_id: u32,
    session_keys: SessionKeys,
}

impl HandshakeResult {
    /// Returns the server-assigned identifier bound into the transcript.
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Borrows the directional traffic keys without exposing them in logs.
    pub fn session_keys(&self) -> &SessionKeys {
        &self.session_keys
    }

    /// Consumes the result so its identifier and keys can enter a session.
    pub fn into_parts(self) -> (u32, SessionKeys) {
        (self.session_id, self.session_keys)
    }
}

/// Client state waiting for an authenticated ServerHello.
///
/// Completion consumes this value, preventing ephemeral-key reuse.
pub struct ClientHandshake {
    key_exchange: EphemeralKeyExchange,
    ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl ClientHandshake {
    /// Generates the client ephemeral key and its first handshake message.
    pub fn start() -> (Self, ClientHello) {
        let key_exchange = EphemeralKeyExchange::generate();
        let ephemeral_public_key = key_exchange.public_key();
        let hello = ClientHello::new(ephemeral_public_key);

        (
            Self {
                key_exchange,
                ephemeral_public_key,
            },
            hello,
        )
    }

    /// Verifies the server, derives keys, and creates the client identity proof.
    pub fn complete(
        self,
        session_id: u32,
        server_hello: ServerHello,
        client_identity: &IdentityKeyPair,
        expected_server_identity: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
    ) -> Result<(ClientAuth, HandshakeResult), AuthenticatedHandshakeError> {
        let server_ephemeral_public = server_hello.ephemeral_public_key();
        let transcript = HandshakeTranscript::new(
            session_id,
            self.ephemeral_public_key,
            server_ephemeral_public,
        );
        let transcript_hash = transcript.hash();

        verify_signature(
            expected_server_identity,
            &transcript.server_authentication_hash(),
            server_hello.signature(),
        )?;

        let shared_secret = self.key_exchange.complete(server_ephemeral_public)?;
        let session_keys = derive_session_keys(shared_secret.as_bytes(), &transcript_hash)?;
        let client_signature = client_identity.sign(&transcript.client_authentication_hash());

        Ok((
            ClientAuth::new(client_signature),
            HandshakeResult {
                session_id,
                session_keys,
            },
        ))
    }
}

/// Server state waiting for the client's identity proof.
///
/// Derived keys remain private until client authentication succeeds.
pub struct ServerHandshake {
    transcript: HandshakeTranscript,
    result: HandshakeResult,
}

impl ServerHandshake {
    /// Processes ClientHello and creates the authenticated server response.
    pub fn respond(
        client_hello: ClientHello,
        session_id: u32,
        server_identity: &IdentityKeyPair,
    ) -> Result<(Self, ServerHello), AuthenticatedHandshakeError> {
        let client_ephemeral_public = client_hello.ephemeral_public_key();
        let key_exchange = EphemeralKeyExchange::generate();
        let server_ephemeral_public = key_exchange.public_key();
        let transcript =
            HandshakeTranscript::new(session_id, client_ephemeral_public, server_ephemeral_public);
        let transcript_hash = transcript.hash();

        // Validate the peer's X25519 input before signing or retaining state.
        let shared_secret = key_exchange.complete(client_ephemeral_public)?;
        let session_keys = derive_session_keys(shared_secret.as_bytes(), &transcript_hash)?;
        let server_signature = server_identity.sign(&transcript.server_authentication_hash());
        let server_hello = ServerHello::new(server_ephemeral_public, server_signature);

        let state = Self {
            transcript,
            result: HandshakeResult {
                session_id,
                session_keys,
            },
        };

        Ok((state, server_hello))
    }

    /// Releases the negotiated session only after verifying the client.
    pub fn complete(
        self,
        client_auth: ClientAuth,
        expected_client_identity: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
    ) -> Result<HandshakeResult, AuthenticatedHandshakeError> {
        verify_signature(
            expected_client_identity,
            &self.transcript.client_authentication_hash(),
            client_auth.signature(),
        )?;

        Ok(self.result)
    }
}

/// Failures that prevent a session from being installed.
#[derive(Debug)]
pub enum AuthenticatedHandshakeError {
    /// A pinned Ed25519 identity or signature was invalid.
    Identity(IdentityError),
    /// The peer supplied an unusable X25519 public key.
    KeyExchange(KeyExchangeError),
    /// HKDF could not produce the required directional keys.
    KeyDerivation(InvalidLength),
}

impl fmt::Display for AuthenticatedHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => write!(formatter, "peer authentication failed: {error}"),
            Self::KeyExchange(error) => write!(formatter, "key exchange failed: {error}"),
            Self::KeyDerivation(error) => {
                write!(formatter, "session-key derivation failed: {error}")
            }
        }
    }
}

impl Error for AuthenticatedHandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::KeyExchange(error) => Some(error),
            Self::KeyDerivation(error) => Some(error),
        }
    }
}

impl From<IdentityError> for AuthenticatedHandshakeError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl From<KeyExchangeError> for AuthenticatedHandshakeError {
    fn from(error: KeyExchangeError) -> Self {
        Self::KeyExchange(error)
    }
}

impl From<InvalidLength> for AuthenticatedHandshakeError {
    fn from(error: InvalidLength) -> Self {
        Self::KeyDerivation(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthenticatedHandshakeError, ClientHandshake, ServerHandshake};
    use crate::{
        handshake::{ClientAuth, ClientHello, ServerHello},
        identity::{IDENTITY_SIGNATURE_LENGTH, IdentityError, IdentityKeyPair},
        key_exchange::{KeyExchangeError, PUBLIC_KEY_LENGTH},
    };

    const SESSION_ID: u32 = 0x0102_0304;

    #[test]
    fn authenticated_peers_derive_identical_directional_keys() {
        let client_identity = IdentityKeyPair::generate().unwrap();
        let server_identity = IdentityKeyPair::generate().unwrap();
        let (client, client_hello) = ClientHandshake::start();
        let (server, server_hello) =
            ServerHandshake::respond(client_hello, SESSION_ID, &server_identity).unwrap();
        let (client_auth, client_result) = client
            .complete(
                SESSION_ID,
                server_hello,
                &client_identity,
                server_identity.public_key(),
            )
            .unwrap();
        let server_result = server
            .complete(client_auth, client_identity.public_key())
            .unwrap();

        assert_eq!(client_result.session_id(), SESSION_ID);
        assert_eq!(server_result.session_id(), SESSION_ID);
        assert_eq!(
            client_result.session_keys().client_to_server(),
            server_result.session_keys().client_to_server()
        );
        assert_eq!(
            client_result.session_keys().server_to_client(),
            server_result.session_keys().server_to_client()
        );
        assert_ne!(
            client_result.session_keys().client_to_server(),
            client_result.session_keys().server_to_client()
        );
    }

    #[test]
    fn client_rejects_the_wrong_server_identity() {
        let client_identity = IdentityKeyPair::generate().unwrap();
        let server_identity = IdentityKeyPair::generate().unwrap();
        let attacker_identity = IdentityKeyPair::generate().unwrap();
        let (client, client_hello) = ClientHandshake::start();
        let (_server, server_hello) =
            ServerHandshake::respond(client_hello, SESSION_ID, &server_identity).unwrap();

        let result = client.complete(
            SESSION_ID,
            server_hello,
            &client_identity,
            attacker_identity.public_key(),
        );

        assert!(matches!(
            result,
            Err(AuthenticatedHandshakeError::Identity(
                IdentityError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn client_rejects_a_modified_server_signature() {
        let client_identity = IdentityKeyPair::generate().unwrap();
        let server_identity = IdentityKeyPair::generate().unwrap();
        let (client, client_hello) = ClientHandshake::start();
        let (_server, server_hello) =
            ServerHandshake::respond(client_hello, SESSION_ID, &server_identity).unwrap();
        let mut signature = server_hello.signature();
        signature[0] ^= 1;
        let modified_hello = ServerHello::new(server_hello.ephemeral_public_key(), signature);

        let result = client.complete(
            SESSION_ID,
            modified_hello,
            &client_identity,
            server_identity.public_key(),
        );

        assert!(matches!(
            result,
            Err(AuthenticatedHandshakeError::Identity(
                IdentityError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn server_rejects_the_wrong_client_identity() {
        let client_identity = IdentityKeyPair::generate().unwrap();
        let server_identity = IdentityKeyPair::generate().unwrap();
        let attacker_identity = IdentityKeyPair::generate().unwrap();
        let (client, client_hello) = ClientHandshake::start();
        let (server, server_hello) =
            ServerHandshake::respond(client_hello, SESSION_ID, &server_identity).unwrap();
        let (client_auth, _client_result) = client
            .complete(
                SESSION_ID,
                server_hello,
                &client_identity,
                server_identity.public_key(),
            )
            .unwrap();

        let result = server.complete(client_auth, attacker_identity.public_key());

        assert!(matches!(
            result,
            Err(AuthenticatedHandshakeError::Identity(
                IdentityError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn server_rejects_a_modified_client_signature() {
        let client_identity = IdentityKeyPair::generate().unwrap();
        let server_identity = IdentityKeyPair::generate().unwrap();
        let (client, client_hello) = ClientHandshake::start();
        let (server, server_hello) =
            ServerHandshake::respond(client_hello, SESSION_ID, &server_identity).unwrap();
        let (client_auth, _client_result) = client
            .complete(
                SESSION_ID,
                server_hello,
                &client_identity,
                server_identity.public_key(),
            )
            .unwrap();
        let mut signature = client_auth.signature();
        signature[IDENTITY_SIGNATURE_LENGTH - 1] ^= 1;

        let result = server.complete(ClientAuth::new(signature), client_identity.public_key());

        assert!(matches!(
            result,
            Err(AuthenticatedHandshakeError::Identity(
                IdentityError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn client_rejects_a_server_hello_under_a_different_session_id() {
        let client_identity = IdentityKeyPair::generate().unwrap();
        let server_identity = IdentityKeyPair::generate().unwrap();
        let (client, client_hello) = ClientHandshake::start();
        let (_server, server_hello) =
            ServerHandshake::respond(client_hello, SESSION_ID, &server_identity).unwrap();

        let result = client.complete(
            SESSION_ID + 1,
            server_hello,
            &client_identity,
            server_identity.public_key(),
        );

        assert!(matches!(
            result,
            Err(AuthenticatedHandshakeError::Identity(
                IdentityError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn server_rejects_a_non_contributory_client_key() {
        let server_identity = IdentityKeyPair::generate().unwrap();
        let invalid_hello = ClientHello::new([0_u8; PUBLIC_KEY_LENGTH]);

        let result = ServerHandshake::respond(invalid_hello, SESSION_ID, &server_identity);

        assert!(matches!(
            result,
            Err(AuthenticatedHandshakeError::KeyExchange(
                KeyExchangeError::NonContributoryPublicKey
            ))
        ));
    }
}
