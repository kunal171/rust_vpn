//! Authenticated packet encryption for the cryptography learning phase.
//!
//! The frame header remains visible so a receiver can route and parse a packet,
//! but it is supplied as associated data and therefore cannot be modified
//! without authentication failing. Only the frame payload is encrypted.
//!
//! Each directional key requires a unique nonce for every packet. This module
//! derives that nonce from the monotonically increasing packet counter.
use std::{error::Error, fmt};

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use super::replay_window::{ReplayError, ReplayWindow};
use crate::protocol::{Frame, MAX_PAYLOAD_SIZE, ProtocolError, encode_frame_header};

/// Nonce size required by ChaCha20-Poly1305.
pub const NONCE_LENGTH: usize = 12;
/// Extra bytes appended by ChaCha20-Poly1305 to authenticate a ciphertext.
pub const AUTHENTICATION_TAG_LENGTH: usize = 16;
/// Largest plaintext that still fits after its authentication tag is appended.
pub const MAX_PLAINTEXT_SIZE: usize = MAX_PAYLOAD_SIZE - AUTHENTICATION_TAG_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Failures while protecting, authenticating, or replay-checking a frame.
pub enum PacketCryptoError {
    PlaintextTooLarge { actual: usize, maximum: usize },
    InvalidFrame(ProtocolError),
    EncryptionFailed,
    AuthenticationFailed,
    ReplayRejected(ReplayError),
}

impl fmt::Display for PacketCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "plaintext contains {actual} bytes, but the maximum is {maximum}"
                )
            }
            Self::InvalidFrame(error) => {
                write!(formatter, "invalid frame: {error}")
            }
            Self::EncryptionFailed => {
                write!(formatter, "packet encryption failed")
            }
            Self::AuthenticationFailed => {
                write!(formatter, "packet authentication failed")
            }
            Self::ReplayRejected(error) => {
                write!(formatter, "packet rejected by replay protection: {error}")
            }
        }
    }
}

impl Error for PacketCryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidFrame(error) => Some(error),
            Self::ReplayRejected(error) => Some(error),
            Self::PlaintextTooLarge { .. }
            | Self::EncryptionFailed
            | Self::AuthenticationFailed => None,
        }
    }
}

impl From<ProtocolError> for PacketCryptoError {
    fn from(error: ProtocolError) -> Self {
        Self::InvalidFrame(error)
    }
}

/// Encrypts a frame payload and authenticates its encoded header.
///
/// The returned frame has the same routing fields and counter, but its payload
/// contains `ciphertext || authentication_tag`.
pub fn protect_frame(frame: &Frame, key: &[u8; 32]) -> Result<Frame, PacketCryptoError> {
    let plaintext_length = frame.payload().len();

    if plaintext_length > MAX_PLAINTEXT_SIZE {
        return Err(PacketCryptoError::PlaintextTooLarge {
            actual: plaintext_length,
            maximum: MAX_PLAINTEXT_SIZE,
        });
    }

    // Payload length is part of the authenticated header, so construct the
    // header with the final ciphertext length before performing encryption.
    let encrypted_length = plaintext_length + AUTHENTICATION_TAG_LENGTH;

    let header = encode_frame_header(
        frame.message_type(),
        frame.session_id(),
        frame.counter(),
        encrypted_length,
    )?;

    // Associated data is authenticated but is not included in the ciphertext.
    let ciphertext = encrypt_packet(key, frame.counter(), frame.payload(), &header)
        .map_err(|_| PacketCryptoError::EncryptionFailed)?;

    Frame::new(
        frame.message_type(),
        frame.session_id(),
        frame.counter(),
        ciphertext,
    )
    .map_err(Into::into)
}

/// Authenticates and decrypts a protected frame.
///
/// Re-encoding the received fields reconstructs the exact associated data used
/// by the sender. Any changed field therefore makes decryption fail.
pub fn unprotect_frame(frame: &Frame, key: &[u8; 32]) -> Result<Frame, PacketCryptoError> {
    let header = encode_frame_header(
        frame.message_type(),
        frame.session_id(),
        frame.counter(),
        frame.payload().len(),
    )?;

    let plaintext = decrypt_packet(key, frame.counter(), frame.payload(), &header)
        .map_err(|_| PacketCryptoError::AuthenticationFailed)?;

    Frame::new(
        frame.message_type(),
        frame.session_id(),
        frame.counter(),
        plaintext,
    )
    .map_err(Into::into)
}

/// Maps a 64-bit packet counter into the 96-bit ChaCha20-Poly1305 nonce format.
///
/// Layout: `four zero bytes || counter in network byte order`. A counter must
/// never repeat under the same key; a reset is safe only after installing a new
/// directional key.
pub fn nonce_from_counter(counter: u64) -> [u8; NONCE_LENGTH] {
    let mut nonce = [0_u8; NONCE_LENGTH];

    nonce[4..].copy_from_slice(&counter.to_be_bytes());

    nonce
}

/// Encrypts bytes with ChaCha20-Poly1305 and authenticates `associated_data`.
pub fn encrypt_packet(
    key_bytes: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let key = Key::from(*key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from(nonce_from_counter(counter));

    cipher.encrypt(
        &nonce,
        Payload {
            msg: plaintext,
            aad: associated_data,
        },
    )
}

/// Authenticates and decrypts bytes produced by [`encrypt_packet`].
pub fn decrypt_packet(
    key_bytes: &[u8; 32],
    counter: u64,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let key = Key::from(*key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);

    let nonce = Nonce::from(nonce_from_counter(counter));

    cipher.decrypt(
        &nonce,
        Payload {
            msg: ciphertext,
            aad: associated_data,
        },
    )
}

/// Authenticates a frame and accepts its counter at most once.
///
/// Authentication deliberately happens before replay state is changed. This
/// prevents a forged packet with a very large counter from moving the window
/// forward and causing valid packets to be rejected.
pub fn unprotect_frame_once(
    frame: &Frame,
    key: &[u8; 32],
    replay_window: &mut ReplayWindow,
) -> Result<Frame, PacketCryptoError> {
    // Do not record attacker-controlled counter values before authentication.
    let plaintext = unprotect_frame(frame, key)?;

    replay_window
        .check_and_record(frame.counter())
        .map_err(PacketCryptoError::ReplayRejected)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHENTICATION_TAG_LENGTH, MAX_PLAINTEXT_SIZE, PacketCryptoError, decrypt_packet,
        encrypt_packet, nonce_from_counter, protect_frame, unprotect_frame, unprotect_frame_once,
    };
    use crate::protocol::{Frame, MAX_PAYLOAD_SIZE, MessageType};
    use crate::toy_crypto::replay_window::{ReplayError, ReplayWindow};

    #[test]
    fn counter_is_stored_in_network_byte_order() {
        assert_eq!(nonce_from_counter(1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],);
    }

    #[test]
    fn different_counters_create_different_nonces() {
        assert_ne!(nonce_from_counter(1), nonce_from_counter(2));
    }

    #[test]
    fn encrypted_packet_round_trips() {
        let key = [7_u8; 32];
        let plaintext = b"inner IPv4 packet";
        let aad = b"packet-header";

        let ciphertext = encrypt_packet(&key, 1, plaintext, aad).unwrap();

        assert_ne!(ciphertext, plaintext);
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + AUTHENTICATION_TAG_LENGTH,
        );

        let decrypted = decrypt_packet(&key, 1, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_modified_ciphertext() {
        let key = [7_u8; 32];
        let aad = b"packet-header";

        let mut ciphertext = encrypt_packet(&key, 1, b"inner packet", aad).unwrap();

        ciphertext[0] ^= 1;

        assert!(decrypt_packet(&key, 1, &ciphertext, aad).is_err());
    }

    #[test]
    fn rejects_the_wrong_counter() {
        let key = [7_u8; 32];
        let aad = b"packet-header";

        let ciphertext = encrypt_packet(&key, 1, b"inner packet", aad).unwrap();

        assert!(decrypt_packet(&key, 2, &ciphertext, aad).is_err());
    }

    #[test]
    fn rejects_the_wrong_key() {
        let sending_key = [7_u8; 32];
        let wrong_key = [8_u8; 32];
        let aad = b"packet-header";

        let ciphertext = encrypt_packet(&sending_key, 1, b"inner packet", aad).unwrap();

        assert!(decrypt_packet(&wrong_key, 1, &ciphertext, aad).is_err());
    }

    #[test]
    fn rejects_modified_associated_data() {
        let key = [7_u8; 32];

        let ciphertext = encrypt_packet(&key, 1, b"inner packet", b"original-header").unwrap();

        assert!(decrypt_packet(&key, 1, &ciphertext, b"modified-header",).is_err());
    }

    #[test]
    fn complete_frame_protection_round_trips() {
        let key = [7_u8; 32];

        let plaintext_frame =
            Frame::new(MessageType::Data, 42, 1, b"inner IPv4 packet".to_vec()).unwrap();

        let protected = protect_frame(&plaintext_frame, &key).unwrap();

        assert_ne!(protected.payload(), plaintext_frame.payload());
        assert_eq!(
            protected.payload().len(),
            plaintext_frame.payload().len() + AUTHENTICATION_TAG_LENGTH,
        );

        let recovered = unprotect_frame(&protected, &key).unwrap();

        assert_eq!(recovered, plaintext_frame);
    }

    #[test]
    fn rejects_a_modified_session_id() {
        let key = [7_u8; 32];

        let plaintext = Frame::new(MessageType::Data, 42, 1, b"packet".to_vec()).unwrap();

        let protected = protect_frame(&plaintext, &key).unwrap();

        let modified = Frame::new(
            protected.message_type(),
            99,
            protected.counter(),
            protected.payload().to_vec(),
        )
        .unwrap();

        assert_eq!(
            unprotect_frame(&modified, &key),
            Err(PacketCryptoError::AuthenticationFailed),
        );
    }

    #[test]
    fn rejects_a_modified_message_type() {
        let key = [7_u8; 32];

        let plaintext = Frame::new(MessageType::Data, 42, 1, b"packet".to_vec()).unwrap();

        let protected = protect_frame(&plaintext, &key).unwrap();

        let modified = Frame::new(
            MessageType::Acknowledgment,
            protected.session_id(),
            protected.counter(),
            protected.payload().to_vec(),
        )
        .unwrap();

        assert_eq!(
            unprotect_frame(&modified, &key),
            Err(PacketCryptoError::AuthenticationFailed),
        );
    }

    #[test]
    fn accepts_the_maximum_plaintext_size() {
        let key = [7_u8; 32];

        let plaintext =
            Frame::new(MessageType::Data, 42, 1, vec![0xaa; MAX_PLAINTEXT_SIZE]).unwrap();

        let protected = protect_frame(&plaintext, &key).unwrap();

        assert_eq!(protected.payload().len(), MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn rejects_plaintext_that_cannot_fit_after_encryption() {
        let key = [7_u8; 32];

        let plaintext =
            Frame::new(MessageType::Data, 42, 1, vec![0xaa; MAX_PLAINTEXT_SIZE + 1]).unwrap();

        assert_eq!(
            protect_frame(&plaintext, &key),
            Err(PacketCryptoError::PlaintextTooLarge {
                actual: MAX_PLAINTEXT_SIZE + 1,
                maximum: MAX_PLAINTEXT_SIZE,
            }),
        );
    }

    #[test]
    fn authenticated_frame_is_accepted_only_once() {
        let key = [7_u8; 32];
        let mut replay_window = ReplayWindow::new();

        let plaintext = Frame::new(MessageType::Data, 42, 7, b"packet".to_vec()).unwrap();

        let protected = protect_frame(&plaintext, &key).unwrap();

        assert_eq!(
            unprotect_frame_once(&protected, &key, &mut replay_window,),
            Ok(plaintext),
        );

        assert_eq!(
            unprotect_frame_once(&protected, &key, &mut replay_window,),
            Err(PacketCryptoError::ReplayRejected(ReplayError::Duplicate,)),
        );
    }

    #[test]
    fn unauthenticated_counter_does_not_update_replay_window() {
        let key = [7_u8; 32];
        let mut replay_window = ReplayWindow::new();

        let plaintext = Frame::new(MessageType::Data, 42, 1, b"packet".to_vec()).unwrap();

        let protected = protect_frame(&plaintext, &key).unwrap();

        let forged = Frame::new(
            protected.message_type(),
            protected.session_id(),
            1_000_000,
            protected.payload().to_vec(),
        )
        .unwrap();

        assert_eq!(
            unprotect_frame_once(&forged, &key, &mut replay_window,),
            Err(PacketCryptoError::AuthenticationFailed),
        );

        // This proves the forged high counter was never recorded.
        assert_eq!(
            unprotect_frame_once(&protected, &key, &mut replay_window,),
            Ok(plaintext),
        );
    }
}
