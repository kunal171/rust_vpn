//! Authenticated packet encryption for the cryptography learning phase.
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

pub const NONCE_LENGTH: usize = 12;
pub const AUTHENTICATION_TAG_LENGTH: usize = 16;

pub fn nonce_from_counter(counter: u64) -> [u8; NONCE_LENGTH] {
    let mut nonce = [0_u8; NONCE_LENGTH];

    nonce[4..].copy_from_slice(&counter.to_be_bytes());

    nonce
}

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

#[cfg(test)]
mod tests {
    use super::{AUTHENTICATION_TAG_LENGTH, decrypt_packet, encrypt_packet, nonce_from_counter};

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
}
