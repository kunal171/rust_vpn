//! Cryptographic building blocks used by the Phase 8 learning exercises.
//!
//! The modular arithmetic and Diffie-Hellman modules are deliberately small,
//! non-constant-time teaching implementations. HKDF and ChaCha20-Poly1305 come
//! from established crates. The real tunnel authenticates these primitives in
//! a separate handshake module, but the project remains educational and has
//! not received the review required for production cryptography.

/// Toy Diffie-Hellman key agreement. Never use it for real secrets.
pub mod diffie_hellman;
/// Turns one shared secret into separate client-to-server and server-to-client keys.
pub mod key_derivation;
/// Modular arithmetic for the toy Diffie-Hellman experiments. Not for real secrets.
pub mod modular;
/// Encrypts frame payloads and authenticates both payloads and visible headers.
pub mod packet_crypto;
/// Detects duplicate and excessively old authenticated packets.
pub mod replay_window;
/// Allocates unique packet counters for one sending key.
pub mod send_counter;
/// Combines keys, send counters, and replay state into a session API.
pub mod session;
