//! Hand-written cryptographic math, for learning only.

/// Toy Diffie-Hellman key agreement. Never use it for real secrets.
pub mod diffie_hellman;
/// HKDF-based session-key derivation for the learning exchange.
pub mod key_derivation;
/// Modular arithmetic for the toy Diffie-Hellman experiments. Not for real secrets.
pub mod modular;
/// Authenticated encryption experiments for the cryptography learning phase.
pub mod packet_crypto;
/// Detects duplicate and excessively old authenticated packets.
pub mod replay_window;
/// Allocates unique packet counters for one sending key.
pub mod send_counter;
/// Owns keys and counter state for one cryptographic session.
pub mod session;
