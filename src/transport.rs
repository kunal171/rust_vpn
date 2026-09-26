//! Transport-level configuration shared by the UDP client and server.
//!
//! `RECEIVE_BUFFER_SIZE` is an application buffer size, not the capacity of
//! UDP itself or of the operating system socket receive queue.

use std::time::Duration;

/// Binds the client to loopback and asks the OS to choose an available port.
///
/// Port `0` is special when binding: it requests an ephemeral local port.
pub const CLIENT_BIND_ADDRESS: &str = "127.0.0.1:0";
/// Fixed loopback address on which the example server listens.
pub const SERVER_ADDRESS: &str = "127.0.0.1:51820";
/// Maximum number of bytes this application reads from one UDP datagram.
///
/// This matches the protocol maximum frame size. A larger datagram may be
/// truncated by `recv_from`, so its full contents would not be usable.
pub const RECEIVE_BUFFER_SIZE: usize = 2048;

/// Prevents the client from waiting forever when no reply arrives.
pub const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(2);
