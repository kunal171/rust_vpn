use std::time::Duration;

pub const CLIENT_BIND_ADDRESS: &str = "127.0.0.1:0";
pub const SERVER_ADDRESS: &str = "127.0.0.1:51820";
pub const RECEIVE_BUFFER_SIZE: usize = 2048;

pub const ACK_PAYLOAD: &[u8] = b"ACK";
pub const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(2);
