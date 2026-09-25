//! End-to-end test of one UDP request and acknowledgment on loopback.
//!
//! This uses real operating-system sockets rather than mocks, so it verifies
//! the same bind, send, receive, and reply operations used by the binaries.

use std::io;
use std::net::UdpSocket;
use std::time::Duration;

use rust_vpn::transport::ACK_PAYLOAD;

#[test]
fn transfers_binary_payload_and_returns_acknowledgment() -> io::Result<()> {
    // Port 0 avoids conflicts by letting the OS choose free ports for the test.
    // Timeouts turn a lost datagram or bug into a test failure instead of a hang.
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(1)))?;

    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(Duration::from_secs(1)))?;

    let server_address = server.local_addr()?;
    let client_address = client.local_addr()?;

    // UDP `connect` stores the peer address; it does not establish a connection
    // or perform a network handshake as TCP does.
    client.connect(server_address)?;

    // Include non-text bytes to prove the transport preserves binary data.
    let expected_payload = [0x00, 0x01, 0xff, b'H', b'i'];

    let sent_length = client.send(&expected_payload)?;

    assert_eq!(sent_length, expected_payload.len());

    let mut server_buffer = [0_u8; 64];

    // The kernel queues the datagram until this receive call, so this simple
    // loopback test does not need a separate server thread.
    let (received_length, sender_address) = server.recv_from(&mut server_buffer)?;

    // Validate both who sent the datagram and exactly which bytes arrived.
    assert_eq!(sender_address, client_address);
    assert_eq!(
        &server_buffer[..received_length],
        expected_payload.as_slice()
    );

    // Send the reply along the reverse path to the observed sender address.
    let acknowledgment_length = server.send_to(ACK_PAYLOAD, sender_address)?;

    assert_eq!(acknowledgment_length, ACK_PAYLOAD.len());

    let mut client_buffer = [0_u8; 64];

    let received_acknowledgment_length = client.recv(&mut client_buffer)?;

    assert_eq!(
        &client_buffer[..received_acknowledgment_length],
        ACK_PAYLOAD
    );

    Ok(())
}
