use std::io;
use std::net::UdpSocket;
use std::time::Duration;

use rust_vpn::transport::ACK_PAYLOAD;

#[test]
fn transfers_binary_payload_and_returns_acknowledgment() -> io::Result<()> {
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(1)))?;

    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(Duration::from_secs(1)))?;

    let server_address = server.local_addr()?;
    let client_address = client.local_addr()?;

    client.connect(server_address)?;

    let expected_payload = [0x00, 0x01, 0xff, b'H', b'i'];

    let sent_length = client.send(&expected_payload)?;

    assert_eq!(sent_length, expected_payload.len());

    let mut server_buffer = [0_u8; 64];

    let (received_length, sender_address) = server.recv_from(&mut server_buffer)?;

    assert_eq!(sender_address, client_address);
    assert_eq!(
        &server_buffer[..received_length],
        expected_payload.as_slice()
    );

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
