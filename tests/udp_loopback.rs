use std::io;
use std::net::UdpSocket;
use std::time::Duration;

#[test]
fn transfers_binary_payload_over_loopback() -> io::Result<()> {
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(1)))?;

    let client = UdpSocket::bind("127.0.0.1:0")?;

    let server_address = server.local_addr()?;
    let client_address = client.local_addr()?;

    let expected_payload = [0x00, 0x01, 0xff, b'H', b'i'];

    let sent_length = client.send_to(&expected_payload, server_address)?;

    assert_eq!(sent_length, expected_payload.len());

    let mut buffer = [0_u8; 64];
    let (received_length, sender_address) = server.recv_from(&mut buffer)?;

    assert_eq!(sender_address, client_address);
    assert_eq!(&buffer[..received_length], expected_payload.as_slice());

    Ok(())
}
