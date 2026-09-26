//! End-to-end test of framed UDP data and acknowledgment on loopback.
//!
//! This uses real operating-system sockets rather than mocks, so it verifies
//! that encoded protocol frames survive an actual UDP round trip.

use std::net::UdpSocket;
use std::time::Duration;

use rust_vpn::{
    protocol::{Frame, MessageType},
    transport::RECEIVE_BUFFER_SIZE,
};

const SESSION_ID: u32 = 42;
const PACKET_COUNTER: u64 = 7;

#[test]
fn transfers_data_frame_and_returns_acknowledgment_frame() -> Result<(), Box<dyn std::error::Error>>
{
    // Port 0 avoids conflicts by letting the OS choose free ports for the test.
    // Timeouts turn a lost datagram or bug into a failure instead of a hang.
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(1)))?;

    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(Duration::from_secs(1)))?;

    let server_address = server.local_addr()?;
    let client_address = client.local_addr()?;

    // UDP `connect` stores the peer address; it performs no TCP-style handshake.
    client.connect(server_address)?;

    let expected_payload = vec![0x00, 0x01, 0xff, 0x48, 0x69];
    let data_frame = Frame::new(
        MessageType::Data,
        SESSION_ID,
        PACKET_COUNTER,
        expected_payload.clone(),
    )?;
    let encoded_data_frame = data_frame.encode();

    let sent_length = client.send(&encoded_data_frame)?;
    assert_eq!(sent_length, encoded_data_frame.len());

    let mut server_buffer = [0_u8; RECEIVE_BUFFER_SIZE];
    let (received_length, sender_address) = server.recv_from(&mut server_buffer)?;

    assert_eq!(sender_address, client_address);

    let received_frame = Frame::decode(&server_buffer[..received_length])?;

    assert_eq!(received_frame.message_type(), MessageType::Data);
    assert_eq!(received_frame.session_id(), SESSION_ID);
    assert_eq!(received_frame.counter(), PACKET_COUNTER);
    assert_eq!(received_frame.payload(), expected_payload.as_slice());

    // Echoing the identifiers tells the client exactly which data frame is
    // being acknowledged without copying its payload into the response.
    let acknowledgment = received_frame
        .acknowledgment()
        .expect("a data frame must produce an acknowledgment");
    let encoded_acknowledgment = acknowledgment.encode();

    let acknowledgment_length = server.send_to(&encoded_acknowledgment, sender_address)?;
    assert_eq!(acknowledgment_length, encoded_acknowledgment.len());

    let mut client_buffer = [0_u8; RECEIVE_BUFFER_SIZE];
    let received_acknowledgment_length = client.recv(&mut client_buffer)?;
    let received_acknowledgment = Frame::decode(&client_buffer[..received_acknowledgment_length])?;

    assert_eq!(
        received_acknowledgment.message_type(),
        MessageType::Acknowledgment
    );
    assert_eq!(received_acknowledgment.session_id(), SESSION_ID);
    assert_eq!(received_acknowledgment.counter(), PACKET_COUNTER);
    assert!(received_acknowledgment.payload().is_empty());

    Ok(())
}
