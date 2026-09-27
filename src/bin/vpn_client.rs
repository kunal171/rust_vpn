//! Minimal UDP client used to exercise framed communication over UDP.
//!
//! It sends several binary `Data` frames and validates each corresponding
//! acknowledgment. This is not yet an encrypted VPN client.

use rust_vpn::{
    AppRole,
    protocol::{Frame, MessageType},
    transport::{CLIENT_BIND_ADDRESS, CLIENT_READ_TIMEOUT, SERVER_ADDRESS},
};
use std::io;
use std::net::UdpSocket;

// Values such as `0x00` and `0xff` demonstrate that a UDP payload is arbitrary
// bytes; it does not have to be valid UTF-8 text.
const PAYLOAD: &[u8] = &[0x00, 0x01, 0xff, b'H', b'i'];

const SESSION_ID: u32 = 1;

const FIRST_PACKET_COUNTER: u64 = 1;
const LAST_PACKET_COUNTER: u64 = 3;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Binding to port 0 lets the OS assign an available ephemeral client port.
    let socket = UdpSocket::bind(CLIENT_BIND_ADDRESS)?;

    // UDP `connect` performs no handshake. It records one default peer so this
    // socket can use `send`/`recv` and accept datagrams from only that peer.
    socket.connect(SERVER_ADDRESS)?;
    // Bound the blocking receive so a missing UDP reply cannot hang forever.
    socket.set_read_timeout(Some(CLIENT_READ_TIMEOUT))?;

    println!(
        "VPN {} Bound to {}",
        AppRole::Client.label(),
        socket.local_addr()?
    );

    let mut acknowledgment_buffer = [0_u8; 64];

    for counter in FIRST_PACKET_COUNTER..=LAST_PACKET_COUNTER {
        let frame = Frame::new(MessageType::Data, SESSION_ID, counter, PAYLOAD.to_vec())?;

        let encoded_frame = frame.encode();

        let sent_length = socket.send(&encoded_frame)?;

        if sent_length != encoded_frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP frame was not completely sent",
            )
            .into());
        }

        println!(
            "direction=send peer={SERVER_ADDRESS} type={:?} \
            session={SESSION_ID} counter={counter} \
            payload_length={} frame_length={sent_length}",
            MessageType::Data,
            PAYLOAD.len(),
        );

        let acknowledgment_length = socket.recv(&mut acknowledgment_buffer)?;
        let acknowledgment = Frame::decode(&acknowledgment_buffer[..acknowledgment_length])?;
        // Only the prefix reported by `recv` contains bytes from this datagram; the
        // rest of the fixed-size array still contains its initial zero values.
        if acknowledgment.message_type() != MessageType::Acknowledgment
            || acknowledgment.session_id() != SESSION_ID
            || acknowledgment.counter() != counter
            || !acknowledgment.payload().is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "server returned an invalid acknowledgment frame",
            )
            .into());
        }

        println!(
            "direction=receive peer={SERVER_ADDRESS} type={:?} \
            session={} counter={} payload_length={} \
            frame_length={acknowledgment_length}",
            acknowledgment.message_type(),
            acknowledgment.session_id(),
            acknowledgment.counter(),
            acknowledgment.payload().len(),
        );
    }

    Ok(())
}
