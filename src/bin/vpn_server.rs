//! Minimal UDP server used to exercise framed communication over UDP.
//!
//! It validates each received frame and replies with a framed acknowledgment.
//! It does not yet tunnel or encrypt network traffic.

use rust_vpn::{
    AppRole,
    protocol::{Frame, MessageType},
    transport::{RECEIVE_BUFFER_SIZE, SERVER_ADDRESS},
};
use std::io;
use std::net::UdpSocket;

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind(SERVER_ADDRESS)?;

    println!(
        "VPN {} listening on {}",
        AppRole::Server.label(),
        socket.local_addr()?
    );

    // Allocate once and reuse the same stack buffer for every datagram.
    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    loop {
        // Unlike TCP, UDP preserves datagram boundaries. `recv_from` returns
        // both this datagram byte count and the address that sent it.
        let (received_length, sender_address) = socket.recv_from(&mut buffer)?;

        let received_bytes = &buffer[..received_length];

        let frame = match Frame::decode(received_bytes) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("Rejected malformed frame from {sender_address}: {error}");
                continue;
            }
        };
        if frame.message_type() != MessageType::Data {
            eprintln!(
                "Ignoring unexpected {:?} frame from {sender_address}",
                frame.message_type()
            );
            continue;
        }

        println!(
            "Decoded frame: version={}, type={:?}, session={}, counter={}",
            frame.version(),
            frame.message_type(),
            frame.session_id(),
            frame.counter(),
        );

        println!("Payload bytes: {:?}", frame.payload());

        // The socket is not connected, so reply explicitly to the address that
        // arrived with this datagram. This lets one socket serve many clients.

        let acknowledgment = Frame::new(
            MessageType::Acknowledgment,
            frame.session_id(),
            frame.counter(),
            Vec::new(),
        )
        .expect("an empty acknowledgment payload is always valid");

        let encoded_acknowledgment = acknowledgment.encode();

        let acknowledgment_length = socket.send_to(&encoded_acknowledgment, sender_address)?;

        if acknowledgment_length != encoded_acknowledgment.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP acknowledgment frame was not completely sent",
            ));
        }

        println!("Sent {acknowledgment_length}-byte acknowledgment to {sender_address}");
    }
}
