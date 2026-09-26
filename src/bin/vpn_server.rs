//! Minimal UDP server used to exercise the transport layer.
//!
//! It receives binary datagrams and replies to each sender with an
//! application-level `ACK`. It does not yet parse or tunnel VPN frames.

use rust_vpn::{
    AppRole,
    protocol::Frame,
    transport::{ACK_PAYLOAD, RECEIVE_BUFFER_SIZE, SERVER_ADDRESS},
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
        let acknowledgment_length = socket.send_to(ACK_PAYLOAD, sender_address)?;

        println!("Sent {acknowledgment_length}-byte acknowledgment to {sender_address}");
    }
}
