//! Minimal UDP server used to exercise framed communication over UDP.
//!
//! It validates each received frame and replies with a framed acknowledgment.
//! It does not yet tunnel or encrypt network traffic.

use rust_vpn::{
    AppRole,
    protocol::Frame,
    transport::{DEFAULT_SERVER_ADDRESS, RECEIVE_BUFFER_SIZE},
};
use std::io;
use std::net::UdpSocket;
use std::{env, net::SocketAddr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_address = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_SERVER_ADDRESS.to_owned());

    let bind_address: SocketAddr = bind_address.parse()?;

    let socket = UdpSocket::bind(bind_address)?;

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
        let acknowledgment = match frame.acknowledgment() {
            Some(acknowledgment) => acknowledgment,
            None => {
                eprintln!(
                    "Ignoring unexpected {:?} frame from {sender_address}",
                    frame.message_type()
                );
                continue;
            }
        };

        println!(
            "direction=receive peer={sender_address} type={:?} \
            session={} counter={} payload_length={} frame_length={received_length}",
            frame.message_type(),
            frame.session_id(),
            frame.counter(),
            frame.payload().len(),
        );

        // The socket is not connected, so reply explicitly to the address that
        // arrived with this datagram. This lets one socket serve many clients.

        let encoded_acknowledgment = acknowledgment.encode();

        let acknowledgment_length = socket.send_to(&encoded_acknowledgment, sender_address)?;

        if acknowledgment_length != encoded_acknowledgment.len() {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP acknowledgment frame was not completely sent",
            )));
        }

        println!(
            "direction=send peer={sender_address} type={:?} \
            session={} counter={} payload_length={} \
            frame_length={acknowledgment_length}",
            acknowledgment.message_type(),
            acknowledgment.session_id(),
            acknowledgment.counter(),
            acknowledgment.payload().len(),
        );
    }
}
