//! Minimal UDP server used to exercise the transport layer.
//!
//! It receives binary datagrams and replies to each sender with an
//! application-level `ACK`. It does not yet parse or tunnel VPN frames.

use rust_vpn::{
    AppRole,
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

        println!("Received {received_length} bytes from {sender_address}");

        // The socket is not connected, so reply explicitly to the address that
        // arrived with this datagram. This lets one socket serve many clients.
        let acknowledgment_length = socket.send_to(ACK_PAYLOAD, sender_address)?;

        println!("Sent {acknowledgment_length}-byte acknowledgment to {sender_address}");

        // Inspect only bytes written by `recv_from`, not unused buffer space.
        println!("Payload bytes: {:?}", &buffer[..received_length]);
    }
}
