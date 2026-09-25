//! Minimal UDP client used to exercise the transport layer.
//!
//! It sends one binary datagram and waits for an application-level `ACK`.
//! This is a networking milestone, not yet an encrypted VPN client.

use rust_vpn::{
    AppRole,
    transport::{ACK_PAYLOAD, CLIENT_BIND_ADDRESS, CLIENT_READ_TIMEOUT, SERVER_ADDRESS},
};
use std::io;
use std::net::UdpSocket;

// Values such as `0x00` and `0xff` demonstrate that a UDP payload is arbitrary
// bytes; it does not have to be valid UTF-8 text.
const PAYLOAD: &[u8] = &[0x00, 0x01, 0xff, b'H', b'i'];

fn main() -> io::Result<()> {
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

    let sent_length = socket.send(PAYLOAD)?;
    // `send` normally handles the complete datagram, but checking its result
    // makes that expectation explicit and prevents silent incomplete output.
    if sent_length != PAYLOAD.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "UDP payload was not completely sent",
        ));
    }
    println!("Sent {sent_length} bytes to {SERVER_ADDRESS}");
    println!("Payload bytes: {PAYLOAD:?}");

    let mut acknowledgment_buffer = [0_u8; 64];

    let acknowledgment_length = socket.recv(&mut acknowledgment_buffer)?;

    // Only the prefix reported by `recv` contains bytes from this datagram; the
    // rest of the fixed-size array still contains its initial zero values.
    let acknowledgment = &acknowledgment_buffer[..acknowledgment_length];

    if acknowledgment != ACK_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server returned an unexpected acknowledgment",
        ));
    }
    println!("Received acknowledgment: {acknowledgment:?}");

    Ok(())
}
