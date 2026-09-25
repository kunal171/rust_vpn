use rust_vpn::{
    AppRole,
    transport::{ACK_PAYLOAD, CLIENT_BIND_ADDRESS, CLIENT_READ_TIMEOUT, SERVER_ADDRESS},
};
use std::io;
use std::net::UdpSocket;

const PAYLOAD: &[u8] = &[0x00, 0x01, 0xff, b'H', b'i'];

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind(CLIENT_BIND_ADDRESS)?;

    socket.connect(SERVER_ADDRESS)?;
    socket.set_read_timeout(Some(CLIENT_READ_TIMEOUT))?;

    println!(
        "VPN {} Bound to {}",
        AppRole::Client.label(),
        socket.local_addr()?
    );

    let sent_length = socket.send(PAYLOAD)?;

    let mut acknowledgment_buffer = [0_u8; 64];

    let acknowledgment_length = socket.recv(&mut acknowledgment_buffer)?;

    let acknowledgment = &acknowledgment_buffer[..acknowledgment_length];

    if acknowledgment != ACK_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server returned an unexpected acknowledgment",
        ));
    }
    println!("Received acknowledgment: {acknowledgment:?}");

    if sent_length != PAYLOAD.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "UDP Payload was not completely sent",
        ));
    }

    println!("Sent {sent_length} bytes to {SERVER_ADDRESS}");
    println!("Payload bytes: {PAYLOAD:?}");

    Ok(())
}
