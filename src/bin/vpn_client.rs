use rust_vpn::{
    AppRole,
    transport::{CLIENT_BIND_ADDRESS, SERVER_ADDRESS},
};
use std::io;
use std::net::UdpSocket;

const PAYLOAD: &[u8] = &[0x00, 0x01, 0xff, b'H', b'i'];

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind(CLIENT_BIND_ADDRESS)?;

    println!(
        "VPN {} Bound to {}",
        AppRole::Client.label(),
        socket.local_addr()?
    );

    let sent_length = socket.send_to(PAYLOAD, SERVER_ADDRESS)?;

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
