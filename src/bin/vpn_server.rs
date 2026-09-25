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

    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    loop {
        let (received_length, sender_address) = socket.recv_from(&mut buffer)?;

        println!("Received {received_length} bytes from {sender_address}");

        let acknowledgment_length = socket.send_to(ACK_PAYLOAD, sender_address)?;

        println!("Sent {acknowledgment_length}-byte acknowledgment to {sender_address}");

        println!("Payload bytes: {:?}", &buffer[..received_length]);
    }
}
