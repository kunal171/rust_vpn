use std::io;
use std::net::UdpSocket;
use rust_vpn::AppRole;
const SERVER_ADDRESS: &str = "127.0.0.1:51820";
const RECEIVE_BUFFER_SIZE: usize = 2048;

fn main() ->io::Result<()> {
    let socket = UdpSocket::bind(SERVER_ADDRESS)?;

    println!(
        "VPN {} listening on {}",
        AppRole::Server.label(),
        socket.local_addr()?
    );

    let mut buffer = [0_u8; RECEIVE_BUFFER_SIZE];

    let (received_length, sender_address) = socket.recv_from(&mut buffer)?;

    println!("Received {received_length} bytes from {sender_address}");
    println!("Payload bytes: {:?}", &buffer[..received_length]);

    Ok(())
}
