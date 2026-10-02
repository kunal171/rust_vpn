//! Connects a Linux TUN interface to a UDP peer.

use rust_vpn::protocol::{Frame, MessageType};
use std::io::Read;
use std::env;
use std::error::Error;
use std::net::{
    Ipv4Addr, SocketAddr, UdpSocket
};
use tun::{
    Configuration, Layer
};

const TUN_NAME: &str = "rvpn0";
const TUN_NETMASK: &str = "255.255.255.0";
const USAGE: &str = "usage: vpn_tunnel <tun-address> <bind-address> <peer-address>\n\
    example: vpn_tunnel 10.210.0.1 10.200.1.1:51820 10.200.1.2:51820";

/// Link MTU (1500) minus outer IPv4 (20), UDP (8), and frame header (16),
/// so an encapsulated packet still fits in one link-sized datagram.
const TUN_MTU: u16 = 1456;
const SESSION_ID: u32 = 1;
// Same reasoning as tun_reader: the largest possible IPv4 packet.
const PACKET_BUFFER_SIZE: usize = 65_535;


/// Returns the next command-line argument, or an error that names it.
fn required_argument(
    arguments: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, Box<dyn Error>> {
    arguments
        .next()
        .ok_or_else(|| format!("missing {name}\n{USAGE}").into())
}

fn main()-> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);

    let tun_address: Ipv4Addr = required_argument(&mut arguments, "tun-address")?.parse()?;
    let bind_address: SocketAddr = required_argument(&mut arguments, "bind-address")?.parse()?;
    let peer_address: SocketAddr = required_argument(&mut arguments, "peer-address")?.parse()?;

    let mut configuration = Configuration::default();

    configuration
        .tun_name(TUN_NAME)
        .address(tun_address)
        .netmask(TUN_NETMASK)
        .mtu(TUN_MTU)
        .layer(Layer::L3)
        .up();

    let mut device = tun::create(&configuration)?;

    let socket = UdpSocket::bind(bind_address)?;
    // As in vpn_client: no handshake, just a default peer for send/recv.
    socket.connect(peer_address)?;

    println!("Created {TUN_NAME} with address {tun_address}/24");
    println!("UDP bound to {} with peer {peer_address}", socket.local_addr()?);

    let mut buffer = vec![0_u8; PACKET_BUFFER_SIZE];
    let mut counter: u64 = 0;

    loop {
        let packet_length = device.read(&mut buffer)?;
        let packet = &buffer[..packet_length];

        counter +=1;

        let frame = match Frame::new(MessageType::Data, SESSION_ID, counter, packet.to_vec()) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("Dropping TUN packet: {error}");
                continue;
            }
        };

        let encoded_frame = frame.encode();

        // A missing peer must not stop the tunnel; drop the packet and go on.
        match socket.send(&encoded_frame) {
            Ok(sent_length) => println!(
                "direction=send peer={peer_address} counter={counter} \
                packet_length={packet_length} frame_length={sent_length}"
            ),
            Err(error) => eprintln!("Dropping packet {counter}: send failed: {error}"),
        }
    }
}