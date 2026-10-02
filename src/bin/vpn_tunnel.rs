//! Connects a Linux TUN interface to a UDP peer.
//!

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
        .layer(Layer::L3)
        .up();
    let _device = tun::create(&configuration)?;

    let socket = UdpSocket::bind(bind_address)?;
    // As in vpn_client: no handshake, just a default peer for send/recv.
    socket.connect(peer_address)?;

    println!("Created {TUN_NAME} with address {tun_address}/24");
    println!("UDP bound to {} with peer {peer_address}", socket.local_addr()?);

    Ok(())
}