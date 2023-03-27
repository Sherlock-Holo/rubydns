use std::io;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};

pub mod tcp;
pub mod udp;

fn get_ipv4_be(addr: &SocketAddr) -> io::Result<u32> {
    match addr.ip() {
        IpAddr::V4(ip) => Ok(u32::from_be_bytes(ip.octets()).to_be()),
        IpAddr::V6(_) => Err(Error::from(ErrorKind::Unsupported)),
    }
}
