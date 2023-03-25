use std::io;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::gen::udp_helper::{self, Addr};

#[allow(unused_macros)]
mod gen {
    wit_bindgen::generate!("rubydns");
}

#[derive(Debug)]
pub struct UdpSocket {
    fd: u32,
}

impl UdpSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let ip = get_ipv4_be(&addr)?;

        let fd = udp_helper::bind(Addr {
            addr: ip,
            port: addr.port().to_be(),
        })
        .map_err(|errno| Error::from_raw_os_error(errno as _))?;

        Ok(Self { fd })
    }

    pub fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        let ip = get_ipv4_be(&addr)?;

        udp_helper::connect(
            self.fd,
            Addr {
                addr: ip,
                port: addr.port().to_be(),
            },
        )
        .map_err(|errno| Error::from_raw_os_error(errno as _))
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        udp_helper::send(self.fd, buf)
            .map_err(|errno| Error::from_raw_os_error(errno as _))
            .map(|n| n as _)
    }

    pub fn recv(&self, buf_size: usize) -> io::Result<Vec<u8>> {
        udp_helper::recv(self.fd, buf_size as _)
            .map_err(|errno| Error::from_raw_os_error(errno as _))
    }

    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let ip = get_ipv4_be(&addr)?;

        udp_helper::send_to(
            self.fd,
            buf,
            Addr {
                addr: ip,
                port: addr.port().to_be(),
            },
        )
        .map_err(|errno| Error::from_raw_os_error(errno as _))
        .map(|n| n as _)
    }

    pub fn recv_from(&self, buf_size: usize) -> io::Result<(Vec<u8>, SocketAddr)> {
        let (data, addr) = udp_helper::recv_from(self.fd, buf_size as _)
            .map_err(|errno| Error::from_raw_os_error(errno as _))?;

        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.addr))),
            u16::from_be(addr.port),
        );

        Ok((data, addr))
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        udp_helper::close(self.fd)
    }
}

fn get_ipv4_be(addr: &SocketAddr) -> io::Result<u32> {
    match addr.ip() {
        IpAddr::V4(ip) => Ok(u32::from_be_bytes(ip.octets()).to_be()),
        IpAddr::V6(_) => Err(Error::from(ErrorKind::Unsupported)),
    }
}
