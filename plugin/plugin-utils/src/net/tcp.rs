use std::io;
use std::io::{Error, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::get_ipv4_be;
use crate::gen::tcp_helper;
use crate::gen::tcp_helper::Addr;

#[derive(Debug)]
pub struct TcpStream {
    fd: u32,
}

impl TcpStream {
    pub fn connect(addr: SocketAddr) -> io::Result<Self> {
        let ip = get_ipv4_be(&addr)?;

        let fd = tcp_helper::connect(Addr {
            addr: ip,
            port: addr.port().to_be(),
        })
        .map_err(|errno| Error::from_raw_os_error(errno as _))?;

        Ok(Self { fd })
    }

    fn inner_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let data = tcp_helper::read(self.fd, buf.len() as _)
            .map_err(|errno| Error::from_raw_os_error(errno as _))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);

        Ok(n)
    }

    fn inner_write(&self, buf: &[u8]) -> io::Result<usize> {
        let n = tcp_helper::write(self.fd, buf)
            .map_err(|errno| Error::from_raw_os_error(errno as _))?;

        Ok(n as _)
    }

    fn inner_flush(&self) -> io::Result<()> {
        tcp_helper::flush(self.fd).map_err(|errno| Error::from_raw_os_error(errno as _))
    }
}

impl Read for TcpStream {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner_read(buf)
    }
}

impl Write for TcpStream {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner_write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.inner_flush()
    }
}

impl Read for &TcpStream {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner_read(buf)
    }
}

impl Write for &TcpStream {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner_write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.inner_flush()
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        tcp_helper::close(self.fd);
    }
}

#[derive(Debug)]
pub struct TcpListener {
    fd: u32,
}

impl TcpListener {
    pub fn listen(addr: SocketAddr) -> io::Result<Self> {
        let ip = get_ipv4_be(&addr)?;

        let fd = tcp_helper::bind(Addr {
            addr: ip,
            port: addr.port().to_be(),
        })
        .map_err(|errno| Error::from_raw_os_error(errno as _))?;

        Ok(Self { fd })
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (fd, addr) =
            tcp_helper::accept(self.fd).map_err(|errno| Error::from_raw_os_error(errno as _))?;

        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.addr))),
            u16::from_be(addr.port),
        );

        Ok((TcpStream { fd }, addr))
    }
}

impl Iterator for TcpListener {
    type Item = io::Result<TcpStream>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.accept().map(|(stream, _)| stream))
    }
}

impl Iterator for &TcpListener {
    type Item = io::Result<TcpStream>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.accept().map(|(stream, _)| stream))
    }
}
