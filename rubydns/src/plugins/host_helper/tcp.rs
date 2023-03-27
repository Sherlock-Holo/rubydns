use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::error;

use super::io_err_to_errno;
use crate::plugins::tcp_helper::{Addr, Host};

#[derive(Debug)]
enum Tcp {
    Stream(TcpStream),
    Listener(TcpListener),
}

#[derive(Debug, Default)]
pub struct TcpHelper {
    fd_map: HashMap<u32, Tcp>,
}

impl TcpHelper {
    async fn inner_bind(&mut self, addr: Addr) -> Result<u32, u32> {
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.addr))),
            u16::from_be(addr.port),
        );

        let listener = TcpListener::bind(addr).await.map_err(|err| {
            error!(%addr, %err, "bind tcp socket failed");

            io_err_to_errno(err)
        })?;
        let fd = listener.as_raw_fd();

        self.fd_map.insert(fd as _, Tcp::Listener(listener));

        Ok(fd as _)
    }

    async fn inner_accept(&mut self, fd: u32) -> Result<(u32, Addr), u32> {
        let listener = match self.fd_map.get_mut(&fd) {
            None => return Err(libc::EBADF as _),
            Some(Tcp::Stream(_)) => return Err(libc::EBADF as _),
            Some(Tcp::Listener(listener)) => listener,
        };

        let (tcp_stream, addr) = listener.accept().await.map_err(|err| {
            error!(%err, "tcp listener accept failed");

            io_err_to_errno(err)
        })?;

        let fd = tcp_stream.as_raw_fd();
        self.fd_map.insert(fd as _, Tcp::Stream(tcp_stream));

        let ip = get_ipv4_be(&addr)?;

        Ok((
            fd as _,
            Addr {
                addr: ip,
                port: addr.port().to_be(),
            },
        ))
    }

    async fn inner_connect(&mut self, addr: Addr) -> Result<u32, u32> {
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.addr))),
            u16::from_be(addr.port),
        );

        let tcp_stream = TcpStream::connect(addr).await.map_err(|err| {
            error!(%addr, "tcp socket connect failed");

            io_err_to_errno(err)
        })?;

        let fd = tcp_stream.as_raw_fd();

        self.fd_map.insert(fd as _, Tcp::Stream(tcp_stream));

        Ok(fd as _)
    }

    async fn inner_write(&mut self, fd: u32, buf: Vec<u8>) -> Result<u64, u32> {
        let tcp_stream = self.get_tcp_stream(fd)?;

        tcp_stream
            .write(&buf)
            .await
            .map_err(|err| {
                error!(fd, %err, "tcp socket write failed");

                io_err_to_errno(err)
            })
            .map(|sent| sent as _)
    }

    async fn inner_flush(&mut self, fd: u32) -> Result<(), u32> {
        let tcp_stream = self.get_tcp_stream(fd)?;

        tcp_stream
            .flush()
            .await
            .map_err(|err| {
                error!(fd, %err, "tcp socket write failed");

                io_err_to_errno(err)
            })
            .map(|sent| sent as _)
    }

    async fn inner_read(&mut self, fd: u32, buf_size: u64) -> Result<Vec<u8>, u32> {
        let tcp_stream = self.get_tcp_stream(fd)?;

        let mut buf = BytesMut::with_capacity(buf_size as _);
        // safety: we don't read it
        unsafe {
            buf.set_len(buf_size as _);
        }

        let n = tcp_stream.read(&mut buf).await.map_err(|err| {
            error!(fd, buf_size, %err, "tcp socket read failed");

            io_err_to_errno(err)
        })?;

        // safety: n bytes data has been init
        unsafe {
            buf.set_len(n);
        }

        Ok(buf.freeze().into())
    }

    fn get_tcp_stream(&mut self, fd: u32) -> Result<&mut TcpStream, u32> {
        match self.fd_map.get_mut(&fd) {
            None => Err(libc::EBADF as _),
            Some(Tcp::Listener(_)) => Err(libc::EBADF as _),
            Some(Tcp::Stream(tcp_stream)) => Ok(tcp_stream),
        }
    }

    pub fn reset(&mut self) {
        self.fd_map.clear();
    }
}

#[async_trait]
impl Host for TcpHelper {
    #[inline]
    async fn bind(&mut self, addr: Addr) -> wasmtime::Result<Result<u32, u32>> {
        Ok(self.inner_bind(addr).await)
    }

    #[inline]
    async fn accept(&mut self, fd: u32) -> wasmtime::Result<Result<(u32, Addr), u32>> {
        Ok(self.inner_accept(fd).await)
    }

    #[inline]
    async fn connect(&mut self, addr: Addr) -> wasmtime::Result<Result<u32, u32>> {
        Ok(self.inner_connect(addr).await)
    }

    #[inline]
    async fn write(&mut self, fd: u32, buf: Vec<u8>) -> wasmtime::Result<Result<u64, u32>> {
        Ok(self.inner_write(fd, buf).await)
    }

    #[inline]
    async fn flush(&mut self, fd: u32) -> wasmtime::Result<Result<(), u32>> {
        Ok(self.inner_flush(fd).await)
    }

    #[inline]
    async fn read(&mut self, fd: u32, buf_size: u64) -> wasmtime::Result<Result<Vec<u8>, u32>> {
        Ok(self.inner_read(fd, buf_size).await)
    }

    #[inline]
    async fn close(&mut self, fd: u32) -> wasmtime::Result<()> {
        self.fd_map.remove(&fd);

        Ok(())
    }
}

fn get_ipv4_be(addr: &SocketAddr) -> Result<u32, u32> {
    match addr.ip() {
        IpAddr::V4(ip) => Ok(u32::from_be_bytes(ip.octets()).to_be()),
        IpAddr::V6(_) => Err(libc::ENOTSUP as _),
    }
}
