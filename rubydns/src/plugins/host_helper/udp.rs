use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::net::UdpSocket;
use tracing::error;

use super::io_err_to_errno;
use crate::plugins::udp_helper::{Addr, Host};

#[derive(Debug, Default)]
pub struct UdpHelper {
    fd_map: HashMap<u32, UdpSocket>,
}

impl UdpHelper {
    async fn inner_bind(&mut self, addr: Addr) -> Result<u32, u32> {
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.addr))),
            u16::from_be(addr.port),
        );

        let udp_socket = UdpSocket::bind(addr).await.map_err(|err| {
            error!(%addr, %err, "bind udp socket failed");

            io_err_to_errno(err)
        })?;
        let fd = udp_socket.as_raw_fd();

        self.fd_map.insert(fd as _, udp_socket);

        Ok(fd as _)
    }

    async fn inner_connect(&mut self, fd: u32, addr: Addr) -> Result<(), u32> {
        let udp_socket = match self.fd_map.get(&fd) {
            None => return Err(libc::EBADF as _),
            Some(udp_socket) => udp_socket,
        };
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.addr))),
            u16::from_be(addr.port),
        );

        udp_socket.connect(addr).await.map_err(|err| {
            error!(fd, %addr, "udp socket connect failed");

            io_err_to_errno(err)
        })
    }

    async fn inner_send(&mut self, fd: u32, buf: Vec<u8>) -> Result<u64, u32> {
        let udp_socket = match self.fd_map.get(&fd) {
            None => return Err(libc::EBADF as _),
            Some(udp_socket) => udp_socket,
        };

        udp_socket
            .send(&buf)
            .await
            .map_err(|err| {
                error!(fd, %err, "udp socket send failed");

                io_err_to_errno(err)
            })
            .map(|sent| sent as _)
    }

    async fn inner_recv(&mut self, fd: u32, buf_size: u64) -> Result<Vec<u8>, u32> {
        let udp_socket = match self.fd_map.get(&fd) {
            None => return Err(libc::EBADF as _),
            Some(udp_socket) => udp_socket,
        };

        let mut buf = BytesMut::with_capacity(buf_size as _);
        // safety: we don't read it
        unsafe {
            buf.set_len(buf_size as _);
        }

        let n = udp_socket.recv(&mut buf).await.map_err(|err| {
            error!(fd, buf_size, %err, "udp socket recv failed");

            io_err_to_errno(err)
        })?;

        // safety: n bytes data has been init
        unsafe {
            buf.set_len(n);
        }

        Ok(buf.freeze().into())
    }

    async fn inner_send_to(&mut self, fd: u32, buf: Vec<u8>, addr: Addr) -> Result<u64, u32> {
        let udp_socket = match self.fd_map.get(&fd) {
            None => return Err(libc::EBADF as _),
            Some(udp_socket) => udp_socket,
        };
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.addr))),
            u16::from_be(addr.port),
        );

        udp_socket
            .send_to(&buf, addr)
            .await
            .map_err(|err| {
                error!(fd, %addr, %err, "udp socket send to failed");

                io_err_to_errno(err)
            })
            .map(|sent| sent as _)
    }

    async fn inner_recv_from(&mut self, fd: u32, buf_size: u64) -> Result<(Vec<u8>, Addr), u32> {
        let udp_socket = match self.fd_map.get(&fd) {
            None => return Err(libc::EBADF as _),
            Some(udp_socket) => udp_socket,
        };

        let mut buf = BytesMut::with_capacity(buf_size as _);
        // safety: we don't read it
        unsafe {
            buf.set_len(buf_size as _);
        }

        let (n, source) = udp_socket.recv_from(&mut buf).await.map_err(|err| {
            error!(fd, %err, "udp socket recv from failed");

            io_err_to_errno(err)
        })?;

        // safety: n bytes data has been init
        unsafe {
            buf.set_len(n);
        }

        let addr = match source.ip() {
            IpAddr::V4(addr) => u32::from_be_bytes(addr.octets()),
            // we don't support v6 yet
            IpAddr::V6(_) => return Err(libc::ENOTSUP as _),
        };

        Ok((
            buf.into(),
            Addr {
                addr,
                port: source.port().to_be(),
            },
        ))
    }

    pub fn reset(&mut self) {
        self.fd_map.clear();
    }
}

#[async_trait]
impl Host for UdpHelper {
    #[inline]
    async fn bind(&mut self, addr: Addr) -> wasmtime::Result<Result<u32, u32>> {
        Ok(self.inner_bind(addr).await)
    }

    #[inline]
    async fn connect(&mut self, fd: u32, addr: Addr) -> wasmtime::Result<Result<(), u32>> {
        Ok(self.inner_connect(fd, addr).await)
    }

    #[inline]
    async fn send(&mut self, fd: u32, buf: Vec<u8>) -> wasmtime::Result<Result<u64, u32>> {
        Ok(self.inner_send(fd, buf).await)
    }

    #[inline]
    async fn recv(&mut self, fd: u32, buf_size: u64) -> wasmtime::Result<Result<Vec<u8>, u32>> {
        Ok(self.inner_recv(fd, buf_size).await)
    }

    #[inline]
    async fn send_to(
        &mut self,
        fd: u32,
        buf: Vec<u8>,
        addr: Addr,
    ) -> wasmtime::Result<Result<u64, u32>> {
        Ok(self.inner_send_to(fd, buf, addr).await)
    }

    #[inline]
    async fn recv_from(
        &mut self,
        fd: u32,
        buf_size: u64,
    ) -> wasmtime::Result<Result<(Vec<u8>, Addr), u32>> {
        Ok(self.inner_recv_from(fd, buf_size).await)
    }

    #[inline]
    async fn close(&mut self, fd: u32) -> wasmtime::Result<()> {
        self.fd_map.remove(&fd);

        Ok(())
    }
}
