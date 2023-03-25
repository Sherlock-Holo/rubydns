use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use host::WasiCtx;
use tap::TapFallible;
use tokio::net::UdpSocket;
use tracing::error;
use wasi_cap_std_sync::WasiCtxBuilder;

use super::helper::Error;
use super::helper::Host as HelperHost;
use super::pool::PluginPool;
use super::udp_helper::{Addr, Host as UdpHost};

pub struct HostHelper {
    wasi_ctx: WasiCtx,
    raw_config: Arc<String>,
    udp_helper: UdpHelper,
    next_plugin: Option<PluginPool>,
}

impl HostHelper {
    pub fn new(raw_config: Arc<String>, next_plugin: Option<PluginPool>) -> Self {
        Self {
            wasi_ctx: WasiCtxBuilder::new().inherit_network().build(),
            raw_config,
            udp_helper: Default::default(),
            next_plugin,
        }
    }

    pub fn wasi_ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }

    pub fn udp_helper(&mut self) -> &mut UdpHelper {
        &mut self.udp_helper
    }

    pub fn reset(&mut self) {
        self.udp_helper.reset();
    }
}

#[async_trait]
impl HelperHost for HostHelper {
    #[inline]
    async fn load_config(&mut self) -> wasmtime::Result<String> {
        Ok(self.raw_config.to_string())
    }

    async fn call_next_plugin(
        &mut self,
        dns_packet: Vec<u8>,
    ) -> anyhow::Result<Option<Result<Vec<u8>, Error>>> {
        let plugin_pool = match &self.next_plugin {
            None => return Ok(None),
            Some(plugin_pool) => plugin_pool,
        };

        let mut next_plugin = plugin_pool
            .get_plugin()
            .await
            .tap_err(|err| error!(%err, "get next plugin failed"))?;

        let (plugin, store) = &mut *next_plugin;

        let result = plugin.plugin().call_run(store, &dns_packet).await?;

        Ok(Some(result))
    }
}

#[derive(Debug, Default)]
pub struct UdpHelper {
    fd_map: HashMap<u32, UdpSocket>,
}

impl UdpHelper {
    #[inline]
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

    #[inline]
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

    #[inline]
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

    #[inline]
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

    #[inline]
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

    #[inline]
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
impl UdpHost for UdpHelper {
    async fn bind(&mut self, addr: Addr) -> wasmtime::Result<Result<u32, u32>> {
        Ok(self.inner_bind(addr).await)
    }

    async fn connect(&mut self, fd: u32, addr: Addr) -> wasmtime::Result<Result<(), u32>> {
        Ok(self.inner_connect(fd, addr).await)
    }

    async fn send(&mut self, fd: u32, buf: Vec<u8>) -> wasmtime::Result<Result<u64, u32>> {
        Ok(self.inner_send(fd, buf).await)
    }

    async fn recv(&mut self, fd: u32, buf_size: u64) -> wasmtime::Result<Result<Vec<u8>, u32>> {
        Ok(self.inner_recv(fd, buf_size).await)
    }

    async fn send_to(
        &mut self,
        fd: u32,
        buf: Vec<u8>,
        addr: Addr,
    ) -> wasmtime::Result<Result<u64, u32>> {
        Ok(self.inner_send_to(fd, buf, addr).await)
    }

    async fn recv_from(
        &mut self,
        fd: u32,
        buf_size: u64,
    ) -> wasmtime::Result<Result<(Vec<u8>, Addr), u32>> {
        Ok(self.inner_recv_from(fd, buf_size).await)
    }

    async fn close(&mut self, fd: u32) -> wasmtime::Result<()> {
        self.fd_map.remove(&fd);

        Ok(())
    }
}

fn io_err_to_errno(err: io::Error) -> u32 {
    err.raw_os_error().unwrap_or(1) as _
}
