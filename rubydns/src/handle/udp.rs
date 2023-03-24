use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use thiserror::Error;
use tokio::net::UdpSocket;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::Message;

pub trait Accept {
    type Error: std::error::Error + Send + Sync + 'static;
    type Identify: Debug + Eq + Send;
    type AcceptFuture<'a>: Future<Output = Result<(Self::Identify, Message, Bytes), Self::Error>>
        + 'a
        + Send
    where
        Self: 'a;

    fn accept(&self) -> Self::AcceptFuture<'_>;
}

pub trait Respond {
    type Error: std::error::Error + Send + Sync + 'static;
    type Identify: Debug + Eq + Send;
    type RespondFuture<'a>: Future<Output = Result<(), Self::Error>> + 'a + Send
    where
        Self: 'a;

    fn respond(&self, identify: Self::Identify, dns_packet: Bytes) -> Self::RespondFuture<'_>;
}

#[derive(Debug)]
pub struct UdpHandle {
    udp_socket: UdpSocket,
}

impl UdpHandle {
    pub async fn new(listen_addr: SocketAddr) -> io::Result<Self> {
        let udp_socket = UdpSocket::bind(listen_addr).await?;

        Ok(Self { udp_socket })
    }
}

#[derive(Debug, Error)]
pub enum AcceptError {
    #[error("io error: {0}")]
    IoError(#[from] io::Error),

    #[error("dns proto error: {0}")]
    ProtoError(#[from] ProtoError),
}

impl Accept for UdpHandle {
    type Error = AcceptError;
    type Identify = SocketAddr;
    type AcceptFuture<'a> = impl Future<Output = Result<(Self::Identify, Message, Bytes), Self::Error>> + 'a + Send
        where Self: 'a;

    fn accept(&self) -> Self::AcceptFuture<'_> {
        async move {
            let mut buf = BytesMut::with_capacity(4096);
            // safety: we don't read until recv
            unsafe {
                buf.set_len(4096);
            }

            let (n, source) = self.udp_socket.recv_from(&mut buf).await?;
            // safety: n bytes has been initialize
            unsafe {
                buf.set_len(n);
            }
            let buf = buf.split().freeze();

            let message = Message::from_vec(&buf)?;

            Ok((source, message, buf))
        }
    }
}

#[derive(Debug, Error)]
pub enum RespondError {
    #[error("io error: {0}")]
    IoError(#[from] io::Error),
}

impl Respond for UdpHandle {
    type Error = RespondError;
    type Identify = SocketAddr;
    type RespondFuture<'a> = impl Future<Output = Result<(), Self::Error>> + 'a + Send
        where
            Self: 'a;

    fn respond(&self, identify: Self::Identify, dns_packet: Bytes) -> Self::RespondFuture<'_> {
        async move {
            self.udp_socket.send_to(&dns_packet, identify).await?;

            Ok(())
        }
    }
}
