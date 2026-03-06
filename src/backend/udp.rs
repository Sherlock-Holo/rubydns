use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use compio::net::UdpSocket;
use hickory_proto26::op::{DnsRequest, DnsRequestOptions, Message};
use rand::prelude::*;
use rand::rng;
use tracing::instrument;

use super::Backend;
use crate::utils::TimeoutExt;

#[derive(Debug)]
pub struct UdpBackend {
    addrs: HashSet<SocketAddr>,
    timeout: Option<Duration>,
}

impl UdpBackend {
    pub fn new(addrs: HashSet<SocketAddr>, timeout: Option<Duration>) -> Self {
        Self { addrs, timeout }
    }

    #[instrument(skip(self), ret(Display), fields(message = %message), err)]
    async fn do_send(&self, message: Message) -> anyhow::Result<Message> {
        let id = message.id();

        let addr = self
            .addrs
            .iter()
            .choose(&mut rng())
            .expect("addrs must not empty");

        // who know why Mac doesn't support dual stack
        let bind_addr = if addr.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };

        let udp_socket = UdpSocket::bind(SocketAddr::new(bind_addr, 0)).await?;
        udp_socket.connect(*addr).await?;

        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        let request = DnsRequest::new(message, options);

        udp_socket.send(request.to_vec()?).await.0?;

        let buf = vec![0; 4096];
        let res = if let Some(timeout) = self.timeout {
            udp_socket.recv(buf).timeout(timeout).await?
        } else {
            udp_socket.recv(buf).await
        };
        res.0?;
        let data = res.1;

        let mut message = Message::from_vec(&data)?;
        message.set_id(id);

        Ok(message)
    }
}

impl Backend for UdpBackend {
    #[instrument(skip(self), ret(Display), fields(message = %message), err)]
    async fn send_request(&self, message: Message, _src: SocketAddr) -> anyhow::Result<Message> {
        let r = self.do_send(message.clone()).await;
        if r.is_ok() {
            return r;
        }

        self.do_send(message).await
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::super::tests::{check_dns_response, create_query_message};
    use super::*;

    #[compio::test]
    async fn test() {
        let backend = UdpBackend::new(
            ["119.28.28.28:53".parse().unwrap()].into(),
            Duration::from_secs(5).into(),
        );

        let response = backend
            .send_request(
                create_query_message(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            )
            .await
            .unwrap();

        check_dns_response(&response);
    }
}
