use std::collections::HashSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use compio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use compio::net::UdpSocket;
use compio::quic::crypto::rustls::QuicClientConfig;
use compio::quic::{ClientConfig, Connection, Endpoint};
use compio::runtime::JoinHandle;
use compio::{BufResult, runtime, time};
use hickory_proto26::op::{DnsResponse, Message};
use rand::rng;
use rand::seq::IteratorRandom;
use rustls::RootCertStore;
use tracing::{error, info, instrument};

use super::{Backend, DnsResponseWrapper};

#[derive(Debug)]
pub struct QuicBackend {
    connection: Rc<ArcSwap<Connection>>,
    _background_task: JoinHandle<()>,
}

impl QuicBackend {
    pub async fn new(addrs: HashSet<SocketAddr>, host: String) -> anyhow::Result<Self> {
        let mut root_cert_store = RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        if !certs.errors.is_empty() {
            return Err(anyhow::anyhow!(
                "load native cert errors: {:?}",
                certs.errors
            ));
        }
        for cert in certs.certs {
            root_cert_store.add(cert)?;
        }

        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"doq".to_vec()];

        let endpoint = Endpoint::new(
            UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)).await?,
            Default::default(),
            None,
            Some(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
                client_config,
            )?))),
        )?;

        let addr = *addrs.iter().choose(&mut rng()).unwrap();
        let connection = Self::connect_to(&endpoint, addr, &host).await?;
        let connection = Rc::new(ArcSwap::from_pointee(connection));

        let background_task = runtime::spawn(Self::check_and_reconnect(
            endpoint,
            connection.clone(),
            addrs,
            host,
        ));

        Ok(Self {
            connection,
            _background_task: background_task,
        })
    }

    async fn check_and_reconnect(
        endpoint: Endpoint,
        connection: Rc<ArcSwap<Connection>>,
        addrs: HashSet<SocketAddr>,
        host: String,
    ) {
        loop {
            let connection_guard = connection.load();
            connection_guard.closed().await;

            loop {
                time::sleep(Duration::from_secs(3)).await;
                let addr = *addrs.iter().choose(&mut rng()).unwrap();

                if let Ok(new_connection) = Self::connect_to(&endpoint, addr, &host).await {
                    info!(%addr, "reconnect to DoQ server done");

                    // arc-swap need it
                    #[allow(clippy::arc_with_non_send_sync)]
                    connection.store(Arc::new(new_connection));
                    break;
                }
            }
        }
    }

    #[instrument(skip(endpoint), ret, err)]
    async fn connect_to(
        endpoint: &Endpoint,
        addr: SocketAddr,
        host: &str,
    ) -> anyhow::Result<Connection> {
        let connection = endpoint
            .connect(addr, host, None)
            .inspect_err(|err| {
                error!(%err, "try to connect to DoQ server failed");
            })?
            .await
            .inspect_err(|err| {
                error!(%err, "connect to DoQ server failed");
            })?;

        Ok(connection)
    }
}

impl Backend for QuicBackend {
    #[instrument(skip(self), ret(Display), fields(message = %message), err)]
    async fn send_request(
        &self,
        mut message: Message,
        _src: SocketAddr,
    ) -> anyhow::Result<DnsResponseWrapper> {
        // RFC: When sending queries over a QUIC connection, the DNS Message ID MUST be set to 0.
        // The stream mapping for DoQ allows for unambiguous correlation of queries and responses,
        // so the Message ID field is not required.
        message.set_id(0);

        let request = message.to_vec()?;
        let len = request.len();
        if len > u16::MAX as _ {
            return Err(anyhow::anyhow!("message length {} too long", request.len()));
        }

        let (mut tx, mut rx) = self.connection.load().open_bi_wait().await?;

        tx.write_all((len as u16).to_be_bytes()).await.0?;
        tx.write_all(request).await.0?;
        tx.flush().await?;

        let BufResult(res, len_buf) = rx.read_exact([0; 2]).await;
        res?;
        let resp_len = u16::from_be_bytes(len_buf);

        if resp_len == 0 {
            return Err(anyhow::anyhow!("response length is 0"));
        }

        let BufResult(res, resp_data) = rx.read_exact(Vec::with_capacity(resp_len as usize)).await;
        res?;

        Ok(DnsResponse::from_buffer(resp_data)?.into())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::super::tests::{check_dns_response, create_query_message, init_tls_provider};
    use super::*;

    #[compio::test]
    async fn test() {
        init_tls_provider();

        let backend = QuicBackend::new(
            ["223.5.5.5:853".parse().unwrap()].into(),
            "dns.alidns.com".to_string(),
        )
        .await
        .unwrap();

        let dns_response = backend
            .send_request(
                create_query_message(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            )
            .await
            .unwrap();

        check_dns_response(&dns_response);
    }
}
