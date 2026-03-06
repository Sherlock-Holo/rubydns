use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use compio::BufResult;
use compio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use compio::net::TcpStream;
use compio::tls::{TlsConnector, TlsStream};
use deadpool::managed::{Manager, Metrics, Object, Pool, RecycleResult};
use hickory_proto26::op::Message;
use rand::rng;
use rand::seq::IteratorRandom;
use rustls::{ClientConfig, RootCertStore};
use send_wrapper::SendWrapper;
use tracing::{debug, instrument};

use super::Backend;

#[derive(Debug)]
pub struct TlsBackend {
    pool: Pool<TlsStreamManager>,
}

impl Backend for TlsBackend {
    #[instrument(skip(self), ret(Display), fields(message = %message), err)]
    async fn send_request(&self, message: Message, _: SocketAddr) -> anyhow::Result<Message> {
        let id = message.id();
        let request_data = message.to_vec()?;
        let mut tls_stream = self.pool.get().await?;

        match self.send_and_recv(&mut tls_stream, request_data).await {
            Err(err) => {
                let _ = Object::take(tls_stream);

                Err(err)
            }

            Ok(mut resp) => {
                resp.set_id(id);

                Ok(resp)
            }
        }
    }
}

impl TlsBackend {
    pub fn new(addrs: HashSet<SocketAddr>, name: String) -> anyhow::Result<Self> {
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

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        Ok(Self {
            pool: Pool::builder(TlsStreamManager {
                addrs,
                name,
                tls_connector: Arc::new(client_config).into(),
            })
            .build()?,
        })
    }

    #[instrument(skip(request_data), ret(Display), err)]
    async fn send_and_recv(
        &self,
        tls_stream: &mut TlsStream<TcpStream>,
        request_data: Vec<u8>,
    ) -> anyhow::Result<Message> {
        let request_len = (request_data.len() as u16).to_be_bytes();

        tls_stream.write_all(request_len).await.0?;
        tls_stream.write_all(request_data).await.0?;
        tls_stream.flush().await?;

        debug!("send request done");

        let BufResult(res, len_buf) = tls_stream.read_exact([0; 2]).await;
        res?;
        let resp_len = u16::from_be_bytes(len_buf);

        if resp_len == 0 {
            return Err(anyhow::anyhow!("response length is 0"));
        }

        let BufResult(res, resp_data) = tls_stream
            .read_exact(Vec::with_capacity(resp_len as usize))
            .await;
        res?;

        Message::from_vec(&resp_data).map_err(Into::into)
    }
}

#[derive(Debug)]
struct TlsStreamManager {
    addrs: HashSet<SocketAddr>,
    name: String,
    tls_connector: TlsConnector,
}

impl Manager for TlsStreamManager {
    type Type = SendWrapper<TlsStream<TcpStream>>;
    type Error = io::Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        SendWrapper::new(async {
            let addr = *self.addrs.iter().choose(&mut rng()).unwrap();

            let tcp_stream = TcpStream::connect(addr).await?;
            let tls_stream = self.tls_connector.connect(&self.name, tcp_stream).await?;

            Ok(SendWrapper::new(tls_stream))
        })
        .await
    }

    async fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        Ok(())
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

        let backend = TlsBackend::new(
            ["1.12.12.21:853".parse().unwrap()].into(),
            "dot.pub".to_string(),
        )
        .unwrap();

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
