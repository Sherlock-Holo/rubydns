use std::fmt::Debug;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::BytesMut;
use compio::buf::{IntoInner, IoBuf};
use compio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use compio::net::{TcpListener, TcpStream};
use compio::runtime;
use compio::tls::{TlsAcceptor, TlsStream};
use hickory_proto26::op::Message;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, error, info, instrument};

use crate::backend::DynBackend;
use crate::utils::{PartsExt, TimeoutExt};

pub struct TlsServer {
    tls_acceptor: TlsAcceptor,
    tcp_listener: TcpListener,
    backend: Rc<dyn DynBackend>,
    idle: Duration,
}

impl Debug for TlsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServer")
            .field("tcp_listener", &self.tcp_listener)
            .finish_non_exhaustive()
    }
}

impl TlsServer {
    pub fn new(
        tcp_listener: TcpListener,
        certificate: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        backend: Rc<dyn DynBackend>,
        idle: Duration,
    ) -> anyhow::Result<Self> {
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificate, private_key)?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        Ok(Self {
            tls_acceptor,
            tcp_listener,
            backend,
            idle,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        loop {
            let (tcp_stream, peer_addr) = match self.tcp_listener.accept().await {
                Err(err) => {
                    error!(%err, "accept new TCP stream failed");

                    continue;
                }

                Ok(res) => res,
            };

            debug!(?tcp_stream, %peer_addr, "accepted new TCP stream");

            let tls_acceptor = self.tls_acceptor.clone();
            let backend = self.backend.clone();
            let idle = self.idle;
            runtime::spawn(async move {
                let tls_stream = tls_acceptor.accept(tcp_stream).await?;

                debug!(?tls_stream, %peer_addr, "accepted new TLS stream");

                Self::handle_tls_stream(tls_stream, peer_addr, backend, idle).await
            })
            .detach();
        }
    }

    async fn handle_tls_stream(
        mut tls_stream: TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        backend: Rc<dyn DynBackend>,
        idle: Duration,
    ) -> anyhow::Result<()> {
        let mut buf = BytesMut::with_capacity(4096);

        loop {
            buf.clear();

            let len = match tls_stream.read_u16().timeout(idle).await {
                Err(_) => {
                    info!(
                        ?tls_stream,
                        ?peer_addr,
                        "read length timeout, close the tls stream"
                    );

                    tls_stream.shutdown().await?;

                    return Ok(());
                }

                Ok(res) => res.with_context(|| "read dns request length failed")? as usize,
            };

            if len == 0 {
                error!("dns request length is 0");

                return Err(anyhow::anyhow!("dns request length is 0"));
            }

            buf = Self::handle_tls_stream_once(&mut tls_stream, len, buf, peer_addr, &*backend)
                .timeout(idle)
                .await??;
        }
    }

    #[instrument(skip(buf, backend), err)]
    async fn handle_tls_stream_once(
        tls_stream: &mut TlsStream<TcpStream>,
        len: usize,
        mut buf: BytesMut,
        peer_addr: SocketAddr,
        backend: &dyn DynBackend,
    ) -> anyhow::Result<BytesMut> {
        buf.reserve(len);
        let (res, buf) = tls_stream.read_exact(buf.slice(..len)).await.to_parts();
        res.with_context(|| format!("read dns request with length {len} failed"))?;

        let message = Message::from_vec(&buf).with_context(|| "parse dns message failed")?;
        let dns_response = backend.dyn_send_request(message, peer_addr).await?;
        let response_data = dns_response.into_buffer();

        tls_stream
            .write_u16(response_data.len() as _)
            .await
            .with_context(|| "write dns response failed")?;
        tls_stream
            .write_all(response_data)
            .await
            .0
            .with_context(|| "write dns response failed")?;
        tls_stream
            .flush()
            .await
            .with_context(|| "flush dns stream failed")?;

        Ok(buf.into_inner())
    }
}
