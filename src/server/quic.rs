use std::fmt::Debug;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use compio::buf::IoBuf;
use compio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use compio::net::UdpSocket;
use compio::quic::crypto::rustls::QuicServerConfig;
use compio::quic::{Endpoint, EndpointConfig, ServerConfig};
use compio::runtime;
use compio_quic::congestion::BbrConfig;
use compio_quic::{Connection, RecvStream, SendStream, TransportConfig};
use hickory_proto26::op::Message;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, error, instrument};

use crate::backend::DynBackend;
use crate::utils::{BytesMutObject, BytesMutPool, PartsExt};

pub struct QuicServer {
    endpoint: Endpoint,
    backend: Rc<dyn DynBackend>,
    bytes_mut_pool: BytesMutPool,
}

impl Debug for QuicServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicServer")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl QuicServer {
    pub fn new(
        udp_socket: UdpSocket,
        certificate: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        backend: Rc<dyn DynBackend>,
        idle: Duration,
    ) -> anyhow::Result<Self> {
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificate, private_key)?;

        server_config.alpn_protocols = vec![b"doq".to_vec()];

        let quic_server_config = QuicServerConfig::try_from(server_config)?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        let mut transport_config = TransportConfig::default();
        transport_config
            .congestion_controller_factory(Arc::new(BbrConfig::default()))
            .max_idle_timeout(Some(idle.try_into()?));
        server_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::new(
            udp_socket,
            EndpointConfig::default(),
            Some(server_config),
            None,
        )?;

        Ok(Self {
            endpoint,
            backend,
            bytes_mut_pool: BytesMutPool::new(4096),
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        loop {
            let incoming = self
                .endpoint
                .wait_incoming()
                .await
                .ok_or_else(|| anyhow::anyhow!("endpoint closed unexpectedly"))?;

            debug!(?incoming, "accepted new incoming connection");

            let backend = self.backend.clone();
            let bytes_mut_pool = self.bytes_mut_pool.clone();
            runtime::spawn(async move {
                let connection = match incoming.await {
                    Ok(conn) => conn,
                    Err(err) => {
                        error!(%err, "accept connection failed");
                        return Err(err.into());
                    }
                };

                debug!(?connection, "accepted new QUIC connection");

                Self::handle_connection(connection, backend, bytes_mut_pool).await
            })
            .detach();
        }
    }

    async fn handle_connection(
        connection: Connection,
        backend: Rc<dyn DynBackend>,
        bytes_mut_pool: BytesMutPool,
    ) -> anyhow::Result<()> {
        let peer_addr = connection.remote_address();

        loop {
            let (tx, rx) = connection
                .accept_bi()
                .await
                .with_context(|| "accept QUIC bi stream failed")?;

            debug!(?connection, %peer_addr, "accepted new QUIC bi stream");

            let backend = backend.clone();
            let buf = bytes_mut_pool.get_bytes_mut().await;
            runtime::spawn(Self::handle_stream(tx, rx, backend, buf, peer_addr)).detach();
        }
    }

    #[instrument(skip(tx, rx, backend), ret, err)]
    async fn handle_stream(
        mut tx: SendStream,
        mut rx: RecvStream,
        backend: Rc<dyn DynBackend>,
        buf: BytesMutObject,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        // Read request length
        let len = rx
            .read_u16()
            .await
            .with_context(|| "read dns request length failed")? as usize;

        if len == 0 {
            error!(%peer_addr, "dns request length is 0");
            return Err(anyhow::anyhow!("dns request length is 0"));
        }

        let (res, buf) = rx.read_exact(buf.slice(..len)).await.to_parts();
        res.with_context(|| format!("read dns request with length {len} failed"))?;

        // Parse DNS message
        let message = Message::from_vec(&buf).with_context(|| "parse dns message failed")?;

        // Send request to backend
        let response_message = backend.dyn_send_request(message, peer_addr).await?;
        let response_data = response_message
            .to_vec()
            .with_context(|| "serialize dns response failed")?;

        // Send response length
        tx.write_u16(response_data.len() as _)
            .await
            .with_context(|| "write dns response length failed")?;

        // Send response data
        tx.write_all(response_data)
            .await
            .0
            .with_context(|| "write dns response failed")?;
        tx.flush()
            .await
            .with_context(|| "flush dns stream failed")?;

        Ok(())
    }
}
