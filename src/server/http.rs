use std::convert::Infallible;
use std::fmt::Debug;
use std::future::{Ready, poll_fn, ready};
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};

use anyhow::Context;
use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bytes::Buf;
use bytes::{Bytes, BytesMut};
use compio::net::UdpSocket;
use compio::net::{TcpListener, TcpStream};
use compio::quic::crypto::rustls::QuicServerConfig;
use compio::quic::{EndpointConfig, ServerConfig as QuicServerConfigInner};
use compio::runtime;
use compio::tls::{TlsAcceptor, TlsStream};
use compio_quic::h3::server::RequestResolver;
use compio_quic::{Endpoint, h3};
use cyper_axum::Listener;
use futures_util::future::LocalBoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt, StreamExt, select, stream};
use hickory_proto26::op::Message;
use http::{Request as HttpRequest, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Limited, StreamBody};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use send_wrapper::SendWrapper;
use tower::Service;
use tower_http::trace::TraceLayer;
use tracing::{error, info, instrument};

use crate::backend::DynBackend;

#[derive(Debug)]
struct HttpError(anyhow::Error);

impl From<anyhow::Error> for HttpError {
    fn from(e: anyhow::Error) -> Self {
        HttpError(e)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::new(self.0.to_string()))
            .unwrap()
    }
}

#[derive(Clone, Debug)]
struct PeerAddrMakeService<S> {
    inner: S,
}

impl<S> PeerAddrMakeService<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

#[derive(Clone, Debug)]
struct PeerAddrService<S> {
    inner: S,
    remote_addr: SocketAddr,
}

impl<ReqBody, S> Service<HttpRequest<ReqBody>> for PeerAddrService<S>
where
    S: Service<HttpRequest<ReqBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: HttpRequest<ReqBody>) -> Self::Future {
        req.extensions_mut().insert(self.remote_addr);
        self.inner.call(req)
    }
}

pub struct HttpsServer {
    kind: HttpServerKind,
    path: String,
    backend: Rc<dyn DynBackend>,
}

impl Debug for HttpsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsServer")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl HttpsServer {
    pub fn new_h2(
        tcp_listener: TcpListener,
        certificate: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        path: String,
        backend: Rc<dyn DynBackend>,
    ) -> anyhow::Result<HttpsServer> {
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificate, private_key)?;

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        Ok(Self {
            kind: HttpServerKind::Http2 {
                tls_acceptor,
                tcp_listener,
            },
            path,
            backend,
        })
    }

    pub fn new_h3(
        udp_socket: UdpSocket,
        certificate: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        path: String,
        backend: Rc<dyn DynBackend>,
    ) -> anyhow::Result<HttpsServer> {
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificate, private_key)?;
        let quic_server_config = QuicServerConfig::try_from(server_config)?;
        let endpoint = Endpoint::new(
            udp_socket,
            EndpointConfig::default(),
            Some(QuicServerConfigInner::with_crypto(Arc::new(
                quic_server_config,
            ))),
            None,
        )?;

        Ok(Self {
            kind: HttpServerKind::Http3 { endpoint },
            path,
            backend,
        })
    }

    #[inline]
    async fn handle(
        Extension(src): Extension<SocketAddr>,
        backend: State<SendWrapper<Rc<dyn DynBackend>>>,
        req: Request,
    ) -> Result<Response, HttpError> {
        HttpsServer::do_handle(req, src, backend)
            .await
            .map_err(Into::into)
    }

    #[instrument(skip(backend), ret, err)]
    async fn do_handle(
        req: Request,
        src: SocketAddr,
        backend: State<SendWrapper<Rc<dyn DynBackend>>>,
    ) -> anyhow::Result<Response> {
        let body = Limited::new(req.into_body(), 4096)
            .collect()
            .await
            .map_err(|err| anyhow::Error::msg(err.to_string()))?
            .to_bytes();

        let message = Message::from_vec(&body).with_context(|| "parse dns message failed")?;

        let dns_response = SendWrapper::new(backend.dyn_send_request(message, src)).await?;

        Ok(Response::new(Body::from(dns_response.into_buffer())))
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let router = Router::new()
            .route(&self.path, post(Self::handle))
            .layer(TraceLayer::new_for_http())
            .with_state(SendWrapper::new(self.backend));

        match self.kind {
            HttpServerKind::Http2 {
                tls_acceptor,
                tcp_listener,
            } => {
                let tls_listener = TlsListener {
                    tls_acceptor,
                    tcp_listener,
                    tls_accept_futs: Default::default(),
                };

                cyper_axum::serve(tls_listener, PeerAddrMakeService::new(router)).await?;
            }
            HttpServerKind::Http3 { endpoint } => {
                Self::run_h3(endpoint, router).await?;
            }
        }

        Err(anyhow::anyhow!("http server stopped unexpectedly"))
    }

    async fn run_h3(endpoint: Endpoint, router: Router) -> anyhow::Result<()> {
        while let Some(incoming) = endpoint.wait_incoming().await {
            match incoming.await {
                Err(err) => {
                    error!(%err, "accept QUIC incoming failed");
                    continue;
                }

                Ok(connection) => {
                    let router = router.clone();
                    runtime::spawn(async move {
                        if let Err(err) = Self::handle_h3_connection(connection, router).await {
                            error!(%err, "h3 connection error");
                        }
                    })
                    .detach();
                }
            }
        }

        Err(anyhow::anyhow!("http3 server stopped unexpectedly"))
    }

    async fn handle_h3_connection(
        connection: compio_quic::Connection,
        router: Router,
    ) -> anyhow::Result<()> {
        let mut h3_server_connection = h3::server::Connection::new(connection).await?;

        while let Some(request) = h3_server_connection.accept().await.transpose() {
            let request = match request {
                Err(err) => {
                    error!(%err, "accept h3 connection failed");
                    continue;
                }

                Ok(request) => request,
            };

            let router = router.clone();
            runtime::spawn(async move {
                if let Err(err) = Self::handle_h3_request(request, router).await {
                    error!(%err, "handle h3 request error");
                }
            })
            .detach();
        }

        info!("h3 connection stopped");
        Ok(())
    }

    #[instrument(skip_all, ret, err)]
    async fn handle_h3_request(
        request_resolver: RequestResolver<compio_quic::Connection, Bytes>,
        mut router: Router,
    ) -> anyhow::Result<()> {
        let (raw_req, req_stream) = request_resolver.resolve_request().await?;

        let mut req_builder = Request::builder()
            .version(raw_req.version())
            .uri(raw_req.uri())
            .method(raw_req.method());

        for (k, v) in raw_req.headers() {
            req_builder = req_builder.header(k, v);
        }

        let (mut send_stream, recv_stream) = req_stream.split();
        let mut recv_stream = SendWrapper::new(recv_stream);
        let mut no_more_data = false;
        let body = Body::new(StreamBody::new(stream::poll_fn(move |cx| {
            loop {
                if no_more_data {
                    return recv_stream
                        .poll_recv_trailers(cx)
                        .map(|res| res.transpose().map(|res| res.map(Frame::trailers)));
                }

                let res = ready!(recv_stream.poll_recv_data(cx)).transpose();
                match res {
                    None => {
                        no_more_data = true;
                        continue;
                    }

                    Some(res) => {
                        return Poll::Ready(Some(res.map(|mut data| {
                            let mut buf = BytesMut::with_capacity(data.remaining());
                            while data.has_remaining() {
                                buf.extend_from_slice(data.chunk());
                                data.advance(data.chunk().len());
                            }

                            Frame::data(buf.freeze())
                        })));
                    }
                }
            }
        })));

        let request = req_builder
            .body(body)
            .with_context(|| "create request failed")?;

        poll_fn(|cx| Service::<Request>::poll_ready(&mut router, cx)).await?;

        let mut response = router.call(request).await?;

        // send response
        let mut raw_response_builder = http::Response::builder()
            .status(response.status())
            .version(response.version());

        for (k, v) in response.headers() {
            raw_response_builder = raw_response_builder.header(k, v);
        }

        send_stream
            .send_response(raw_response_builder.body(())?)
            .await?;

        while let Some(frame) = response.body_mut().frame().await {
            let frame = frame.with_context(|| "receive response frame failed")?;
            if frame.is_data() {
                send_stream
                    .send_data(frame.into_data().unwrap())
                    .await
                    .with_context(|| "send response data to send_stream failed")?;
            } else if frame.is_trailers() {
                send_stream
                    .send_trailers(frame.into_trailers().unwrap())
                    .await
                    .with_context(|| "send response trailers to send_stream failed")?;
            }
        }

        Ok(())
    }
}

enum HttpServerKind {
    Http2 {
        tls_acceptor: TlsAcceptor,
        tcp_listener: TcpListener,
    },
    Http3 {
        endpoint: Endpoint,
    },
}

impl<S> Service<cyper_axum::IncomingStream<'_, TlsListener>> for PeerAddrMakeService<S>
where
    S: Clone,
{
    type Response = PeerAddrService<S>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, stream: cyper_axum::IncomingStream<'_, TlsListener>) -> Self::Future {
        ready(Ok(PeerAddrService {
            inner: self.inner.clone(),
            remote_addr: *stream.remote_addr(),
        }))
    }
}

type TlsAcceptFuture =
    LocalBoxFuture<'static, Result<(TlsStream<TcpStream>, SocketAddr), io::Error>>;

struct TlsListener {
    tls_acceptor: TlsAcceptor,
    tcp_listener: TcpListener,
    tls_accept_futs: FuturesUnordered<TlsAcceptFuture>,
}

impl TlsListener {
    #[instrument(skip(self))]
    fn push_accept_tls_fut(&self, tcp_stream: TcpStream, peer_addr: SocketAddr) {
        let tls_acceptor = self.tls_acceptor.clone();
        self.tls_accept_futs.push(
            async move {
                let tls_stream = tls_acceptor
                    .accept(tcp_stream)
                    .await
                    .inspect_err(|err| error!(%err, "tls accept failed"))?;

                Ok::<_, io::Error>((tls_stream, peer_addr))
            }
            .boxed_local(),
        );
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let tcp_listener = &self.tcp_listener;
        let mut accept_fut = pin!(tcp_listener.accept().fuse());
        loop {
            if self.tls_accept_futs.is_empty() {
                let (tcp_stream, peer_addr) = match accept_fut.as_mut().await {
                    Err(err) => {
                        error!(%err, "accept new tcp stream failed");

                        accept_fut.set(tcp_listener.accept().fuse());
                        continue;
                    }

                    Ok((tcp_stream, peer_addr)) => (tcp_stream, peer_addr),
                };

                accept_fut.set(tcp_listener.accept().fuse());
                self.push_accept_tls_fut(tcp_stream, peer_addr);
            }

            select! {
                res = self.tls_accept_futs.next() => {
                    if let Some(Ok(res)) = res {
                        return res
                    }
                }

                res = accept_fut.as_mut() => {
                    accept_fut.set(tcp_listener.accept().fuse());

                    match res {
                        Err(err) => {
                            error!(%err, "accept new tcp stream failed");
                        }

                        Ok((tcp_stream, peer_addr)) => {
                            self.push_accept_tls_fut(tcp_stream, peer_addr);
                        }
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp_listener.local_addr()
    }
}
