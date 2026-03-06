use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use async_notify::Notify;
use clap::Parser;
use clap::builder::styling;
use compio::driver::Proactor;
use compio::net::{TcpListener, UdpSocket};
use compio::runtime;
use compio::runtime::Runtime;
use flume::Receiver;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt, StreamExt, TryStreamExt, select};
use hickory_proto26::op::{Message, Query};
use hickory_proto26::rr::{Name, RData, RecordType};
use itertools::Itertools;
use nix::sys::signal;
use nix::sys::signal::{SigSet, SigmaskHow, Signal};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tower::Layer;
use tower::layer::layer_fn;
use tracing::instrument;
use tracing::{error, info};

use crate::addr::BindAddr;
use crate::backend::{
    Backend, DynBackend, Group, HttpsBackend, QuicBackend, StaticFileBackend, TlsBackend,
    UdpBackend,
};
use crate::cache::Cache;
use crate::config::{
    BackendDetail, Bind, BootstrapOrAddrs, Config, Filter, HttpsBasedBind, Proxy, RouteType,
    TcpBind, TlsBasedBind, UdpBind,
};
use crate::filter::ecs::EcsFilterLayer;
use crate::filter::static_ecs::StaticEcsFilterLayer;
use crate::layer::LayerBuilder;
use crate::log::{LogLevel, init_log};
use crate::proxy::ProxyBackend;
use crate::route::Route;
use crate::route::dnsmasq::DnsmasqExt;
use crate::server::http::HttpsServer;
use crate::server::quic::QuicServer;
use crate::server::tls::TlsServer;
use crate::server::udp::UdpServer;

mod addr;
mod backend;
mod cache;
mod config;
mod filter;
mod layer;
mod log;
mod proxy;
mod route;
mod server;
mod utils;
mod wrr;

const STYLES: styling::Styles = styling::Styles::styled()
    .header(styling::AnsiColor::Green.on_default().bold())
    .usage(styling::AnsiColor::Green.on_default().bold())
    .literal(styling::AnsiColor::Blue.on_default().bold())
    .placeholder(styling::AnsiColor::Cyan.on_default());

const DEFAULT_RETRY_ATTEMPTS: NonZeroUsize = const {
    match NonZeroUsize::new(3) {
        None => unreachable!(),
        Some(v) => v,
    }
};

const DEFAULT_SERVER_IDLE: Duration = Duration::from_secs(30);

#[derive(Debug, Parser)]
#[command(styles = STYLES)]
pub struct Args {
    #[clap(short, long, env)]
    /// Config path
    config: String,

    #[clap(short, long, env, default_value = "info")]
    /// Log level
    log_level: LogLevel,

    #[clap(long, env)]
    /// OpenTelemetry OTLP gRPC endpoint (e.g. http://apm.example.com:4317 for insecure, https://apm.example.com:443 for TLS)
    otel_endpoint: Option<String>,

    #[clap(long, env)]
    /// OpenTelemetry auth token (will be sent as Bearer token if not already prefixed)
    otel_token: Option<String>,

    #[clap(long, env, default_value = "0.01")]
    /// OpenTelemetry trace sampling rate (0.0-1.0, e.g. 0.01 for 1%)
    otel_sampling_rate: f64,
}

pub async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    // Must block process signals before any subsystem may spawn background threads.
    block_signal()?;

    let _guard = init_log(
        args.log_level,
        args.otel_endpoint,
        args.otel_token,
        args.otel_sampling_rate,
    )?;
    init_tls_provider();

    let Config {
        workers,
        proxy,
        backend,
    } = Config::read(&args.config)?;

    info!(config = %args.config, "edns-proxy config loaded");

    let workers = workers.count();
    let (shutdown_notify, shutdown_waiters, worker_result_rx) =
        spawn_proxy_workers(proxy, backend, workers)?;

    info!(workers, "proxy workers started");

    let mut worker_results = worker_result_rx.into_stream();

    select! {
        res = signal_stop().fuse() => {
            res?;

            info!("shutdown signal received, stopping proxy workers");

            shutdown_notify.notify_n(NonZeroUsize::new(shutdown_waiters).unwrap());
        }

        res = worker_results.next() => {
            res.unwrap()?;
        }
    }

    while let Some(res) = worker_results.next().await {
        res?;
    }

    Ok(())
}

async fn collect_backends(
    cfg_backends: &[config::Backend],
) -> anyhow::Result<HashMap<String, Rc<dyn DynBackend>>> {
    let mut backend_groups = HashMap::new();
    let mut backends = HashMap::with_capacity(cfg_backends.len());
    for backend in cfg_backends {
        let name = &backend.name;
        let backend_type = backend.backend_detail.backend_type();
        if backends.contains_key(name) {
            return Err(anyhow::anyhow!(
                "{backend_type} backend '{name}' already exists"
            ));
        }

        let backend: Rc<dyn DynBackend> = match &backend.backend_detail {
            BackendDetail::Tls(config::TlsBackend {
                tls_name,
                port,
                bootstrap_or_addrs,
            }) => {
                let addrs = match bootstrap_or_addrs {
                    BootstrapOrAddrs::Bootstrap(bootstrap) => {
                        bootstrap_domain(bootstrap, tls_name, *port).await?
                    }
                    BootstrapOrAddrs::Addr(addrs) => addrs.clone(),
                };

                Rc::new(TlsBackend::new(addrs, tls_name.clone())?)
            }

            BackendDetail::Udp(config::UdpBackend { addr, timeout }) => Rc::new(UdpBackend::new(
                addr.iter().copied().collect(),
                timeout.map(|timeout| timeout.into_inner()),
            )),

            BackendDetail::Https(config::HttpsBackend { url, ips }) => {
                Rc::new(HttpsBackend::new(url.clone(), ips.iter().copied(), false))
            }

            BackendDetail::Quic(config::TlsBackend {
                tls_name,
                port,
                bootstrap_or_addrs,
            }) => {
                let addrs = match bootstrap_or_addrs {
                    BootstrapOrAddrs::Bootstrap(bootstrap) => {
                        bootstrap_domain(bootstrap, tls_name, *port).await?
                    }
                    BootstrapOrAddrs::Addr(addrs) => addrs.clone(),
                };

                Rc::new(QuicBackend::new(addrs, tls_name.to_string()).await?)
            }

            BackendDetail::H3(config::HttpsBackend { url, ips }) => {
                Rc::new(HttpsBackend::new(url.clone(), ips.iter().copied(), true))
            }

            BackendDetail::StaticFile(static_config) => {
                let static_file_backend_config = static_config.load()?;
                Rc::new(StaticFileBackend::new(static_file_backend_config)?)
            }

            BackendDetail::Group(backend_info_list) => {
                backend_groups.insert(name, backend_info_list);

                continue;
            }
        };

        info!("create {backend_type} backend '{name}' done");

        backends.insert(name.to_string(), backend);
    }

    for (name, group_backend) in backend_groups {
        let grouped_backends: Vec<(usize, Rc<dyn DynBackend>)> = group_backend
            .backends
            .iter()
            .map(|info| {
                backends
                    .get(&info.name)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("backend '{}' not found", info.name))
                    .map(|backend| (info.weight, backend))
            })
            .try_collect()?;

        let group = Group::new(grouped_backends);

        info!("create group backend '{name}' done");

        backends.insert(name.to_string(), Rc::new(group));
    }

    Ok(backends)
}

async fn run_server_until_shutdown(
    bind_addr: BindAddr,
    backend: Rc<dyn DynBackend>,
    shutdown: Arc<Notify>,
) -> anyhow::Result<()> {
    match bind_addr {
        BindAddr::Udp(addr) => {
            info!(%addr, "starting UDP DNS server");

            let udp_socket = create_udp_socket_reuse_port(addr)?;
            let server = UdpServer::new(udp_socket, backend)?;

            select! {
                _ = shutdown.notified().fuse() => Ok(()),
                _ = server.run().fuse() => Ok(()),
            }
        }

        BindAddr::Tcp { .. } => {
            todo!("tcp server not implemented yet");
        }

        BindAddr::Tls {
            addr,
            certificate,
            private_key,
            timeout,
        } => {
            info!(%addr, idle = ?timeout.unwrap_or(DEFAULT_SERVER_IDLE), "starting TLS DNS server");

            let tcp_listener = create_tcp_listener_reuse_port(addr)?;
            let server = TlsServer::new(
                tcp_listener,
                certificate,
                private_key,
                backend,
                timeout.unwrap_or(DEFAULT_SERVER_IDLE),
            )?;

            select! {
                _ = shutdown.notified().fuse() => Ok(()),
                res = server.run().fuse() => res,
            }
        }

        BindAddr::Quic {
            addr,
            certificate,
            private_key,
            timeout,
        } => {
            info!(%addr, idle = ?timeout.unwrap_or(DEFAULT_SERVER_IDLE), "starting QUIC DNS server");

            let udp_socket = create_udp_socket_reuse_port(addr)?;
            let server = QuicServer::new(
                udp_socket,
                certificate,
                private_key,
                backend,
                timeout.unwrap_or(DEFAULT_SERVER_IDLE),
            )?;

            select! {
                _ = shutdown.notified().fuse() => Ok(()),
                res = server.run().fuse() => res,
            }
        }

        BindAddr::Https {
            addr,
            certificate,
            private_key,
            path,
            ..
        } => {
            info!(%addr, path = %path, "starting HTTPS DNS server");

            let tcp_listener = create_tcp_listener_reuse_port(addr)?;
            let server =
                HttpsServer::new_h2(tcp_listener, certificate, private_key, path, backend)?;

            select! {
                _ = shutdown.notified().fuse() => Ok(()),
                res = server.run().fuse() => res,
            }
        }

        BindAddr::H3 {
            addr,
            certificate,
            private_key,
            ..
        } => {
            info!(%addr, path = "/dns-query", "starting HTTP/3 DNS server");

            let udp_socket = create_udp_socket_reuse_port(addr)?;
            let server = HttpsServer::new_h3(
                udp_socket,
                certificate,
                private_key,
                "/dns-query".to_string(),
                backend,
            )?;

            select! {
                _ = shutdown.notified().fuse() => Ok(()),
                res = server.run().fuse() => res,
            }
        }
    }
}

fn create_udp_socket_reuse_port(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(addr))?;
    let std_socket = std::net::UdpSocket::from(socket);
    UdpSocket::from_std(std_socket).map_err(Into::into)
}

fn create_tcp_listener_reuse_port(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(addr))?;
    socket.listen(1024)?;
    let std_listener = std::net::TcpListener::from(socket);
    TcpListener::from_std(std_listener).map_err(Into::into)
}

type SpawnResult = (Arc<Notify>, usize, Receiver<anyhow::Result<()>>);

fn spawn_proxy_workers(
    proxy_configs: Vec<Proxy>,
    backend_configs: Vec<config::Backend>,
    threads: usize,
) -> anyhow::Result<SpawnResult> {
    let shutdown_notify = Arc::new(Notify::new());
    let (worker_result_tx, worker_result_rx) = flume::unbounded();
    let proxy_configs = Arc::<[Proxy]>::from(proxy_configs);
    let backend_configs = Arc::<[config::Backend]>::from(backend_configs);
    let shutdown_waiters = threads * proxy_configs.len();

    for _ in 0..threads {
        let shutdown = shutdown_notify.clone();
        let backend_configs = backend_configs.clone();
        let proxy_configs = proxy_configs.clone();
        let worker_result_tx = worker_result_tx.clone();

        thread::spawn(move || {
            let mut builder = Runtime::builder();
            let mut proactor_builder = Proactor::builder();
            proactor_builder
                .capacity(128)
                .coop_taskrun(true)
                .taskrun_flag(true);

            let runtime = builder.with_proactor(proactor_builder).build().unwrap();

            let run_result = runtime.block_on(async move {
                let backends = select! {
                    _ = shutdown.notified().fuse() => {
                        return Ok(());
                    }
                    res = collect_backends(&backend_configs).fuse() => res?,
                };
                let mut servers = FuturesUnordered::new();

                for proxy in proxy_configs.iter().cloned() {
                    let bind_addr = create_bind_addr(proxy.bind)?;
                    let default_backend = backends
                        .get(&proxy.backend)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("backend '{}' not found", proxy.backend))?;
                    let default_backend = filter_backend(proxy.filter, default_backend);

                    let mut route = Route::default();
                    for route_config in proxy.route {
                        let backend =
                            backends
                                .get(&route_config.backend)
                                .cloned()
                                .ok_or_else(|| {
                                    anyhow::anyhow!("backend '{}' not found", route_config.backend)
                                })?;
                        let backend = filter_backend(route_config.filter, backend);

                        match route_config.route_type {
                            RouteType::Normal { path } => {
                                let file = File::open(path)
                                    .inspect_err(|err| error!(%err, "open normal file failed"))?;
                                route.import(file, backend)?;
                            }

                            RouteType::Dnsmasq { path } => {
                                let file = File::open(path)
                                    .inspect_err(|err| error!(%err, "open dnsmasq file failed"))?;
                                route.import_from_dnsmasq(file, backend)?;
                            }
                        }
                    }

                    let retry_attempts = proxy.retry_attempts.unwrap_or(DEFAULT_RETRY_ATTEMPTS);
                    let proxy_backend = ProxyBackend::new(
                        proxy.cache.map(|c| {
                            Cache::new(c.capacity, c.ipv4_fuzz_prefix, c.ipv6_fuzz_prefix)
                        }),
                        default_backend,
                        route,
                        retry_attempts,
                    );

                    info!(
                        ?bind_addr,
                        backend = %proxy.backend,
                        retry_attempts = retry_attempts.get(),
                        "proxy worker initialized"
                    );

                    servers.push(runtime::spawn(run_server_until_shutdown(
                        bind_addr,
                        Rc::new(proxy_backend),
                        shutdown.clone(),
                    )));
                }

                while let Some(res) = servers
                    .try_next()
                    .await
                    .map_err(|err| anyhow::anyhow!("proxy panic: {err:?}"))?
                {
                    res?;
                }

                Ok(())
            });

            let _ = worker_result_tx.send(run_result);
        });
    }

    Ok((shutdown_notify, shutdown_waiters, worker_result_rx))
}

fn filter_backend(filter: Vec<Filter>, backend: Rc<dyn DynBackend>) -> Rc<dyn DynBackend> {
    let mut layer_builder = LayerBuilder::new();
    for filter in filter {
        match filter {
            Filter::EdnsClientSubnet {
                ipv4_prefix,
                ipv6_prefix,
            } => {
                let layer = EcsFilterLayer::new(ipv4_prefix, ipv6_prefix);

                layer_builder = layer_builder.layer(layer_fn(move |backend| {
                    Rc::new(layer.layer(backend)) as Rc<dyn DynBackend>
                }));
            }

            Filter::StaticEdnsClientSubnet { ipv4, ipv6 } => {
                let layer = StaticEcsFilterLayer::new(
                    ipv4.map(|cfg| (cfg.ip, cfg.prefix)),
                    ipv6.map(|cfg| (cfg.ip, cfg.prefix)),
                );

                layer_builder = layer_builder.layer(layer_fn(move |backend| {
                    Rc::new(layer.layer(backend)) as Rc<dyn DynBackend>
                }));
            }
        }
    }

    layer_builder.build(backend)
}

#[instrument(ret, err)]
async fn bootstrap_domain(
    bootstrap_addr: &HashSet<SocketAddr>,
    domain: &str,
    port: u16,
) -> anyhow::Result<HashSet<SocketAddr>> {
    let backend = UdpBackend::new(bootstrap_addr.clone(), Some(Duration::from_secs(5)));
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let name = Name::from_utf8(domain)?;
    let mut addrs = HashSet::new();

    let mut query_a = Message::query();
    query_a.add_query(Query::query(name.clone(), RecordType::A));
    if let Ok(resp) = backend.send_request(query_a, src).await {
        addrs.extend(
            resp.answers()
                .iter()
                .filter_map(|record| match record.data() {
                    RData::A(ip) => Some(SocketAddr::new(ip.0.into(), port)),
                    _ => None,
                }),
        );
    }

    let mut query_aaaa = Message::query();
    query_aaaa.add_query(Query::query(name, RecordType::AAAA));
    if let Ok(resp) = backend.send_request(query_aaaa, src).await {
        addrs.extend(
            resp.answers()
                .iter()
                .filter_map(|record| match record.data() {
                    RData::AAAA(ip) => Some(SocketAddr::new(ip.0.into(), port)),
                    _ => None,
                }),
        );
    }

    if addrs.is_empty() {
        return Err(anyhow::anyhow!(
            "bootstrap domain '{}' resolved to empty set",
            domain
        ));
    }
    Ok(addrs)
}

fn create_bind_addr(bind: Bind) -> anyhow::Result<BindAddr> {
    let bind_addr = match bind {
        Bind::Udp(UdpBind { bind_addr }) => BindAddr::Udp(bind_addr),

        Bind::Tcp(TcpBind { bind_addr, timeout }) => BindAddr::Tcp {
            addr: bind_addr,
            timeout: timeout.map(|timeout| timeout.into_inner()),
        },

        Bind::Https(HttpsBasedBind {
            bind_addr,
            bind_domain,
            bind_path,
            timeout,
            private_key,
            certificate,
        }) => {
            let certs = load_certificates_from_pem(&certificate)?;
            let private_key = load_private_key_from_file(&private_key)?;
            BindAddr::Https {
                addr: bind_addr,
                certificate: certs,
                private_key,
                domain: bind_domain,
                path: bind_path,
                timeout: timeout.map(|timeout| timeout.into_inner()),
            }
        }

        Bind::Tls(TlsBasedBind {
            bind_addr,
            bind_tls_name: _bind_tls_name,
            timeout,
            private_key,
            certificate,
        }) => {
            let certs = load_certificates_from_pem(&certificate)?;
            let private_key = load_private_key_from_file(&private_key)?;
            BindAddr::Tls {
                addr: bind_addr,
                certificate: certs,
                private_key,
                timeout: timeout.map(|timeout| timeout.into_inner()),
            }
        }

        Bind::Quic(TlsBasedBind {
            bind_addr,
            bind_tls_name: _bind_tls_name,
            timeout,
            private_key,
            certificate,
        }) => {
            let certs = load_certificates_from_pem(&certificate)?;
            let private_key = load_private_key_from_file(&private_key)?;
            BindAddr::Quic {
                addr: bind_addr,
                certificate: certs,
                private_key,
                timeout: timeout.map(|timeout| timeout.into_inner()),
            }
        }

        Bind::H3(HttpsBasedBind {
            bind_addr,
            bind_domain: _bind_domain,
            bind_path: _bind_path,
            timeout,
            private_key,
            certificate,
        }) => {
            let certs = load_certificates_from_pem(&certificate)?;
            let private_key = load_private_key_from_file(&private_key)?;
            BindAddr::H3 {
                addr: bind_addr,
                certificate: certs,
                private_key,
                timeout: timeout.map(|timeout| timeout.into_inner()),
            }
        }
    };

    Ok(bind_addr)
}

async fn signal_stop() -> anyhow::Result<()> {
    const SIGTERM: i32 = 15;
    select! {
        res = compio::signal::ctrl_c().fuse() => { res?; }
        res = compio::signal::unix::signal(SIGTERM).fuse() => { res?; }
    }

    Ok(())
}

fn init_tls_provider() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    provider
        .install_default()
        .expect("install crypto provider should succeed");
}

fn load_certificates_from_pem(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .map(|res| res.map_err(anyhow::Error::from))
        .try_collect()
}

fn load_private_key_from_file(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    Ok(PrivateKeyDer::from_pem_file(path)?)
}

fn block_signal() -> anyhow::Result<()> {
    let mut sig_set = SigSet::empty();
    sig_set.add(Signal::SIGINT);
    sig_set.add(Signal::SIGTERM);

    signal::pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&sig_set), None)?;

    Ok(())
}
