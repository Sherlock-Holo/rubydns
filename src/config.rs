use std::collections::HashSet;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::thread;
use std::time::Duration;

use humantime_serde::Serde;
use serde::{Deserialize, Deserializer, de};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default, deserialize_with = "deserialize_workers_config")]
    pub workers: WorkersConfig,
    pub proxy: Vec<Proxy>,
    pub backend: Vec<Backend>,
}

impl Config {
    pub fn read(path: &str) -> anyhow::Result<Self> {
        let file = File::open(path)?;

        Ok(serde_yaml::from_reader(file)?)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Proxy {
    #[serde(flatten)]
    pub bind: Bind,
    pub backend: String,
    #[serde(default)]
    pub filter: Vec<Filter>,
    pub cache: Option<Cache>,
    #[serde(default)]
    pub route: Vec<Route>,
    pub retry_attempts: Option<NonZeroUsize>,
}

#[derive(Debug, Default, Clone)]
pub enum WorkersConfig {
    #[default]
    Auto,
    Count(usize),
}

fn deserialize_workers_config<'de, D>(deserializer: D) -> Result<WorkersConfig, D::Error>
where
    D: Deserializer<'de>,
{
    let value = <String>::deserialize(deserializer)?;
    if value.eq_ignore_ascii_case("auto") {
        return Ok(WorkersConfig::Auto);
    }

    value
        .parse::<usize>()
        .map_err(de::Error::custom)
        .map(WorkersConfig::Count)
}

impl WorkersConfig {
    pub fn count(&self) -> usize {
        match self {
            WorkersConfig::Auto => thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4),
            WorkersConfig::Count(n) => (*n).max(1),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Bind {
    Udp(UdpBind),
    Tcp(TcpBind),
    Tls(TlsBasedBind),
    Quic(TlsBasedBind),
    Https(HttpsBasedBind),
    H3(HttpsBasedBind),
}

#[derive(Debug, Deserialize, Clone)]
pub struct UdpBind {
    pub bind_addr: SocketAddr,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TcpBind {
    pub bind_addr: SocketAddr,
    pub timeout: Option<Serde<Duration>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HttpsBasedBind {
    pub bind_addr: SocketAddr,
    pub bind_domain: Option<String>,
    #[serde(default = "HttpsBasedBind::default_bind_path")]
    pub bind_path: String,
    pub timeout: Option<Serde<Duration>>,
    pub private_key: String,
    pub certificate: String,
}

impl HttpsBasedBind {
    fn default_bind_path() -> String {
        "/dns-query".to_string()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsBasedBind {
    pub bind_addr: SocketAddr,
    pub bind_tls_name: Option<String>,
    pub timeout: Option<Serde<Duration>>,
    pub private_key: String,
    pub certificate: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Backend {
    pub name: String,
    #[serde(flatten)]
    pub backend_detail: BackendDetail,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendDetail {
    Tls(TlsBackend),
    Udp(UdpBackend),
    Https(HttpsBackend),
    H3(HttpsBackend),
    Quic(TlsBackend),
    StaticFile(StaticFileBackend),

    Group(GroupBackend),
}

/// Configuration for static file backend (used for deserialization)
#[derive(Debug, Deserialize, Clone)]
pub struct StaticFileBackend {
    pub file: String,
}

impl StaticFileBackend {
    pub fn load(&self) -> anyhow::Result<StaticFileBackendConfig> {
        let file = File::open(&self.file)?;
        let records = serde_yaml::from_reader(file)?;

        Ok(StaticFileBackendConfig { records })
    }
}

/// Runtime data for static file backend (contains parsed records)
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct StaticFileBackendConfig {
    pub records: Vec<StaticRecord>,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct StaticRecord {
    pub domain: String,
    pub ips: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsBackend {
    pub tls_name: String,
    #[serde(default = "TlsBackend::default_port")]
    pub port: u16,
    #[serde(flatten)]
    pub bootstrap_or_addrs: BootstrapOrAddrs,
}

impl TlsBackend {
    const fn default_port() -> u16 {
        853
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct HttpsBackend {
    pub url: String,
    pub ips: HashSet<IpAddr>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapOrAddrs {
    Bootstrap(HashSet<SocketAddr>),
    Addr(HashSet<SocketAddr>),
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct UdpBackend {
    pub addr: Vec<SocketAddr>,
    pub timeout: Option<Serde<Duration>>,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct GroupBackend {
    pub backends: Vec<GroupBackendInfo>,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct GroupBackendInfo {
    pub name: String,
    pub weight: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Route {
    #[serde(flatten)]
    pub route_type: RouteType,
    pub backend: String,
    #[serde(default)]
    pub filter: Vec<Filter>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RouteType {
    Normal { path: String },
    Dnsmasq { path: String },
}

#[derive(Debug, Deserialize, Clone)]
pub struct Cache {
    #[serde(default = "Cache::default_capacity")]
    pub capacity: NonZeroUsize,
    #[serde(default = "Cache::default_ipv4_fuzz_prefix")]
    pub ipv4_fuzz_prefix: u8,
    #[serde(default = "Cache::default_ipv6_fuzz_prefix")]
    pub ipv6_fuzz_prefix: u8,
}

impl Cache {
    const fn default_capacity() -> NonZeroUsize {
        NonZeroUsize::new(100).unwrap()
    }

    const fn default_ipv4_fuzz_prefix() -> u8 {
        16
    }

    const fn default_ipv6_fuzz_prefix() -> u8 {
        64
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Filter {
    EdnsClientSubnet {
        ipv4_prefix: Option<u8>,
        ipv6_prefix: Option<u8>,
    },

    StaticEdnsClientSubnet {
        ipv4: Option<StaticEdnsClientSubnetIpv4>,
        ipv6: Option<StaticEdnsClientSubnetIpv6>,
    },
}

#[derive(Debug, Deserialize, Clone)]
pub struct StaticEdnsClientSubnetIpv4 {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StaticEdnsClientSubnetIpv6 {
    pub ip: Ipv6Addr,
    pub prefix: u8,
}
