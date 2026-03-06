mod group;
mod https;
mod quic;
mod static_file;
mod tls;
mod udp;

use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

use futures_util::FutureExt;
use futures_util::future::LocalBoxFuture;
use hickory_proto26::op::{DnsResponse, Message};

pub use self::group::Group;
pub use self::https::HttpsBackend;
pub use self::quic::QuicBackend;
pub use self::static_file::StaticFileBackend;
pub use self::tls::TlsBackend;
pub use self::udp::UdpBackend;

pub trait Backend {
    async fn send_request(
        &self,
        message: Message,
        src: SocketAddr,
    ) -> anyhow::Result<DnsResponseWrapper>;
}

#[derive(Clone)]
pub struct DnsResponseWrapper(pub DnsResponse);

impl DnsResponseWrapper {
    pub fn into_inner(self) -> DnsResponse {
        self.0
    }

    pub fn into_buffer(self) -> Vec<u8> {
        self.0.into_buffer()
    }
}

impl From<DnsResponse> for DnsResponseWrapper {
    fn from(value: DnsResponse) -> Self {
        DnsResponseWrapper(value)
    }
}

impl From<DnsResponseWrapper> for DnsResponse {
    fn from(value: DnsResponseWrapper) -> Self {
        value.0
    }
}

impl Deref for DnsResponseWrapper {
    type Target = DnsResponse;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DnsResponseWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Debug for DnsResponseWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Message as Debug>::fmt(&self.0, f)
    }
}

impl Display for DnsResponseWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Message as Display>::fmt(&self.0, f)
    }
}

pub trait DynBackend {
    fn dyn_send_request(
        &self,
        message: Message,
        src: SocketAddr,
    ) -> LocalBoxFuture<'_, anyhow::Result<DnsResponseWrapper>>;
}

impl<T: Backend> DynBackend for T {
    fn dyn_send_request(
        &self,
        message: Message,
        src: SocketAddr,
    ) -> LocalBoxFuture<'_, anyhow::Result<DnsResponseWrapper>> {
        self.send_request(message, src).boxed_local()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Once;

    use hickory_proto26::op::{DnsResponse, Message, Query};
    use hickory_proto26::rr::{Name, RData, RecordType};

    pub fn create_query_message() -> Message {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_utf8("www.example.com").unwrap(),
            RecordType::A,
        ));
        message.set_recursion_desired(true);

        message
    }

    #[track_caller]
    pub fn check_dns_response(dns_response: &DnsResponse) {
        let answers = dns_response.answers();
        dbg!(answers);

        assert!(answers.iter().any(|record| {
            let data = record.data();
            match data {
                RData::A(ip) => ip.0 == Ipv4Addr::new(104, 18, 26, 120),
                _ => false,
            }
        }));
    }

    pub fn init_tls_provider() {
        static INSTALL_ONCE: Once = Once::new();

        INSTALL_ONCE.call_once(|| {
            let provider = rustls::crypto::aws_lc_rs::default_provider();

            provider
                .install_default()
                .expect("install crypto provider should succeed");
        })
    }
}
