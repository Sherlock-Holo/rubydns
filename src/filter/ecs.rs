use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;

use hickory_proto26::op::{Edns as Edns26, Message as Message26};
use hickory_proto26::rr::rdata::opt::{
    ClientSubnet as ClientSubnet26, EdnsCode as EdnsCode26, EdnsOption as EdnsOption26,
};
use tower::Layer;

use crate::backend::{Backend, DnsResponseWrapper, DynBackend};

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EcsFilterLayer {
    ipv4_prefix: Option<u8>,
    ipv6_prefix: Option<u8>,
}

impl EcsFilterLayer {
    pub fn new(ipv4_prefix: Option<u8>, ipv6_prefix: Option<u8>) -> Self {
        EcsFilterLayer {
            ipv4_prefix,
            ipv6_prefix,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct EcsFilter<B> {
    ipv4_prefix: Option<u8>,
    ipv6_prefix: Option<u8>,
    backend: B,
}

impl<B> Layer<B> for EcsFilterLayer {
    type Service = EcsFilter<B>;

    fn layer(&self, inner: B) -> Self::Service {
        EcsFilter {
            ipv4_prefix: self.ipv4_prefix,
            ipv6_prefix: self.ipv6_prefix,
            backend: inner,
        }
    }
}

impl Backend for EcsFilter<Rc<dyn DynBackend>> {
    async fn send_request(
        &self,
        mut message: Message26,
        src: SocketAddr,
    ) -> anyhow::Result<DnsResponseWrapper> {
        let extensions = message.extensions_mut();
        let opt = extensions.get_or_insert_with(Edns26::new).options_mut();
        if opt.get(EdnsCode26::Subnet).is_none() {
            let src_ip = src.ip();
            let prefix = match src_ip {
                IpAddr::V4(_) => self.ipv4_prefix,
                IpAddr::V6(_) => self.ipv6_prefix,
            };

            if let Some(prefix) = prefix {
                opt.insert(EdnsOption26::Subnet(ClientSubnet26::new(src_ip, prefix, 0)));
            }
        }

        self.backend.dyn_send_request(message, src).await
    }
}
