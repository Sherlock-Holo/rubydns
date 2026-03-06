use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;

use hickory_proto26::op::{Edns, Message};
use hickory_proto26::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use tower::Layer;

use crate::backend::{Backend, DynBackend};

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct StaticEcsFilterLayer {
    ipv4_prefix: Option<(Ipv4Addr, u8)>,
    ipv6_prefix: Option<(Ipv6Addr, u8)>,
}

impl StaticEcsFilterLayer {
    pub fn new(ipv4_prefix: Option<(Ipv4Addr, u8)>, ipv6_prefix: Option<(Ipv6Addr, u8)>) -> Self {
        StaticEcsFilterLayer {
            ipv4_prefix,
            ipv6_prefix,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct StaticEcsFilter<B> {
    ipv4_prefix: Option<(Ipv4Addr, u8)>,
    ipv6_prefix: Option<(Ipv6Addr, u8)>,
    backend: B,
}

impl<B> Layer<B> for StaticEcsFilterLayer {
    type Service = StaticEcsFilter<B>;

    fn layer(&self, inner: B) -> Self::Service {
        StaticEcsFilter {
            ipv4_prefix: self.ipv4_prefix,
            ipv6_prefix: self.ipv6_prefix,
            backend: inner,
        }
    }
}

impl Backend for StaticEcsFilter<Rc<dyn DynBackend>> {
    async fn send_request(&self, mut message: Message, src: SocketAddr) -> anyhow::Result<Message> {
        let extensions = message.extensions_mut();
        let opt = extensions.get_or_insert_with(Edns::new).options_mut();
        if opt.get(EdnsCode::Subnet).is_none() {
            let addr_and_prefix = match src.ip() {
                IpAddr::V4(_) => self
                    .ipv4_prefix
                    .map(|(addr, prefix)| (IpAddr::V4(addr), prefix)),
                IpAddr::V6(_) => self
                    .ipv6_prefix
                    .map(|(addr, prefix)| (IpAddr::V6(addr), prefix)),
            };

            if let Some((addr, prefix)) = addr_and_prefix {
                opt.insert(EdnsOption::Subnet(ClientSubnet::new(addr, prefix, 0)));
            }
        }

        self.backend.dyn_send_request(message, src).await
    }
}
