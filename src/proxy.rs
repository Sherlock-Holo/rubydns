use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::rc::Rc;

use hickory_proto26::op::{DnsResponse, Message};

use crate::backend::{Backend, DnsResponseWrapper, DynBackend};
use crate::cache::Cache;
use crate::route::Route;
use crate::utils::retry;

pub struct ProxyBackend {
    cache: Option<Cache>,
    default_backend: Rc<dyn DynBackend>,
    route: Route,
    attempts: NonZeroUsize,
}

impl ProxyBackend {
    pub fn new(
        cache: Option<Cache>,
        default_backend: Rc<dyn DynBackend>,
        route: Route,
        attempts: NonZeroUsize,
    ) -> Self {
        Self {
            cache,
            default_backend,
            route,
            attempts,
        }
    }
}

impl Backend for ProxyBackend {
    async fn send_request(
        &self,
        message: Message,
        src: SocketAddr,
    ) -> anyhow::Result<DnsResponseWrapper> {
        let query = message
            .queries()
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no query found"))?;

        if let Some(cache) = &self.cache
            && let Some(resp) = cache.get_cache_response(query.clone(), src.ip())
        {
            return Ok(resp.into());
        }

        let backend = self
            .route
            .get_backend(query.name())
            .unwrap_or_else(|| self.default_backend.as_ref());
        let response = retry(self.attempts, || {
            backend.dyn_send_request(message.clone(), src)
        })
        .await?;

        if let Some(cache) = &self.cache {
            let dns_response: DnsResponse = response.clone().into();
            cache.put_cache_response(query, src.ip(), dns_response);
        }

        Ok(response)
    }
}
