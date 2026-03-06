use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Instant;

use cidr::IpInet;
use hickory_proto26::op::{DnsResponse, Query};
use quick_cache::sync::Cache as S3FifoCache;

#[derive(Debug)]
pub struct Cache {
    inner: S3FifoCache<RequestKey, CacheResponse>,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
}

impl Cache {
    pub fn new(capacity: NonZeroUsize, ipv4_prefix: u8, ipv6_prefix: u8) -> Self {
        Self {
            inner: S3FifoCache::new(capacity.get()),
            ipv4_prefix,
            ipv6_prefix,
        }
    }

    pub fn get_cache_response(&self, query: Query, src_ip: IpAddr) -> Option<DnsResponse> {
        let prefix = match src_ip {
            IpAddr::V4(_) => self.ipv4_prefix,
            IpAddr::V6(_) => self.ipv6_prefix,
        };
        let ip_inet = IpInet::new(src_ip, prefix).ok()?.first();
        self.get_response(query, ip_inet)
    }

    pub fn put_cache_response(&self, query: Query, src_ip: IpAddr, response: DnsResponse) {
        let prefix = match src_ip {
            IpAddr::V4(_) => self.ipv4_prefix,
            IpAddr::V6(_) => self.ipv6_prefix,
        };
        let Some(ip_inet) = IpInet::new(src_ip, prefix).ok().map(|i| i.first()) else {
            return;
        };
        self.add_response(query, ip_inet, response);
    }

    fn get_response(&self, query: Query, src_ip: IpInet) -> Option<DnsResponse> {
        let key = RequestKey { query, src_ip };
        let mut cache_resp = self.inner.get(&key)?;
        let elapsed = cache_resp.cache_time.elapsed().as_secs() as u32;
        let ttl = cache_resp.ttl;

        if elapsed >= ttl {
            self.inner.remove(&key);
            None
        } else {
            for answer in cache_resp.response.answers_mut() {
                answer.set_ttl(ttl - elapsed);
            }
            Some(cache_resp.response)
        }
    }

    fn add_response(&self, query: Query, src_ip: IpInet, response: DnsResponse) {
        let ttl = match response.answers().iter().map(|record| record.ttl()).min() {
            None => return,
            Some(0) => return,
            Some(ttl) => ttl,
        };

        let key = RequestKey { query, src_ip };
        self.inner.insert(
            key,
            CacheResponse {
                response,
                ttl,
                cache_time: Instant::now(),
            },
        );
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct RequestKey {
    query: Query,
    src_ip: IpInet,
}

#[derive(Debug, Clone)]
struct CacheResponse {
    response: DnsResponse,
    ttl: u32,
    cache_time: Instant,
}
