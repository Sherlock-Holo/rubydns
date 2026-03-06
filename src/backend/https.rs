use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;

use cyper::Client;
use cyper::resolve::Resolve;
use futures_util::{AsyncReadExt, Stream, TryStreamExt, stream};
use hickory_proto26::op::{DnsRequest, DnsRequestOptions, DnsResponse, Message};
use http::{StatusCode, Uri, Version};
use rand::rng;
use rand::seq::IteratorRandom;
use tracing::{error, instrument};

use super::{Backend, DnsResponseWrapper};

#[derive(Debug)]
pub struct HttpsBackend {
    url: String,
    client: Client,
    is_h3: bool,
}

impl HttpsBackend {
    pub fn new(url: String, ips: impl IntoIterator<Item = IpAddr>, is_h3: bool) -> Self {
        let resolver = Resolver {
            addrs: Rc::new(ips.into_iter().collect()),
        };

        let client = Client::builder()
            .custom_resolver(resolver)
            .use_rustls_default()
            .build();

        Self { url, client, is_h3 }
    }
}

impl Backend for HttpsBackend {
    #[instrument(skip(self), ret(Display), fields(message = %message), err)]
    async fn send_request(
        &self,
        message: Message,
        _src: SocketAddr,
    ) -> anyhow::Result<DnsResponseWrapper> {
        let mut options = DnsRequestOptions::default();
        options.use_edns = true;
        let request = DnsRequest::new(message, options);
        let request = request.to_vec()?;

        let version = if self.is_h3 {
            Version::HTTP_3
        } else {
            Version::HTTP_2
        };

        let response = self
            .client
            .post(&self.url)?
            .version(version)
            .header("content-type", "application/dns-message")?
            .header("accept", "application/dns-message")?
            .body(request)
            .send()
            .await?;

        let status_code = response.status();
        if status_code != StatusCode::OK {
            error!(%status_code, "status code is not 200");

            return Err(anyhow::anyhow!("status {status_code} is not 200"));
        }

        let mut resp_stream = response
            .bytes_stream()
            .map_err(io::Error::other)
            .into_async_read()
            .take(4096);

        let mut buf = Vec::with_capacity(4096);
        resp_stream.read_to_end(&mut buf).await?;

        Ok(DnsResponse::from_buffer(buf)?.into())
    }
}

#[derive(Debug, Clone)]
struct Resolver {
    addrs: Rc<HashSet<IpAddr>>,
}

impl Resolve for Resolver {
    type Err = cyper::Error;

    async fn resolve(&self, _uri: &Uri) -> Result<impl Stream<Item = IpAddr> + '_, Self::Err> {
        let addr = *self.addrs.iter().choose(&mut rng()).unwrap();

        Ok(stream::iter([addr]))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::super::tests::{check_dns_response, create_query_message, init_tls_provider};
    use super::*;

    #[compio::test]
    async fn test_h2() {
        init_tls_provider();

        let backend = HttpsBackend::new(
            "https://doh.pub/dns-query".to_string(),
            ["1.12.12.21".parse().unwrap()],
            false,
        );

        let dns_response = backend
            .send_request(
                create_query_message(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            )
            .await
            .unwrap();

        check_dns_response(&dns_response);
    }

    #[compio::test]
    async fn test_h3() {
        init_tls_provider();

        let backend = HttpsBackend::new(
            "https://dns.alidns.com/dns-query".to_string(),
            ["223.5.5.5".parse().unwrap()],
            true,
        );

        let dns_response = backend
            .send_request(
                create_query_message(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            )
            .await
            .unwrap();

        check_dns_response(&dns_response);
    }
}
