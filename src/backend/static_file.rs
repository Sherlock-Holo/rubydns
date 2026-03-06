use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use hickory_proto26::op::{DnsResponse, Message, ResponseCode};
use hickory_proto26::rr::{Name, RData, Record, RecordType};
use tracing::{info, instrument};

use super::{Backend, DnsResponseWrapper};
use crate::config::StaticFileBackendConfig;

const DEFAULT_TTL: u32 = 3600; // 1 hour

#[derive(Debug, Clone, Ord, PartialOrd)]
struct DomainKey(Name);

impl DomainKey {
    fn from_name(mut name: Name) -> Self {
        name.set_fqdn(true);

        Self(name)
    }
}

impl PartialEq for DomainKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_root(&other.0)
    }
}

impl Eq for DomainKey {}

#[derive(Debug)]
pub struct StaticFileBackend {
    exact_matches: BTreeMap<DomainKey, Vec<RData>>,
    wildcard_matches: HashMap<String, Vec<RData>>,
}

impl StaticFileBackend {
    pub fn new(config: StaticFileBackendConfig) -> anyhow::Result<Self> {
        info!(?config, "create static file backend");

        let mut exact_matches = BTreeMap::new();
        let mut wildcard_matches = HashMap::new();

        for record in config.records {
            let ips = record
                .ips
                .iter()
                .map(|ip| {
                    if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                        Ok(RData::A(ipv4.into()))
                    } else if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
                        Ok(RData::AAAA(ipv6.into()))
                    } else {
                        Err(anyhow::anyhow!("Invalid IP address: {}", ip))
                    }
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            match record.domain.strip_prefix("*.") {
                None => {
                    let name = Name::from_utf8(&record.domain)?;
                    exact_matches.insert(DomainKey::from_name(name), ips);
                }
                Some(suffix) => {
                    let name = Name::from_utf8(suffix)?;
                    wildcard_matches
                        .insert(normalize_domain_str(&mut name.to_string()).to_string(), ips);
                }
            }
        }

        info!("created static file backend inner done");

        Ok(Self {
            exact_matches,
            wildcard_matches,
        })
    }

    #[instrument(skip(self), ret(Display), fields(message = %message), err)]
    fn lookup_and_build_response(&self, message: Message) -> anyhow::Result<DnsResponseWrapper> {
        let query = message
            .queries()
            .first()
            .ok_or_else(|| anyhow::anyhow!("No query in message"))?;

        let query_name = query.name();
        let query_type = query.query_type();

        info!("Static backend lookup: {} {}", query_name, query_type);

        let ips = self.lookup_ips(query_name.clone(), query_type);

        let mut response = Message::response(message.id(), message.op_code());
        response.set_id(message.id());
        response.set_recursion_desired(message.recursion_desired());
        response.set_recursion_available(true);
        response.add_query(query.clone());

        if let Some(ips) = ips {
            for ip in ips {
                let record = Record::from_rdata(query_name.clone(), DEFAULT_TTL, ip);
                response.add_answer(record);
            }
            response.set_response_code(ResponseCode::NoError);
        } else {
            response.set_response_code(ResponseCode::NXDomain);
        }

        DnsResponse::from_message(response)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn lookup_ips(&self, query_name: Name, query_type: RecordType) -> Option<Vec<RData>> {
        let query_key = DomainKey::from_name(query_name);

        if let Some(found) = self.exact_matches.get(&query_key) {
            let filtered = Self::filter_by_type(found, query_type);
            if !filtered.is_empty() {
                return Some(filtered);
            }
        }

        let mut query_key = query_key.0.to_string();
        let query_trimmed = normalize_domain_str(&mut query_key);
        for (suffix, rdata_list) in self.wildcard_matches.iter() {
            if query_trimmed == *suffix || query_trimmed.ends_with(suffix) {
                let filtered = Self::filter_by_type(rdata_list, query_type);
                if !filtered.is_empty() {
                    return Some(filtered);
                }
            }
        }

        None
    }

    #[inline]
    fn filter_by_type(ips: &[RData], query_type: RecordType) -> Vec<RData> {
        match query_type {
            RecordType::A => ips
                .iter()
                .filter(|ip| matches!(ip, RData::A(_)))
                .cloned()
                .collect(),

            RecordType::AAAA => ips
                .iter()
                .filter(|ip| matches!(ip, RData::AAAA(_)))
                .cloned()
                .collect(),

            _ => ips.to_vec(),
        }
    }
}

fn normalize_domain_str(input: &mut str) -> &str {
    input.make_ascii_lowercase();
    input.trim_end_matches('.')
}

impl Backend for StaticFileBackend {
    async fn send_request(
        &self,
        message: Message,
        _src: SocketAddr,
    ) -> anyhow::Result<DnsResponseWrapper> {
        self.lookup_and_build_response(message)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use hickory_proto26::op::Query;

    use super::*;
    use crate::config::StaticRecord;

    fn create_query_message(domain: &str, record_type: RecordType) -> Message {
        let mut message = Message::query();
        message.add_query(Query::query(Name::from_utf8(domain).unwrap(), record_type));
        message.set_recursion_desired(true);
        message
    }

    fn dummy_socket_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)
    }

    #[compio::test]
    async fn test_exact_match() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".to_string()],
            }],
        };

        let backend = StaticFileBackend::new(config).unwrap();

        let message = create_query_message("example.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let record = &response.answers()[0];
        assert_eq!(record.record_type(), RecordType::A);
        if let RData::A(ip) = record.data() {
            assert_eq!(ip.0, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("Expected A record");
        }
    }

    #[compio::test]
    async fn test_wildcard_match() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "*.test.com".to_string(),
                ips: vec!["5.6.7.8".to_string()],
            }],
        };

        let backend = StaticFileBackend::new(config).unwrap();

        let message = create_query_message("test.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();
        assert_eq!(response.answers().len(), 1);

        let message = create_query_message("a.test.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();
        assert_eq!(response.answers().len(), 1);

        let message = create_query_message("a.b.test.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();
        assert_eq!(response.answers().len(), 1);
    }

    #[compio::test]
    async fn test_no_match() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".to_string()],
            }],
        };

        let backend = StaticFileBackend::new(config).unwrap();

        let message = create_query_message("other.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();

        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert_eq!(response.answers().len(), 0);
    }

    #[compio::test]
    async fn test_multiple_ips() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "example.com".to_string(),
                ips: vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
            }],
        };

        let backend = StaticFileBackend::new(config).unwrap();

        let message = create_query_message("example.com", RecordType::A);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 2);
    }

    #[compio::test]
    async fn test_ipv6() {
        let config = StaticFileBackendConfig {
            records: vec![StaticRecord {
                domain: "example.com".to_string(),
                ips: vec!["2001:db8::1".to_string()],
            }],
        };

        let backend = StaticFileBackend::new(config).unwrap();

        let message = create_query_message("example.com", RecordType::AAAA);
        let response = backend
            .send_request(message, dummy_socket_addr())
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let record = &response.answers()[0];
        assert_eq!(record.record_type(), RecordType::AAAA);
    }
}
