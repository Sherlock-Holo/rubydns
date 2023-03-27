use bincode::{DefaultOptions, Options};
use tracing::error;
use trust_dns_proto::op::{Message, MessageType};

use crate::cache_key::{CacheKey, QueryDef};
use crate::helper::{call_next_plugin, map_get, map_set};
use crate::plugin::{Error, Plugin};

mod cache_key;

wit_bindgen::generate!("rubydns");

#[derive(Debug)]
struct CacheRunner;

impl Plugin for CacheRunner {
    fn run(dns_packet: Vec<u8>) -> Result<Vec<u8>, Error> {
        let request_message = Message::from_vec(&dns_packet).map_err(|err| {
            error!(%err, "decode dns request packet failed");

            Error {
                code: 1,
                msg: err.to_string(),
            }
        })?;

        let cache_key = CacheKey {
            query: request_message
                .queries()
                .iter()
                .map(|query| QueryDef::from(query.clone()))
                .collect(),
        };

        let cache_key = DefaultOptions::new().serialize(&cache_key).map_err(|err| {
            error!(%err, ?cache_key, "encode cache key failed");

            Error {
                code: 1,
                msg: err.to_string(),
            }
        })?;

        match map_get(&cache_key) {
            None => call_next_and_set_cache(&dns_packet, cache_key),
            Some(response_packet) => create_response_from_cache(&dns_packet, response_packet),
        }
    }

    fn valid_config() -> Result<(), Error> {
        Ok(())
    }
}

fn call_next_and_set_cache(dns_packet: &[u8], cache_key: Vec<u8>) -> Result<Vec<u8>, Error> {
    let response_packet = match call_next_plugin(dns_packet) {
        None => {
            return Err(Error {
                code: 1,
                msg: "no next plugin".to_string(),
            })
        }

        Some(result) => result?,
    };

    let message = Message::from_vec(&response_packet).map_err(|err| {
        error!(%err, "decode dns packet failed");

        Error {
            code: 1,
            msg: err.to_string(),
        }
    })?;

    if let Some(ttl) = message.answers().iter().map(|answer| answer.ttl()).min() {
        map_set(&cache_key, &response_packet, Some(ttl as _));
    }

    Ok(response_packet)
}

fn create_response_from_cache(
    dns_packet: &[u8],
    response_packet: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let request_message = Message::from_vec(dns_packet).map_err(|err| {
        error!(%err, "decode dns request packet failed");

        Error {
            code: 1,
            msg: err.to_string(),
        }
    })?;

    let response_message = Message::from_vec(&response_packet).map_err(|err| {
        error!(%err, "decode dns response packet failed");

        Error {
            code: 1,
            msg: err.to_string(),
        }
    })?;

    let mut request_message = request_message.into_parts();

    request_message
        .header
        .set_message_type(MessageType::Response)
        .set_response_code(response_message.response_code())
        .set_answer_count(response_message.answer_count())
        .set_additional_count(response_message.additional_count())
        .set_authoritative(response_message.authoritative());
    request_message
        .answers
        .extend_from_slice(response_message.answers());
    request_message
        .additionals
        .extend_from_slice(response_message.additionals());

    let request_message = Message::from(request_message);
    let data = request_message.to_vec().map_err(|err| {
        error!(%err, "encode dns response packet failed");

        Error {
            code: 1,
            msg: err.to_string(),
        }
    })?;

    Ok(data)
}

export_rubydns!(CacheRunner);
