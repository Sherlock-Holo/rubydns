use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use plugin_utils::net::udp::UdpSocket;
use serde::Deserialize;
use tracing::error;

use crate::helper::load_config;
use crate::plugin::{Error, Plugin};

wit_bindgen::generate!("rubydns");

#[derive(Debug, Deserialize)]
struct Config {
    nameservers: Vec<SocketAddr>,
}

#[derive(Debug)]
struct ProxyRunner;

impl Plugin for ProxyRunner {
    fn run(dns_packet: Vec<u8>) -> Result<Vec<u8>, Error> {
        let config = load_config();
        let config: Config = serde_yaml::from_str(&config).map_err(|err| {
            error!(%err, "load proxy config failed");

            Error {
                code: 1,
                msg: err.to_string(),
            }
        })?;

        for nameserver in config.nameservers {
            match handle_dns(&dns_packet, nameserver) {
                Err(_) => continue,
                Ok(action) => return Ok(action),
            }
        }

        Err(Error {
            code: 1,
            msg: "all nameserver failed".to_string(),
        })
    }

    fn valid_config() -> Result<(), Error> {
        serde_yaml::from_str::<Config>(&load_config()).map_err(|err| {
            error!(%err, "load proxy config failed");

            Error {
                code: 1,
                msg: err.to_string(),
            }
        })?;

        Ok(())
    }
}

fn handle_dns(dns_packet: &[u8], nameserver: SocketAddr) -> Result<Vec<u8>, Error> {
    let udp_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
        .map_err(|err| {
            error!(%err, "bind udp socket failed");

            Error {
                code: err.raw_os_error().unwrap_or(1) as _,
                msg: err.to_string(),
            }
        })?;

    udp_socket.connect(nameserver).map_err(|err| {
        error!(%err, %nameserver, "connect nameserver failed");

        Error {
            code: err.raw_os_error().unwrap_or(1) as _,
            msg: err.to_string(),
        }
    })?;

    udp_socket.send(dns_packet).map_err(|err| {
        error!(%err, %nameserver, "send dns packet failed");

        Error {
            code: err.raw_os_error().unwrap_or(1) as _,
            msg: err.to_string(),
        }
    })?;

    let data = udp_socket.recv_size(4096).map_err(|err| {
        error!(%err, %nameserver, "recv dns packet failed");

        Error {
            code: err.raw_os_error().unwrap_or(1) as _,
            msg: err.to_string(),
        }
    })?;

    Ok(data)
}

export_rubydns!(ProxyRunner);
