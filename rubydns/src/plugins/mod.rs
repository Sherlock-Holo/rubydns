use std::path::{Path, PathBuf};

use bytes::Bytes;
use futures_util::{stream, TryStreamExt};
use tap::TapFallible;
use thiserror::Error;
use tokio::fs;
use tracing::{error, info, instrument};
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use wasmtime::component::bindgen;
use wasmtime::Engine;

pub use self::config::Plugin as PluginConfig;
use self::pool::PluginPool;

mod config;
mod host_helper;
mod pool;

bindgen!({
    path: "../wit",
    async: true,
});

#[derive(Debug, Error)]
pub enum Error {
    #[error("plugin run error: {0}")]
    PluginRun(wasmtime::Error),

    #[error("dns proto error: {0}")]
    Proto(#[from] ProtoError),

    #[error("get plugin from pool failed: {0}")]
    PluginPool(anyhow::Error),
}

pub struct PluginChain {
    plugin: PluginPool,
}

impl PluginChain {
    pub async fn new(plugin_dir: &Path, configs: Vec<PluginConfig>) -> anyhow::Result<Self> {
        let mut engine_config = wasmtime::Config::new();
        engine_config.wasm_component_model(true).async_support(true);
        let engine = Engine::new(&engine_config)?;

        let plugin = stream::iter(configs.into_iter().rev().map(Ok))
            .try_fold(None, |next_plugin, plugin_config| {
                let engine = engine.clone();

                async move {
                    let raw_config = serde_yaml::to_string(&plugin_config.config)?;
                    let plugin_path = match plugin_config.plugin_path {
                        None => plugin_dir.join(plugin_config.name + ".wasm"),
                        Some(plugin_path) => PathBuf::from(plugin_path + ".wasm"),
                    };

                    let plugin_binary = fs::read(&plugin_path).await?;
                    let plugin_pool =
                        PluginPool::new(engine, plugin_binary.into(), raw_config, next_plugin);

                    Ok::<_, anyhow::Error>(Some(plugin_pool))
                }
            })
            .await?
            .expect("no plugin set");

        Ok(Self { plugin })
    }
}

impl PluginChain {
    #[instrument(err, skip(self, dns_packet))]
    pub async fn handle_dns(
        &self,
        mut dns_message: Message,
        dns_packet: Bytes,
    ) -> Result<(Message, Bytes), Error> {
        let mut obj = self.plugin.get_plugin().await.map_err(Error::PluginPool)?;
        let (plugin, store) = &mut *obj;

        let result = plugin
            .plugin()
            .call_run(store, &dns_packet)
            .await
            .map_err(|err| {
                error!(%err, "plugin run failed");

                Error::PluginRun(err)
            })?;

        let data = match result {
            Err(err) => {
                error!(?err, "plugin handle dns failed");

                dns_message.set_message_type(MessageType::Response);
                dns_message.set_response_code(ResponseCode::ServFail);

                let response_packet = dns_message
                    .to_vec()
                    .tap_err(|err| error!(%err, ?dns_message, "encode error dns message failed"))?;

                return Ok((dns_message, response_packet.into()));
            }

            Ok(data) => data,
        };

        info!("call plugin done");

        let response_message = Message::from_vec(&data)
            .tap_err(|err| error!(%err, "decode response dns message failed"))?;

        Ok((response_message, data.into()))
    }
}
