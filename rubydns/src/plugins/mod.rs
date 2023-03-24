use std::path::{Path, PathBuf};

use bytes::Bytes;
use thiserror::Error;
use tokio::fs;
use tracing::instrument;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::op::Message;
use wasmtime::component::bindgen;
use wasmtime::Engine;

pub use self::config::Plugin as PluginConfig;
use self::plugin::Action;
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

    #[error("plugin handle dns error: {0}")]
    PluginHandle(plugin::Error),
}

pub struct PluginChain {
    plugins: Vec<PluginState>,
}

impl PluginChain {
    pub async fn new(plugin_dir: &Path, configs: Vec<PluginConfig>) -> anyhow::Result<Self> {
        let mut engine_config = wasmtime::Config::new();
        engine_config.wasm_component_model(true).async_support(true);
        let engine = Engine::new(&engine_config)?;

        let mut plugins = Vec::with_capacity(configs.len());
        for plugin_config in configs {
            let raw_config = serde_yaml::to_string(&plugin_config.config)?;
            let plugin_path = match plugin_config.plugin_path {
                None => plugin_dir.join(plugin_config.name + ".wasm"),
                Some(plugin_path) => PathBuf::from(plugin_path + ".wasm"),
            };

            let plugin_binary = fs::read(&plugin_path).await?;
            let plugin_pool = PluginPool::new(engine.clone(), plugin_binary.into(), raw_config);

            plugins.push(PluginState { plugin_pool });
        }

        Ok(Self { plugins })
    }
}

impl PluginChain {
    #[instrument(err, skip(self, dns_packet))]
    pub async fn handle_dns(
        &self,
        mut dns_message: Message,
        mut dns_packet: Bytes,
    ) -> Result<(Message, Bytes), Error> {
        for dns_plugin in &self.plugins {
            let mut obj = dns_plugin
                .plugin_pool
                .get_plugin()
                .await
                .map_err(Error::PluginPool)?;
            let (plugin, store) = &mut *obj;
            store
                .data_mut()
                .update(dns_message.clone(), dns_packet.clone());

            let result = plugin
                .plugin()
                .call_run(store)
                .await
                .map_err(Error::PluginRun)?;

            let action = match result {
                Err(err) => return Err(Error::PluginHandle(err)),
                Ok(action) => action,
            };

            match action {
                Action::Responed(response) => {
                    let response_message = Message::from_vec(&response)?;

                    return Ok((response_message, Bytes::from(response)));
                }

                Action::Next(response) => {
                    if let Some(response) = response {
                        dns_packet = response.into();
                        dns_message = Message::from_vec(&dns_packet)?;
                    }
                }
            }
        }

        todo!("send dns packet back?")
    }
}

struct PluginState {
    plugin_pool: PluginPool,
}
