use std::ops::DerefMut;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use deadpool::managed;
use deadpool::managed::{Pool, RecycleResult};
use host::command;
use tap::TapFallible;
use thiserror::Error;
use tracing::{error, info};
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

use super::helper;
use super::host_helper::HostHelper;
use super::tcp_helper;
use super::udp_helper;
use super::Rubydns;
use crate::plugins::host_helper::StoreValue;

#[derive(Clone)]
pub struct PluginPool {
    pool: Pool<Manager>,
}

impl PluginPool {
    pub async fn new(
        engine: Engine,
        plugin_binary: Bytes,
        raw_config: String,
        next_plugin: Option<PluginPool>,
    ) -> anyhow::Result<Self> {
        let pool = Pool::builder(Manager {
            engine,
            plugin_binary,
            raw_config: Arc::new(raw_config),
            next_plugin,
            plugin_store_map: Arc::new(Default::default()),
        })
        .build()
        .expect("build plugin pool failed");

        let plugin_pool = Self { pool };
        plugin_pool.validate_config().await?;

        info!(raw_config = %plugin_pool.pool.manager().raw_config, "plugin config valid");

        Ok(plugin_pool)
    }

    pub async fn get_plugin(
        &self,
    ) -> anyhow::Result<impl DerefMut<Target = (Rubydns, Store<HostHelper>)> + '_> {
        Ok(self.pool.get().await?)
    }

    async fn validate_config(&self) -> anyhow::Result<()> {
        let mut object = self
            .pool
            .get()
            .await
            .tap_err(|err| error!(%err, "get plugin failed"))?;
        let (plugin, store) = &mut *object;

        match plugin
            .plugin()
            .call_valid_config(store)
            .await
            .tap_err(|err| error!(%err, "call plugin valid config failed"))?
        {
            Err(err) => {
                error!(?err, raw_config = %self.pool.manager().raw_config, "plugin config invalid");

                Err(anyhow::anyhow!("plugin config invalid: {err:?}"))
            }

            Ok(()) => Ok(()),
        }
    }
}

#[derive(Debug, Error)]
#[error("{source}")]
pub struct Error {
    #[source]
    #[from]
    source: wasmtime::Error,
}

struct Manager {
    engine: Engine,
    plugin_binary: Bytes,
    raw_config: Arc<String>,
    next_plugin: Option<PluginPool>,
    plugin_store_map: Arc<DashMap<Bytes, StoreValue>>,
}

#[async_trait]
impl managed::Manager for Manager {
    type Type = (Rubydns, Store<HostHelper>);
    type Error = Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let mut linker = Linker::new(&self.engine);
        let mut store = Store::new(
            &self.engine,
            HostHelper::new(
                self.raw_config.clone(),
                self.next_plugin.clone(),
                self.plugin_store_map.clone(),
            ),
        );

        store.out_of_fuel_async_yield(u64::MAX, 10000);

        helper::add_to_linker(&mut linker, |state: &mut HostHelper| state)
            .tap_err(|err| error!(%err, "helper add to linker failed"))?;
        command::add_to_linker(&mut linker, |state: &mut HostHelper| state.wasi_ctx())
            .tap_err(|err| error!(%err, "command add to linker failed"))?;
        udp_helper::add_to_linker(&mut linker, |state: &mut HostHelper| state.udp_helper())
            .tap_err(|err| error!(%err, "udp_helper add to linker failed"))?;
        tcp_helper::add_to_linker(&mut linker, |state: &mut HostHelper| state.tcp_helper())
            .tap_err(|err| error!(%err, "tcp_helper add to linker failed"))?;

        let component = Component::new(&self.engine, &self.plugin_binary)?;
        let (plugin, _) = Rubydns::instantiate_async(&mut store, &component, &linker).await?;

        Ok((plugin, store))
    }

    async fn recycle(&self, obj: &mut Self::Type) -> RecycleResult<Self::Error> {
        let store = &mut obj.1;
        store.data_mut().reset();
        store.out_of_fuel_async_yield(u64::MAX, 10000);

        Ok(())
    }
}
