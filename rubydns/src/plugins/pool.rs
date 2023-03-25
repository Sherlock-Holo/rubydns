use std::ops::DerefMut;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use deadpool::managed;
use deadpool::managed::{Pool, RecycleResult};
use host::command;
use thiserror::Error;
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

use super::helper;
use super::host_helper::HostHelper;
use super::udp_helper;
use super::Rubydns;

pub struct PluginPool {
    pool: Pool<Manager>,
}

impl PluginPool {
    pub fn new(engine: Engine, plugin_binary: Bytes, raw_config: String) -> Self {
        let pool = Pool::builder(Manager {
            engine,
            plugin_binary,
            raw_config: Arc::new(raw_config),
        })
        .build()
        .expect("build plugin pool failed");

        Self { pool }
    }

    pub async fn get_plugin(
        &self,
    ) -> anyhow::Result<impl DerefMut<Target = (Rubydns, Store<HostHelper>)> + '_> {
        Ok(self.pool.get().await?)
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
}

#[async_trait]
impl managed::Manager for Manager {
    type Type = (Rubydns, Store<HostHelper>);
    type Error = Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let mut linker = Linker::new(&self.engine);
        let mut store = Store::new(&self.engine, HostHelper::new(self.raw_config.clone()));

        store.out_of_fuel_async_yield(u64::MAX, 10000);
        helper::add_to_linker(&mut linker, |state: &mut HostHelper| state)?;
        command::add_to_linker(&mut linker, |state: &mut HostHelper| state.wasi_ctx())?;
        udp_helper::add_to_linker(&mut linker, |state: &mut HostHelper| state.udp_helper())?;

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
