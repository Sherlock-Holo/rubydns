use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use host::WasiCtx;
use tap::TapFallible;
use tracing::error;
use wasi_cap_std_sync::WasiCtxBuilder;

pub use self::tcp::TcpHelper;
pub use self::udp::UdpHelper;
use super::helper::Error;
use super::helper::Host as HelperHost;
use super::pool::PluginPool;

mod tcp;
mod udp;

pub struct HostHelper {
    wasi_ctx: WasiCtx,
    raw_config: Arc<String>,
    udp_helper: UdpHelper,
    tcp_helper: TcpHelper,
    next_plugin: Option<PluginPool>,
    plugin_store_map: Arc<DashMap<Bytes, StoreValue>>,
}

impl HostHelper {
    pub fn new(
        raw_config: Arc<String>,
        next_plugin: Option<PluginPool>,
        plugin_store_map: Arc<DashMap<Bytes, StoreValue>>,
    ) -> Self {
        Self {
            wasi_ctx: WasiCtxBuilder::new().inherit_network().build(),
            raw_config,
            udp_helper: Default::default(),
            tcp_helper: Default::default(),
            next_plugin,
            plugin_store_map,
        }
    }

    pub fn wasi_ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }

    pub fn udp_helper(&mut self) -> &mut UdpHelper {
        &mut self.udp_helper
    }

    pub fn tcp_helper(&mut self) -> &mut TcpHelper {
        &mut self.tcp_helper
    }

    pub fn reset(&mut self) {
        self.udp_helper.reset();
        self.tcp_helper.reset();
    }
}

#[async_trait]
impl HelperHost for HostHelper {
    #[inline]
    async fn load_config(&mut self) -> wasmtime::Result<String> {
        Ok(self.raw_config.to_string())
    }

    async fn call_next_plugin(
        &mut self,
        dns_packet: Vec<u8>,
    ) -> anyhow::Result<Option<Result<Vec<u8>, Error>>> {
        let plugin_pool = match &self.next_plugin {
            None => return Ok(None),
            Some(plugin_pool) => plugin_pool,
        };

        let mut next_plugin = plugin_pool
            .get_plugin()
            .await
            .tap_err(|err| error!(%err, "get next plugin failed"))?;

        let (plugin, store) = &mut *next_plugin;

        let result = plugin.plugin().call_run(store, &dns_packet).await?;

        Ok(Some(result))
    }

    async fn map_set(
        &mut self,
        key: Vec<u8>,
        value: Vec<u8>,
        timeout: Option<u64>,
    ) -> anyhow::Result<()> {
        self.plugin_store_map.insert(
            key.into(),
            StoreValue {
                data: value.into(),
                timeout: timeout.map(|timeout| Instant::now() + Duration::from_secs(timeout)),
            },
        );

        Ok(())
    }

    async fn map_get(&mut self, key: Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        match self.plugin_store_map.get(key.as_slice()) {
            None => Ok(None),
            Some(value) => {
                if let Some(timeout) = value.timeout {
                    if Instant::now().checked_duration_since(timeout).is_some() {
                        self.plugin_store_map.remove(key.as_slice());

                        return Ok(None);
                    }
                }

                Ok(Some(value.data.clone().into()))
            }
        }
    }

    async fn map_remove(&mut self, key: Vec<u8>) -> anyhow::Result<()> {
        self.plugin_store_map.remove(key.as_slice());

        Ok(())
    }
}

fn io_err_to_errno(err: io::Error) -> u32 {
    err.raw_os_error().unwrap_or(1) as _
}

pub struct StoreValue {
    data: Bytes,
    timeout: Option<Instant>,
}
