use async_trait::async_trait;
use bytes::Bytes;
use host::WasiCtx;
use trust_dns_proto::op::Message;
use wasi_cap_std_sync::WasiCtxBuilder;

use super::helper::Host;

pub struct HostHelper {
    dns_message: Option<Message>,
    dns_packet: Option<Bytes>,
    wasi_ctx: WasiCtx,
    raw_config: String,
}

impl HostHelper {
    pub fn new(raw_config: String) -> Self {
        Self {
            dns_message: None,
            dns_packet: None,
            wasi_ctx: WasiCtxBuilder::new().inherit_network().build(),
            raw_config,
        }
    }

    pub fn wasi_ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }

    pub fn update(&mut self, dns_message: Message, dns_packet: Bytes) {
        self.dns_message.replace(dns_message);
        self.dns_packet.replace(dns_packet);
    }

    pub fn reset(&mut self) {
        self.dns_message.take();
        self.dns_packet.take();
    }
}

#[async_trait]
impl Host for HostHelper {
    #[inline]
    async fn dns_packet(&mut self) -> wasmtime::Result<Vec<u8>> {
        Ok(self
            .dns_packet
            .as_ref()
            .expect("dns_packet not init")
            .to_vec())
    }

    #[inline]
    async fn load_config(&mut self) -> wasmtime::Result<String> {
        Ok(self.raw_config.clone())
    }
}
