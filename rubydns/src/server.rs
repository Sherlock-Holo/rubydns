use std::sync::Arc;

use bytes::Bytes;
use tap::TapFallible;
use tracing::{error, instrument};
use trust_dns_proto::op::{Message, MessageType, ResponseCode};

use crate::handle::udp;
use crate::plugins::PluginChain;

pub struct Server<UdpHandler> {
    inner: Arc<ServerInner<UdpHandler>>,
}

impl<UdpHandler: udp::Accept + udp::Respond> Server<UdpHandler>
where
    UdpHandler: udp::Accept,
    UdpHandler: udp::Respond<Identify = <UdpHandler as udp::Accept>::Identify>,
    UdpHandler: Send + Sync + 'static,
{
    pub fn new(udp_handler: UdpHandler, plugin_chain: PluginChain) -> Self {
        Self {
            inner: Arc::new(ServerInner {
                udp_handler,
                plugin_chain,
            }),
        }
    }

    pub async fn serve(&mut self) {
        loop {
            let (identify, dns_message, dns_packet) = match self.inner.udp_handler.accept().await {
                Err(err) => {
                    error!(%err, "accept udp request failed");

                    continue;
                }

                Ok(request) => request,
            };

            self.handle(identify, dns_message, dns_packet);
        }
    }

    fn handle(
        &mut self,
        identify: <UdpHandler as udp::Accept>::Identify,
        dns_message: Message,
        dns_packet: Bytes,
    ) {
        let inner = self.inner.clone();

        tokio::spawn(async move {
            let _ = inner.handle(identify, dns_message, dns_packet).await;
        });
    }
}

pub struct ServerInner<UdpHandler> {
    udp_handler: UdpHandler,
    plugin_chain: PluginChain,
}

impl<UdpHandler> ServerInner<UdpHandler>
where
    UdpHandler: udp::Accept,
    UdpHandler: udp::Respond<Identify = <UdpHandler as udp::Accept>::Identify>,
{
    #[instrument(err, skip(self, dns_message, dns_packet))]
    async fn handle(
        &self,
        identify: <UdpHandler as udp::Accept>::Identify,
        mut dns_message: Message,
        dns_packet: Bytes,
    ) -> anyhow::Result<()> {
        let response = match self
            .plugin_chain
            .handle_dns(dns_message.clone(), dns_packet)
            .await
        {
            Err(err) => {
                error!(%err, "plugins handle dns request failed");

                dns_message.set_message_type(MessageType::Response);
                dns_message.set_response_code(ResponseCode::ServFail);

                dns_message.to_vec()?.into()
            }
            Ok((_, response)) => response,
        };

        self.udp_handler
            .respond(identify, response)
            .await
            .tap_err(|err| error!(%err, "respond dns failed"))?;

        Ok(())
    }
}
