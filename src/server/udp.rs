use std::net::SocketAddr;
use std::rc::Rc;

use compio::net::UdpSocket;
use compio::runtime::{self, BufferPool};
use hickory_proto26::op::{DnsResponse, Message, ResponseCode};
use tracing::{debug, error, instrument};

use crate::backend::DynBackend;

pub struct UdpServer {
    udp_socket: UdpSocket,
    buffer_pool: BufferPool,
    backend: Rc<dyn DynBackend>,
}

impl UdpServer {
    pub fn new(udp_socket: UdpSocket, backend: Rc<dyn DynBackend>) -> anyhow::Result<Self> {
        Ok(Self {
            udp_socket,
            buffer_pool: BufferPool::new(10, 8192)?,
            backend,
        })
    }

    pub async fn run(self) {
        loop {
            let res = self
                .udp_socket
                .recv_from_managed(&self.buffer_pool, 8192)
                .await;
            let (buf, src) = match res {
                Err(err) => {
                    error!(%err, "recv udp socket failed");

                    continue;
                }

                Ok((buf, src)) => {
                    if buf.is_empty() {
                        error!(%src, "recv empty udp socket");

                        continue;
                    }

                    (buf, src)
                }
            };

            let message = match Message::from_vec(&buf) {
                Err(err) => {
                    error!(%err, %src, "parse udp message failed");

                    continue;
                }

                Ok(message) => message,
            };

            debug!(%src, %message, "parse udp message done");

            runtime::spawn(Self::handle_message(
                self.backend.clone(),
                src,
                message,
                self.udp_socket.clone(),
            ))
            .detach();
        }
    }

    #[instrument(skip(backend, udp_socket), fields(message = %message))]
    async fn handle_message(
        backend: Rc<dyn DynBackend>,
        src: SocketAddr,
        message: Message,
        udp_socket: UdpSocket,
    ) {
        let id = message.id();
        let op_code = message.op_code();
        let response = match backend.dyn_send_request(message, src).await {
            Err(err) => {
                error!(%err, "backend handle message failed");

                let err_message = Message::error_msg(id, op_code, ResponseCode::ServFail);
                match DnsResponse::from_message(err_message) {
                    Err(err) => {
                        error!(%err, "create dns response from err message failed");
                        return;
                    }

                    Ok(response) => response.into(),
                }
            }

            Ok(response) => {
                debug!(?response, "backend handle message done");
                response
            }
        };

        let data = response.into_buffer();

        if let Err(err) = udp_socket.send_to(data, src).await.0 {
            error!(%err, "send dns response failed");
        } else {
            debug!("send dns response done");
        }
    }
}
