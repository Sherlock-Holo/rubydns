use std::cell::RefCell;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::rc::Rc;

use hickory_proto26::op::Message;
use tracing::instrument;

use super::{Backend, DnsResponseWrapper, DynBackend};
use crate::wrr::SmoothWeight;

#[derive(Clone)]
pub struct Group {
    backends: Rc<RefCell<SmoothWeight<Rc<dyn DynBackend>>>>,
}

impl Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group").finish_non_exhaustive()
    }
}

impl Group {
    pub fn new(backends: Vec<(usize, Rc<dyn DynBackend>)>) -> Self {
        let backends =
            backends
                .into_iter()
                .fold(SmoothWeight::new(), |mut backends, (weight, backend)| {
                    backends.add(backend, weight as _);
                    backends
                });

        Self {
            backends: Rc::new(RefCell::new(backends)),
        }
    }
}

impl Backend for Group {
    #[instrument(skip(self), ret(Display), fields(message = %message), err)]
    async fn send_request(
        &self,
        message: Message,
        src: SocketAddr,
    ) -> anyhow::Result<DnsResponseWrapper> {
        let backend = self
            .backends
            .borrow_mut()
            .next()
            .expect("backends must not empty");

        backend.dyn_send_request(message, src).await
    }
}
