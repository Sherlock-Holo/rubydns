use std::rc::Rc;

use tower::Layer;
use tower::layer::layer_fn;
use tower::layer::util::Identity;

use crate::backend::DynBackend;

pub struct LayerBuilder {
    layer: Box<dyn Layer<Rc<dyn DynBackend>, Service = Rc<dyn DynBackend>>>,
}

impl LayerBuilder {
    pub fn new() -> Self {
        Self {
            layer: Box::new(Identity::new()),
        }
    }

    pub fn layer<L>(self, layer: L) -> LayerBuilder
    where
        L: Layer<Rc<dyn DynBackend>, Service = Rc<dyn DynBackend>> + 'static,
    {
        LayerBuilder {
            layer: Box::new(layer_fn(move |backend| {
                let backend = self.layer.layer(backend);
                layer.layer(backend)
            })),
        }
    }

    pub fn build(self, backend: Rc<dyn DynBackend>) -> Rc<dyn DynBackend> {
        self.layer.layer(backend)
    }
}
