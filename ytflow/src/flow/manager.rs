use crate::config::Config;

#[derive(Debug)]
pub struct Manager {
    pub rt: tokio::runtime::Runtime,
}

impl Manager {
    pub fn new(config: &Config) -> Self {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // let manager = Arc::new(Self { rt });
        // let ip_stack = IpStack::new(manager.clone());
        // (manager, ip_stack)
        Self { rt }
        // TODO: initialize other plugins
    }

    // pub(crate) fn query_node_factory(&self, node_handle) -> Box<NodeFactory> {

    // }
}
