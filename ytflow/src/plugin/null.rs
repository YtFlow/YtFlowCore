use std::net::IpAddr;

use async_trait::async_trait;

use crate::flow::*;

pub struct Null;

#[async_trait]
impl StreamOutboundFactory for Null {
    async fn create_outbound(
        &self,
        _context: Box<FlowContext>,
        _initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        Err(FlowError::NoOutbound)
    }
}

#[async_trait]
impl DatagramSessionFactory for Null {
    async fn bind(&self, _context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        Err(FlowError::NoOutbound)
    }
}

#[async_trait]
impl Resolver for Null {
    async fn resolve_ipv4(&self, _domain: String) -> ResolveResultV4 {
        Err(FlowError::NoOutbound)
    }
    async fn resolve_ipv6(&self, _domain: String) -> ResolveResultV6 {
        Err(FlowError::NoOutbound)
    }
    async fn resolve_reverse(&self, _ip: IpAddr) -> FlowResult<String> {
        Err(FlowError::NoOutbound)
    }
}
