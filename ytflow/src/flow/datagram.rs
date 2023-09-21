use std::task::{Context, Poll};

use async_trait::async_trait;

use super::*;

pub trait DatagramSession: Send {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>>;
    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()>;
    fn send_to(&mut self, remote_peer: DestinationAddr, buf: Buffer);
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>>;
}

pub trait DatagramSessionHandler: Send + Sync {
    fn on_session(&self, session: Box<dyn DatagramSession>, context: Box<FlowContext>);
}

#[async_trait]
pub trait DatagramSessionFactory: Send + Sync {
    async fn bind(&self, context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>>;
}
