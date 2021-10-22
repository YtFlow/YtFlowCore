use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;

use super::*;

pub trait DatagramSession: Send + Sync {
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<(DestinationAddr, Buffer)>>;
    fn poll_send_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()>;
    fn send_to(self: Pin<&mut Self>, remote_peer: DestinationAddr, buf: Buffer);
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>>;
}

pub trait DatagramSessionHandler: Send + Sync {
    fn on_session(&self, session: Pin<Box<dyn DatagramSession>>, context: Box<FlowContext>);
}

#[async_trait]
pub trait DatagramSessionFactory: Send + Sync {
    async fn bind(&self, context: Box<FlowContext>) -> FlowResult<Pin<Box<dyn DatagramSession>>>;
}
