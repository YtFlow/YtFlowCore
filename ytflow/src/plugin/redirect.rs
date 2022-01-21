use std::sync::Weak;
use std::task::{Context, Poll};

use async_trait::async_trait;
use pin_project_lite::pin_project;

use crate::flow::*;

pub trait PeerProvider: 'static + Send + Sync + Clone {
    fn get_peer(&self) -> DestinationAddr;
}

impl<R: 'static + Send + Sync + Clone + Fn() -> DestinationAddr> PeerProvider for R {
    fn get_peer(&self) -> DestinationAddr {
        self()
    }
}

pub struct StreamRedirectHandler<R: PeerProvider> {
    pub remote_peer: R,
    pub next: Weak<dyn StreamHandler>,
}

pub struct StreamRedirectOutboundFactory<R: PeerProvider> {
    pub remote_peer: R,
    pub next: Weak<dyn StreamOutboundFactory>,
}

pin_project! {
    struct DatagramRedirectSession<R: PeerProvider> {
        remote_peer: R,
        #[pin]
        lower: Box<dyn DatagramSession>,
    }
}

pub struct DatagramSessionRedirectHandler<R: PeerProvider> {
    pub remote_peer: R,
    pub next: Weak<dyn DatagramSessionHandler>,
}

pub struct DatagramSessionRedirectFactory<R: PeerProvider> {
    pub remote_peer: R,
    pub next: Weak<dyn DatagramSessionFactory>,
}

impl<R: PeerProvider> StreamHandler for StreamRedirectHandler<R> {
    fn on_stream(&self, lower: Box<dyn Stream>, mut context: Box<FlowContext>) {
        let next = match self.next.upgrade() {
            Some(n) => n,
            None => return,
        };
        context.remote_peer = self.remote_peer.get_peer();
        next.on_stream(lower, context);
    }
}

#[async_trait]
impl<R: PeerProvider> StreamOutboundFactory for StreamRedirectOutboundFactory<R> {
    async fn create_outbound(
        &self,
        mut context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let next = match self.next.upgrade() {
            Some(n) => n,
            None => return Err(FlowError::NoOutbound),
        };
        context.remote_peer = self.remote_peer.get_peer();
        next.create_outbound(context, initial_data).await
    }
}

impl<R: PeerProvider> DatagramSession for DatagramRedirectSession<R> {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        self.lower.as_mut().poll_recv_from(cx)
    }
    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.lower.as_mut().poll_send_ready(cx)
    }
    fn send_to(&mut self, _remote_peer: DestinationAddr, buf: Buffer) {
        let dest = self.remote_peer.get_peer();
        self.lower.as_mut().send_to(dest, buf)
    }
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.as_mut().poll_shutdown(cx)
    }
}

impl<R: PeerProvider> DatagramSessionHandler for DatagramSessionRedirectHandler<R> {
    fn on_session(&self, session: Box<dyn DatagramSession>, mut context: Box<FlowContext>) {
        let next = match self.next.upgrade() {
            Some(n) => n,
            None => return,
        };
        context.remote_peer = self.remote_peer.get_peer();
        next.on_session(
            Box::new(DatagramRedirectSession {
                remote_peer: self.remote_peer.clone(),
                lower: session,
            }),
            context,
        );
    }
}

#[async_trait]
impl<R: PeerProvider> DatagramSessionFactory for DatagramSessionRedirectFactory<R> {
    async fn bind(&self, mut context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let next = match self.next.upgrade() {
            Some(n) => n,
            None => return Err(FlowError::NoOutbound),
        };
        context.remote_peer = self.remote_peer.get_peer();
        Ok(Box::new(DatagramRedirectSession {
            remote_peer: self.remote_peer.clone(),
            lower: next.bind(context).await?,
        }))
    }
}
