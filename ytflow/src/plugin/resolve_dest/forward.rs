use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::{future::BoxFuture, ready};

use crate::flow::*;

pub struct StreamForwardResolver {
    pub resolver: Weak<dyn Resolver>,
    pub next: Weak<dyn StreamHandler>,
}

pub struct DatagramForwardResolver {
    pub resolver: Weak<dyn Resolver>,
    pub next: Weak<dyn DatagramSessionHandler>,
}

fn handle_context(
    resolver: &Weak<dyn Resolver>,
    mut context: Box<FlowContext>,
    on_context: impl FnOnce(Box<FlowContext>) + Send + 'static,
) {
    let domain = match &mut context.remote_peer.dest {
        Destination::DomainName(domain) => std::mem::replace(domain, String::new()),
        _ => return on_context(context),
    };
    let resolver = match resolver.upgrade() {
        Some(resolver) => resolver,
        None => return,
    };
    tokio::spawn(async move {
        context.remote_peer = super::try_resolve_forward(
            context.local_peer.is_ipv6(),
            resolver,
            domain,
            context.remote_peer.port,
        )
        .await;
        on_context(context);
        FlowResult::Ok(())
    });
}

#[async_trait]
impl StreamHandler for StreamForwardResolver {
    fn on_stream(&self, lower: Pin<Box<dyn Stream>>, mut context: Box<FlowContext>) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => return,
        };
        handle_context(&self.resolver, context, move |c| next.on_stream(lower, c));
    }
}

impl DatagramSessionHandler for DatagramForwardResolver {
    fn on_session(&self, lower: Pin<Box<dyn DatagramSession>>, mut context: Box<FlowContext>) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => return,
        };
        let resolver = match self.resolver.upgrade() {
            Some(resolver) => resolver,
            None => return,
        };
        handle_context(&self.resolver, context, move |c| {
            next.on_session(
                Box::pin(DatagramForwardSession {
                    is_ipv6: c.local_peer.is_ipv6(),
                    resolver,
                    lower,
                    resolving: None,
                    reverse_resolving: None,
                }),
                c,
            )
        });
    }
}

struct DatagramForwardSession {
    is_ipv6: bool,
    resolver: Arc<dyn Resolver>,
    lower: Pin<Box<dyn DatagramSession>>,
    resolving: Option<BoxFuture<'static, (DestinationAddr, Buffer)>>,
    reverse_resolving: Option<BoxFuture<'static, (DestinationAddr, Buffer)>>,
}

// TODO: 为啥？
unsafe impl Sync for DatagramForwardSession {}

impl DatagramSession for DatagramForwardSession {
    fn poll_recv_from(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<(DestinationAddr, Buffer)>> {
        if let Some(mut fut) = self.resolving.take() {
            return if let Poll::Ready(ret) = fut.as_mut().poll(cx) {
                Poll::Ready(Some(ret))
            } else {
                self.resolving = Some(fut);
                Poll::Pending
            };
        }
        let (dest, buf) = match ready!(self.lower.as_mut().poll_recv_from(cx)) {
            Some(ret) => ret,
            None => return Poll::Ready(None),
        };
        let (domain, port) = match dest {
            DestinationAddr {
                dest: Destination::DomainName(domain),
                port,
            } => (domain, port),
            dest => return Poll::Ready(Some((dest, buf))),
        };
        let resolver = self.resolver.clone();
        let is_ipv6 = self.is_ipv6;
        self.resolving = Some(Box::pin(async move {
            (
                super::try_resolve_forward(is_ipv6, resolver, domain, port).await,
                buf,
            )
        }));
        self.poll_recv_from(cx)
    }

    fn poll_send_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(mut fut) = self.reverse_resolving.take() {
            if let Poll::Ready((dest, buf)) = fut.as_mut().poll(cx) {
                self.lower.as_mut().send_to(dest, buf);
            } else {
                self.reverse_resolving = Some(fut);
                // Poll resolving task and lower send_ready simultaneously.
                let _ = self.lower.as_mut().poll_send_ready(cx);
                return Poll::Pending;
            };
        }
        self.lower.as_mut().poll_send_ready(cx)
    }

    fn send_to(mut self: Pin<&mut Self>, remote_peer: DestinationAddr, buf: Buffer) {
        let (ip, port) = match remote_peer {
            DestinationAddr {
                dest: Destination::Ip(ip),
                port,
            } => (ip, port),
            dest => return self.lower.as_mut().send_to(dest, buf),
        };
        let resolver = self.resolver.clone();
        self.resolving = Some(Box::pin(async move {
            (super::try_resolve_reverse(resolver, ip, port).await, buf)
        }));
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.as_mut().poll_shutdown(cx)
    }
}
