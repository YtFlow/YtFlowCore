use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use futures::{future::BoxFuture, ready};

use crate::flow::*;

pub struct StreamReverseResolver {
    pub resolver: Weak<dyn Resolver>,
    pub next: Weak<dyn StreamHandler>,
}

pub struct DatagramReverseResolver {
    pub resolver: Weak<dyn Resolver>,
    pub next: Weak<dyn DatagramSessionHandler>,
}

fn handle_context(
    resolver: &Weak<dyn Resolver>,
    mut context: Box<FlowContext>,
    on_context: impl FnOnce(Box<FlowContext>) + Send + 'static,
) {
    let ip = match &context.remote_peer.dest {
        Destination::Ip(ip) => *ip,
        _ => return on_context(context),
    };
    let resolver = match resolver.upgrade() {
        Some(resolver) => resolver,
        None => return,
    };
    tokio::spawn(async move {
        context.remote_peer.dest = match resolver.resolve_reverse(ip).await {
            Ok(domain) => {
                crate::log::debug_log(format!("Reverse request: {}", domain));
                Destination::DomainName(domain)
            }
            Err(_) => Destination::Ip(ip),
        };
        on_context(context);
        FlowResult::Ok(())
    });
}

impl StreamHandler for StreamReverseResolver {
    fn on_stream(&self, lower: Box<dyn Stream>, initial_data: Buffer, context: Box<FlowContext>) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => return,
        };
        handle_context(&self.resolver, context, move |c| {
            next.on_stream(lower, initial_data, c)
        });
    }
}

impl DatagramSessionHandler for DatagramReverseResolver {
    fn on_session(&self, lower: Box<dyn DatagramSession>, context: Box<FlowContext>) {
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
                Box::new(DatagramReverseSession {
                    is_ipv6: c.local_peer.is_ipv6(),
                    resolver,
                    lower,
                    reverse_resolving: None,
                    resolving: None,
                }),
                c,
            )
        });
    }
}

struct DatagramReverseSession {
    is_ipv6: bool,
    resolver: Arc<dyn Resolver>,
    lower: Box<dyn DatagramSession>,
    reverse_resolving: Option<BoxFuture<'static, (DestinationAddr, Buffer)>>,
    resolving: Option<BoxFuture<'static, (DestinationAddr, Buffer)>>,
}

// TODO: 为啥？
unsafe impl Sync for DatagramReverseSession {}

impl DatagramSession for DatagramReverseSession {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        if let Some(mut fut) = self.reverse_resolving.take() {
            return if let Poll::Ready(ret) = fut.as_mut().poll(cx) {
                Poll::Ready(Some(ret))
            } else {
                self.reverse_resolving = Some(fut);
                Poll::Pending
            };
        }
        let (dest, buf) = match ready!(self.lower.as_mut().poll_recv_from(cx)) {
            Some(ret) => ret,
            None => return Poll::Ready(None),
        };
        let ip = match &dest.dest {
            Destination::DomainName(_) => return Poll::Ready(Some((dest, buf))),
            Destination::Ip(ip) => *ip,
        };
        let port = dest.port;
        let resolver = self.resolver.clone();
        self.reverse_resolving = Some(Box::pin(async move {
            (super::try_resolve_reverse(resolver, ip, port).await, buf)
        }));
        self.poll_recv_from(cx)
    }

    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if let Some(mut fut) = self.resolving.take() {
            if let Poll::Ready((dest, buf)) = fut.as_mut().poll(cx) {
                self.lower.as_mut().send_to(dest, buf);
            } else {
                self.resolving = Some(fut);
                // Poll resolving task and lower send_ready simultaneously.
                let _ = self.lower.as_mut().poll_send_ready(cx);
                return Poll::Pending;
            };
        }
        self.lower.as_mut().poll_send_ready(cx)
    }

    fn send_to(&mut self, remote_peer: DestinationAddr, buf: Buffer) {
        let DestinationAddr { dest, port } = remote_peer;
        let domain = match dest {
            Destination::DomainName(domain) => domain,
            dest => {
                return self
                    .lower
                    .as_mut()
                    .send_to(DestinationAddr { dest, port }, buf)
            }
        };
        let resolver = self.resolver.clone();
        let is_ipv6 = self.is_ipv6;
        self.resolving = Some(Box::pin(async move {
            (
                super::try_resolve_forward(is_ipv6, resolver, domain, port).await,
                buf,
            )
        }));
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.as_mut().poll_shutdown(cx)
    }
}
