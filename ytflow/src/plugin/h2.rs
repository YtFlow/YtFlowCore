use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Weak;
use std::task::{Context, Poll};

use http::uri::{Scheme, Uri};
use hyper::client::connect::{Connected, Connection};
use hyper::rt::Executor;
use hyper::service::Service as TowerService;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::flow::*;

#[derive(Clone)]
pub struct FlowAdapterConnector {
    pub next: Weak<dyn StreamOutboundFactory>,
}

pub struct CompatStreamAdapter {
    stream: CompatStream,
    use_h2: bool,
}

pub struct TokioHyperExecutor(tokio::runtime::Handle);

impl TokioHyperExecutor {
    pub fn new_current() -> Self {
        Self(tokio::runtime::Handle::current())
    }
}

impl Executor<Pin<Box<dyn Future<Output = ()> + Send>>> for TokioHyperExecutor {
    fn execute(&self, fut: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.0.spawn(fut);
    }
}

impl TowerService<Uri> for FlowAdapterConnector {
    type Response = CompatStreamAdapter;

    type Error = Box<dyn StdError + Send + Sync>;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let host = dst
            .authority()
            .expect("h2 url must have authority")
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let next_host = Ipv4Addr::from_str(host)
            .ok()
            .map(|i| HostName::Ip(i.into()))
            .or_else(|| {
                Ipv6Addr::from_str(host)
                    .map(|i| HostName::Ip(i.into()))
                    .ok()
            })
            .or_else(|| {
                let mut host = host.to_string();
                if !host.ends_with('.') {
                    host.push('.');
                }
                HostName::from_domain_name(host.to_string()).ok()
            })
            .unwrap();
        let remote_peer = DestinationAddr {
            host: next_host,
            port: dst
                .port_u16()
                .unwrap_or(if dst.scheme() == Some(&Scheme::HTTPS) {
                    443
                } else {
                    80
                }),
        };
        let next = self.next.clone();
        Box::pin(async move {
            let next = next.upgrade().ok_or("next is gone")?;
            let mut ctx = FlowContext::new(
                SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0),
                remote_peer,
            );
            ctx.application_layer_protocol = ["h2", "http/1.1"].into_iter().collect();
            let (stream, inital_data) = next
                .create_outbound(&mut ctx, &[])
                .await
                .map_err(|e| e.to_string())?;
            let use_h2 = std::mem::take(&mut ctx.application_layer_protocol) == ["h2"].into();
            Ok(CompatStreamAdapter {
                stream: CompatStream {
                    inner: stream,
                    reader: StreamReader::new(4096, inital_data),
                },
                use_h2,
            })
        })
    }
}

impl AsyncRead for CompatStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CompatStreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl Connection for CompatStreamAdapter {
    fn connected(&self) -> Connected {
        if self.use_h2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}
