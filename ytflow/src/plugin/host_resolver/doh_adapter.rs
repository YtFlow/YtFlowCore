use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Weak;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use futures::{FutureExt, SinkExt};
use http::header::{ACCEPT, CONTENT_TYPE};
use http::uri::{Scheme, Uri};
use http::{Method, Request};
use hyper::body::{Bytes, HttpBody};
use hyper::client::connect::{Connected, Connection};
use hyper::client::ResponseFuture;
use hyper::rt::Executor;
use hyper::{service::Service as TowerService, Body, Client as HyperClient};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::flow::*;

pub struct DohDatagramAdapterFactory {
    client: HyperClient<FlowAdapterConnector, Body>,
    url: Uri,
}

#[derive(Clone)]
struct FlowAdapterConnector {
    next: Weak<dyn StreamOutboundFactory>,
    remote_peer: DestinationAddr,
}

#[derive(Default)]
enum DohDatagramAdapterTxState {
    #[default]
    Idle,
    PendingResponse(ResponseFuture),
    ReadingResponse(Body, Vec<Bytes>),
}

struct DohDatagramAdapter {
    url: Uri,
    client: HyperClient<FlowAdapterConnector, Body>,
    tx_state: DohDatagramAdapterTxState,
    rx_chan: (Option<PollSender<Buffer>>, mpsc::Receiver<Buffer>),
}

struct CompatStreamAdapter {
    stream: CompatStream,
    use_h2: bool,
}

struct TokioHyperExecutor(tokio::runtime::Handle);

impl DohDatagramAdapterFactory {
    pub fn new(url: Uri, next: Weak<dyn StreamOutboundFactory>) -> Self {
        let host = url
            .authority()
            .expect("doh url must have authority")
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
            port: url
                .port_u16()
                .unwrap_or(if url.scheme() == Some(&Scheme::HTTPS) {
                    443
                } else {
                    80
                }),
        };
        let client = hyper::Client::builder()
            .executor(TokioHyperExecutor(tokio::runtime::Handle::current()))
            .build(FlowAdapterConnector { next, remote_peer });
        Self { client, url }
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

    fn call(&mut self, _dst: Uri) -> Self::Future {
        // 让下一层 redirect，这里直接摆烂
        let next = self.next.clone();
        let remote_peer = self.remote_peer.clone();
        Box::pin(async move {
            let next = next.upgrade().ok_or("next is gone")?;
            let mut ctx = FlowContext::new(
                SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0),
                remote_peer,
            );
            ctx.application_layer_protocol.push("h2");
            ctx.application_layer_protocol.push("http/1.1");
            let (stream, inital_data) = next
                .create_outbound(&mut ctx, &[])
                .await
                .map_err(|e| e.to_string())?;
            Ok(CompatStreamAdapter {
                stream: CompatStream {
                    inner: stream,
                    reader: StreamReader::new(4096, inital_data),
                },
                use_h2: ctx.application_layer_protocol == ["h2"].into(),
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

#[async_trait]
impl DatagramSessionFactory for DohDatagramAdapterFactory {
    async fn bind(&self, _context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let (rx_tx, rx_rx) = mpsc::channel(4);
        Ok(Box::new(DohDatagramAdapter {
            client: self.client.clone(),
            tx_state: Default::default(),
            rx_chan: (Some(PollSender::new(rx_tx)), rx_rx),
            url: self.url.clone(),
        }))
    }
}

impl DatagramSession for DohDatagramAdapter {
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        let buf = match ready!(self.rx_chan.1.poll_recv(cx)) {
            Some(buf) => buf,
            None => return Poll::Ready(None),
        };
        let dummy_addr = DestinationAddr {
            host: HostName::Ip([1, 1, 1, 1].into()),
            port: 53,
        };
        Poll::Ready(Some((dummy_addr, buf)))
    }

    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            let Some(tx) = self.rx_chan.0.as_mut() else {
                break Poll::Ready(());
            };
            let _ = ready!(tx.poll_ready_unpin(cx)).ok();
            match std::mem::take(&mut self.tx_state) {
                DohDatagramAdapterTxState::Idle => break Poll::Ready(()),
                DohDatagramAdapterTxState::PendingResponse(mut fut) => match fut.poll_unpin(cx) {
                    Poll::Ready(Ok(resp)) => {
                        if resp.status().is_success() {
                            self.tx_state = DohDatagramAdapterTxState::ReadingResponse(
                                resp.into_body(),
                                Vec::new(),
                            );
                        } else {
                            // TODO: log res error
                            self.rx_chan.0 = None;
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        // TODO: log error
                        self.rx_chan.0 = None;
                    }
                    Poll::Pending => {
                        self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
                        break Poll::Pending;
                    }
                },
                DohDatagramAdapterTxState::ReadingResponse(mut body, mut byte_bufs) => {
                    let current_buf_len = byte_bufs.iter().map(|c| c.len()).sum();
                    match Pin::new(&mut body).poll_data(cx) {
                        Poll::Ready(None) => {
                            let mut buf = Vec::with_capacity(current_buf_len);
                            for b in byte_bufs {
                                buf.extend_from_slice(&b[..]);
                            }
                            if tx.start_send_unpin(buf).is_err() {
                                self.rx_chan.0 = None;
                            }
                            self.tx_state = DohDatagramAdapterTxState::Idle;
                        }
                        Poll::Ready(Some(Err(_))) => {
                            // TODO: log error
                            self.rx_chan.0 = None;
                        }
                        Poll::Ready(Some(Ok(buf))) => {
                            if current_buf_len + buf.len() > 4096 {
                                // Body too long
                                // TODO: log error
                                self.rx_chan.0 = None;
                            } else {
                                byte_bufs.push(buf);
                                self.tx_state =
                                    DohDatagramAdapterTxState::ReadingResponse(body, byte_bufs);
                            }
                        }
                        Poll::Pending => {
                            self.tx_state =
                                DohDatagramAdapterTxState::ReadingResponse(body, byte_bufs);
                            break Poll::Pending;
                        }
                    }
                }
            }
        }
    }

    fn send_to(&mut self, _remote_peer: DestinationAddr, buf: Buffer) {
        let req = Request::builder()
            .method(Method::POST)
            .uri(self.url.clone())
            .header(ACCEPT, "application/dns-message")
            .header(CONTENT_TYPE, "application/dns-message")
            .body(buf.into())
            .unwrap();
        let fut = self.client.request(req);
        self.tx_state = DohDatagramAdapterTxState::PendingResponse(fut);
    }

    fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        Poll::Ready(Ok(()))
    }
}
