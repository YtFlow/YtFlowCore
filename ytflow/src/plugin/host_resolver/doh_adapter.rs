use std::pin::Pin;
use std::sync::Weak;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use futures::{FutureExt, SinkExt};
use http::header::{ACCEPT, CONTENT_TYPE};
use http::uri::Uri;
use http::{Method, Request};
use hyper::body::{Bytes, HttpBody};
use hyper::client::ResponseFuture;
use hyper::{Body, Client as HyperClient};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::flow::*;
use crate::plugin::h2::{FlowAdapterConnector, TokioHyperExecutor};

pub struct DohDatagramAdapterFactory {
    client: HyperClient<FlowAdapterConnector, Body>,
    url: Uri,
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

impl DohDatagramAdapterFactory {
    pub fn new(url: Uri, next: Weak<dyn StreamOutboundFactory>) -> Self {
        let client = hyper::Client::builder()
            .executor(TokioHyperExecutor::new_current())
            .build(FlowAdapterConnector { next });
        Self { client, url }
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
