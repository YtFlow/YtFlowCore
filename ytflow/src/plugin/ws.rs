use std::num::NonZeroUsize;
use std::sync::Weak;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, Version};
use hyper::{Body, Client as HyperClient};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_tungstenite::{
    self as tokio_ws, tungstenite as ws, WebSocketStream as TokioWebSocketStream,
};
use tokio_ws::tungstenite::protocol::Role;
use ws::{
    error::{Error as WsError, ProtocolError},
    handshake::client::generate_key as generate_ws_key,
    Message as WsMessage,
};

use super::h2::FlowAdapterConnector;
use crate::flow::*;
use crate::plugin::h2::TokioHyperExecutor;

struct WebSocketStream<S> {
    rx_buffer: Option<Buffer>,
    rx_ws_res: Option<Vec<u8>>,
    ws: TokioWebSocketStream<S>,
}

#[derive(Clone, Default)]
enum H2ProbeState {
    #[default]
    Unknown,
    NotSupported,
    Supported(HyperClient<FlowAdapterConnector>),
}

pub struct WebSocketStreamOutboundFactory {
    pub host: Option<String>,
    pub path: String,
    pub headers: HeaderMap<HeaderValue>,
    pub next: Weak<dyn StreamOutboundFactory>,
    h2_probe_state: Mutex<H2ProbeState>,
}

impl WebSocketStreamOutboundFactory {
    pub fn new(
        host: Option<String>,
        path: String,
        headers: HeaderMap<HeaderValue>,
        next: Weak<dyn StreamOutboundFactory>,
    ) -> Self {
        Self {
            host,
            path,
            headers,
            next,
            h2_probe_state: Mutex::new(Default::default()),
        }
    }

    fn create_upgrade_req<B>(
        &self,
        peer: &DestinationAddr,
        body: B,
        is_h2: bool,
    ) -> FlowResult<Request<B>> {
        let host = match (&self.host, peer.port) {
            (Some(_), _) => None,
            (None, 443 | 80) => Some(peer.host.to_string()),
            (None, _) => Some(peer.to_string()),
        };
        let host = if let Some(host) = self.host.as_ref() {
            host.as_str()
        } else {
            host.as_deref().unwrap()
        };
        let uri = Uri::builder()
            .scheme(if is_h2 {
                // FIXME: http or https?
                "https"
            } else {
                "ws"
            })
            .authority(host)
            .path_and_query(&self.path)
            .build()
            .map_err(|_| FlowError::UnexpectedData)?;

        let mut http_req = Request::new(body);
        if is_h2 {
            *http_req.method_mut() = Method::CONNECT;
            http_req
                .extensions_mut()
                .insert(hyper::ext::Protocol::from_static("websocket"));
        }
        *http_req.headers_mut() = self.headers.clone();
        let authority = uri.authority().unwrap().as_str();
        let host = authority
            .find('@')
            .map(|idx| authority.split_at(idx + 1).1)
            .unwrap_or_else(|| authority);
        if !is_h2 {
            http_req.headers_mut().append(
                HeaderName::from_static("host"),
                HeaderValue::from_str(host).unwrap(),
            );
            http_req.headers_mut().append(
                HeaderName::from_static("connection"),
                HeaderValue::from_static("Upgrade"),
            );
            http_req.headers_mut().append(
                HeaderName::from_static("upgrade"),
                HeaderValue::from_static("websocket"),
            );
            http_req.headers_mut().append(
                HeaderName::from_static("sec-websocket-key"),
                HeaderValue::from_str(&generate_ws_key()).unwrap(),
            );
        }
        http_req.headers_mut().append(
            HeaderName::from_static("sec-websocket-version"),
            HeaderValue::from_static("13"),
        );
        *http_req.uri_mut() = uri;

        Ok(http_req)
    }
    async fn websocket_handshake_h1(
        &self,
        context: &mut FlowContext,
        initial_data: Vec<u8>,
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let http_req = self.create_upgrade_req(&context.remote_peer, (), false)?;

        let next = self.next.upgrade().ok_or(FlowError::UnexpectedData)?;
        context.application_layer_protocol = ["http/1.1"].into_iter().collect();
        let (lower, initial_res) = next.create_outbound(context, &[]).await?;
        context.application_layer_protocol.clear();
        let reader = StreamReader::new(4096, initial_res);

        let (mut ws, res) = tokio_ws::client_async(
            http_req,
            CompatStream {
                reader,
                inner: lower,
            },
        )
        .await
        .map_err(ws_handshake_err_to_flow_err)?;
        if !initial_data.is_empty() {
            ws.send(WsMessage::Binary(initial_data))
                .await
                .map_err(ws_stream_err_to_flow_err)?;
        }
        Ok((
            Box::new(WebSocketStream::new(ws)),
            res.into_body().unwrap_or_default(),
        ))
    }
}

#[async_trait]
impl StreamOutboundFactory for WebSocketStreamOutboundFactory {
    async fn create_outbound(
        &self,
        mut context: &mut FlowContext,
        initial_data: &[u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let res = loop {
            match {
                let guard = self.h2_probe_state.lock().await;
                (*guard).clone()
            } {
                H2ProbeState::NotSupported => {
                    return self
                        .websocket_handshake_h1(&mut context, initial_data.into())
                        .await
                }
                H2ProbeState::Supported(client) => {
                    let h2_req =
                        self.create_upgrade_req(&context.remote_peer, Body::empty(), true)?;
                    break client
                        .request(h2_req)
                        .await
                        .map_err(|_| FlowError::UnexpectedData)?;
                }
                H2ProbeState::Unknown => {}
            }
            let mut h2_req = self.create_upgrade_req(&context.remote_peer, Body::empty(), true)?;
            *h2_req.version_mut() = Version::HTTP_2;
            let next = self.next.clone();
            let mut guard = self.h2_probe_state.lock().await;
            if let H2ProbeState::Unknown = &*guard {
                let client = hyper::Client::builder()
                    .executor(TokioHyperExecutor::new_current())
                    .build(FlowAdapterConnector { next });
                let res = client.request(h2_req).await;
                match res {
                    Ok(res) if res.version() == Version::HTTP_2 && res.status().is_success() => {
                        *guard = H2ProbeState::Supported(client);
                        break res;
                    }
                    Ok(_) => {
                        // TODO: log resp
                        *guard = H2ProbeState::NotSupported;
                    }
                    Err(_) => {
                        // TODO: log error
                        *guard = H2ProbeState::NotSupported;
                        // hyper tends to make more connections for subsequent requests at this stage, so there is no
                        // point to reuse the client for HTTP/1.1 WebSocket handshake.
                    }
                }
            }
        };
        if !res.status().is_success() {
            return Err(FlowError::UnexpectedData);
        }
        let upgraded = hyper::upgrade::on(res)
            .await
            .map_err(|_| FlowError::UnexpectedData)?;
        let mut ws = TokioWebSocketStream::from_raw_socket(upgraded, Role::Client, None).await;
        if !initial_data.is_empty() {
            ws.send(WsMessage::Binary(initial_data.to_vec()))
                .await
                .map_err(ws_stream_err_to_flow_err)?;
        }
        Ok((Box::new(WebSocketStream::new(ws)), Default::default()))
    }
}

fn ws_stream_err_to_flow_err(e: WsError) -> FlowError {
    match e {
        WsError::Io(e) => FlowError::Io(e),
        WsError::AlreadyClosed | WsError::ConnectionClosed => FlowError::Eof,
        _ => FlowError::UnexpectedData,
    }
}

fn ws_handshake_err_to_flow_err(e: WsError) -> FlowError {
    match e {
        WsError::Io(e) => FlowError::Io(e),
        WsError::Protocol(ProtocolError::HandshakeIncomplete) => FlowError::Eof,
        _ => FlowError::UnexpectedData,
    }
}

impl<S> WebSocketStream<S> {
    fn new(stream: TokioWebSocketStream<S>) -> Self {
        Self {
            ws: stream,
            rx_buffer: None,
            rx_ws_res: None,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for WebSocketStream<S> {
    fn poll_request_size(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        let res = ready!(self.ws.poll_next_unpin(cx));
        Poll::Ready(match res {
            None | Some(Ok(WsMessage::Close(_))) => Err(FlowError::Eof),
            Some(Ok(WsMessage::Binary(buf))) => {
                let size = buf.len();
                self.rx_ws_res = Some(buf);
                Ok(SizeHint::AtLeast(size))
            }
            Some(Ok(_)) => Err(FlowError::UnexpectedData),
            Some(Err(e)) => Err(ws_stream_err_to_flow_err(e)),
        })
    }

    fn commit_rx_buffer(&mut self, buffer: Buffer) -> Result<(), (Buffer, FlowError)> {
        self.rx_buffer = Some(buffer);
        Ok(())
    }

    fn poll_rx_buffer(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        let mut rx_buf = self.rx_buffer.take().unwrap();
        let res_buf = self.rx_ws_res.take().unwrap();
        rx_buf.extend_from_slice(&res_buf);
        Poll::Ready(Ok(rx_buf))
    }

    fn poll_tx_buffer(
        &mut self,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        ready!(self.ws.poll_flush_unpin(cx)).map_err(ws_stream_err_to_flow_err)?;
        ready!(self.ws.poll_ready_unpin(cx)).map_err(ws_stream_err_to_flow_err)?;
        Poll::Ready(Ok(Buffer::with_capacity(size.get())))
    }

    fn commit_tx_buffer(&mut self, buffer: Buffer) -> FlowResult<()> {
        self.ws
            .start_send_unpin(WsMessage::Binary(buffer))
            .map_err(ws_stream_err_to_flow_err)?;
        Ok(())
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.ws
            .poll_flush_unpin(cx)
            .map_err(ws_stream_err_to_flow_err)
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        // Unfortunately WebSocket does not support half close.
        self.ws
            .poll_close_unpin(cx)
            .map_err(ws_stream_err_to_flow_err)
    }
}
