use std::num::NonZeroUsize;
use std::sync::Weak;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Uri};
use tokio_tungstenite::{
    self as tokio_ws, tungstenite as ws, WebSocketStream as TokioWebSocketStream,
};
use ws::{
    error::{Error as WsError, ProtocolError},
    handshake::client::generate_key as generate_ws_key,
    Message as WsMessage,
};

use crate::flow::*;

struct WebSocketStream {
    rx_buffer: Option<Buffer>,
    rx_ws_res: Option<Vec<u8>>,
    ws: TokioWebSocketStream<CompatStream>,
}

pub struct WebSocketStreamOutboundFactory {
    pub host: Option<String>,
    pub path: String,
    pub headers: HeaderMap<HeaderValue>,
    pub next: Weak<dyn StreamOutboundFactory>,
}

impl WebSocketStreamOutboundFactory {
    async fn websocket_handshake(
        &self,
        lower: Box<dyn Stream>,
        uri: Uri,
        reader: StreamReader,
        initial_data: Vec<u8>,
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let mut http_req = Request::new(());
        *http_req.headers_mut() = self.headers.clone();
        let authority = uri.authority().unwrap().as_str();
        let host = authority
            .find('@')
            .map(|idx| authority.split_at(idx + 1).1)
            .unwrap_or_else(|| authority);
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
            HeaderName::from_static("sec-websocket-version"),
            HeaderValue::from_static("13"),
        );
        http_req.headers_mut().append(
            HeaderName::from_static("sec-websocket-key"),
            HeaderValue::from_str(&generate_ws_key()).unwrap(),
        );
        *http_req.uri_mut() = uri;

        let (mut ws, res) = tokio_ws::client_async(
            http_req,
            CompatStream {
                reader,
                inner: lower,
            },
        )
        .await
        .map_err(|e| match e {
            WsError::Io(e) => FlowError::Io(e),
            WsError::Protocol(ProtocolError::HandshakeIncomplete) => FlowError::Eof,
            _ => FlowError::UnexpectedData,
        })?;
        ws.send(WsMessage::Binary(initial_data))
            .await
            .map_err(ws_stream_err_to_flow_err)?;
        Ok((
            Box::new(WebSocketStream {
                ws,
                rx_buffer: None,
                rx_ws_res: None,
            }),
            res.into_body().unwrap_or_default(),
        ))
    }
}

#[async_trait]
impl StreamOutboundFactory for WebSocketStreamOutboundFactory {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let next = self.next.upgrade().ok_or(FlowError::UnexpectedData)?;

        let host = match (&self.host, context.remote_peer.port) {
            (Some(_), _) => None,
            (None, 443 | 80) => Some(context.remote_peer.host.to_string()),
            (None, _) => Some(context.remote_peer.to_string()),
        };
        let host = if let Some(host) = self.host.as_ref() {
            host.as_str()
        } else {
            host.as_deref().unwrap()
        };
        let uri = Uri::builder()
            .scheme("ws")
            .authority(host)
            .path_and_query(&self.path)
            .build()
            .map_err(|_| FlowError::NoOutbound)?;
        let (lower, initial_res) = next.create_outbound(context, &[]).await?;
        let reader = StreamReader::new(4096, initial_res);
        self.websocket_handshake(lower, uri, reader, initial_data.into())
            .await
    }
}

fn ws_stream_err_to_flow_err(e: WsError) -> FlowError {
    match e {
        WsError::Io(e) => FlowError::Io(e),
        WsError::AlreadyClosed | WsError::ConnectionClosed => FlowError::Eof,
        _ => FlowError::UnexpectedData,
    }
}

impl Stream for WebSocketStream {
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
