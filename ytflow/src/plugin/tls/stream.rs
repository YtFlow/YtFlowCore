use std::future::Future;
use std::num::NonZeroUsize;
use std::os::raw::c_int;
use std::pin::Pin;
use std::sync::Weak;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::future::poll_fn;
use futures::ready;

use super::ffi::ssl::SslResult;
use super::ffi::*;
use crate::flow::*;

pub struct SslStream {
    ssl: ssl::Ssl,
    rx_buf: Option<(Buffer, usize)>,
    tx_buf: Option<(Buffer, usize)>,
    shutdown: bool,
    lower: Pin<Box<dyn Stream>>,
}

pub struct SslStreamFactory {
    ctx: ctx::SslCtx,
    next: Weak<dyn StreamOutboundFactory>,
}

impl SslStreamFactory {
    pub fn new(next: Weak<dyn StreamOutboundFactory>) -> Self {
        // TODO: sni, alpn, ...
        Self {
            ctx: ctx::SslCtx::new(),
            next,
        }
    }
}

impl Stream for SslStream {
    fn poll_request_size(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        Poll::Ready(Ok(SizeHint::Unknown { overhead: 0 }))
    }

    fn commit_rx_buffer(
        mut self: Pin<&mut Self>,
        buffer: Buffer,
        offset: usize,
    ) -> Result<(), (Buffer, FlowError)> {
        self.rx_buf = Some((buffer, offset));
        Ok(())
    }

    fn poll_rx_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        let Self {
            ssl,
            rx_buf: rx_buf_opt,
            lower,
            ..
        } = &mut *self;
        let (rx_buf, offset) = rx_buf_opt.as_mut().unwrap();
        let read = match ready!(poll_ssl_action(
            cx,
            |ssl| ssl.read(&mut rx_buf[*offset..]),
            ssl,
            lower.as_mut()
        )) {
            Ok(r) => r as usize,
            Err(e) => return Poll::Ready(Err((rx_buf_opt.take().unwrap().0, e))),
        };
        rx_buf.truncate(*offset + read);
        Poll::Ready(Ok(rx_buf_opt.take().unwrap().0))
    }

    fn poll_tx_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<(Buffer, usize)>> {
        let Self {
            tx_buf: tx_buf_opt,
            ssl,
            lower,
            ..
        } = &mut *self;
        let (tx_buf, offset) = tx_buf_opt.as_mut().unwrap();
        while *offset < tx_buf.len() {
            *offset += ready!(poll_ssl_action(
                cx,
                |ssl| ssl.write(&tx_buf[*offset..]),
                ssl,
                lower.as_mut()
            ))? as usize;
        }
        tx_buf.resize(size.get(), 0);
        Poll::Ready(Ok((tx_buf_opt.take().unwrap().0, 0)))
    }

    fn commit_tx_buffer(mut self: Pin<&mut Self>, buffer: Buffer) -> FlowResult<()> {
        let Self {
            tx_buf, ssl, lower, ..
        } = &mut *self;
        let (tx_buf, offset) = tx_buf.insert((buffer, 0));
        let written = match ssl.write(tx_buf.as_slice()) {
            SslResult::Ok(r) => r as usize,
            SslResult::Other => return Err(FlowError::UnexpectedData),
            SslResult::Fatal(s) => {
                // TODO: log error
                return Err(FlowError::UnexpectedData);
            }
            SslResult::WantRead | SslResult::WantWrite => return Ok(()),
        };
        *offset += written;
        Ok(())
    }

    fn poll_close_tx(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        let Self {
            tx_buf: tx_buf_opt,
            ssl,
            lower,
            shutdown,
            ..
        } = &mut *self;
        while let Some((tx_buf, offset)) = tx_buf_opt.as_mut().filter(|(b, o)| *o < b.len()) {
            *offset += ready!(poll_ssl_action(
                cx,
                |ssl| ssl.write(&tx_buf[*offset..]),
                ssl,
                lower.as_mut()
            ))? as usize;
        }
        if !*shutdown {
            ready!(poll_ssl_action(
                cx,
                |ssl| ssl.shutdown(),
                ssl,
                lower.as_mut()
            ))?;
            *shutdown = true;
        }
        lower.as_mut().poll_close_tx(cx)
    }
}

#[async_trait]
impl StreamOutboundFactory for SslStreamFactory {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        mut initial_data: &'_ [u8],
    ) -> FlowResult<Pin<Box<dyn Stream>>> {
        let outbound_factory = self.next.upgrade().ok_or(FlowError::NoOutbound)?;
        let bio = bio::Bio::new();
        let mut ssl = ssl::Ssl::new_client(&self.ctx, bio);
        ssl.inner_data_mut().rx_buf = Some((Vec::with_capacity(4096), 0));
        ssl.inner_data_mut().tx_buf = Some((vec![0; 4096], 0));

        // Extract initial data from handshake to sent to lower
        let handshake_ret = ssl.do_handshake();
        if let SslResult::Fatal(_) | SslResult::Other = handshake_ret {
            // TODO: log error
            return Err(FlowError::UnexpectedData);
        }
        let (lower_initial_data, lower_initial_data_len) = match ssl.inner_data_mut().tx_buf.take()
        {
            Some(buf) => buf,
            None => return Err(FlowError::UnexpectedData),
        };
        let lower_initial_data = &lower_initial_data[..lower_initial_data_len];
        let mut lower = outbound_factory
            .create_outbound(context, lower_initial_data)
            .await?;

        // Finish handshake
        while initial_data.len() > 0 {
            let written = poll_fn(|cx| {
                poll_ssl_action(cx, |ssl| ssl.write(initial_data), &mut ssl, lower.as_mut())
            })
            .await? as usize;
            initial_data = &initial_data[written..];
        }

        Ok(Box::pin(SslStream {
            ssl,
            rx_buf: None,
            tx_buf: Some((vec![0; 4096], 4096)),
            shutdown: false,
            lower,
        }))
    }
}

fn poll_ssl_action(
    cx: &mut Context<'_>,
    mut act: impl FnMut(&mut ssl::Ssl) -> SslResult,
    ssl: &mut ssl::Ssl,
    mut lower: Pin<&mut dyn Stream>,
) -> Poll<FlowResult<c_int>> {
    loop {
        let tx_offset = ssl.inner_data_mut().tx_buf.as_ref().map(|(_, l)| *l);
        let ret = act(ssl);
        if {
            let tx_buf = ssl.inner_data_mut().tx_buf.as_ref();
            // Either SSL has written something ...
            tx_buf.map(|(_, l)| *l) != tx_offset
            // ... or the tx buffer is already full,
            || tx_buf.map(|(b, o)| b.len() == *o).unwrap_or(false)
        } {
            // Send buffer to lower.
            let (mut buf, offset) = ssl.inner_data_mut().tx_buf.take().unwrap();
            buf.truncate(offset);
            lower.as_mut().commit_tx_buffer(buf)?;
        }
        match ret {
            SslResult::Ok(n) => break Poll::Ready(Ok(n)),
            SslResult::Other => break Poll::Ready(Err(FlowError::UnexpectedData)),
            SslResult::Fatal(_) => {
                // TODO: log error
                break Poll::Ready(Err(FlowError::UnexpectedData));
            }
            SslResult::WantRead => {
                let size_hint = match ssl.inner_data_mut().rx_size_hint.as_mut() {
                    Some(h) => h,
                    None => ssl
                        .inner_data_mut()
                        .rx_size_hint
                        .insert(ready!(lower.as_mut().poll_request_size(cx))?),
                }
                .with_min_content(4096);
                match ssl.inner_data_mut().rx_buf.take() {
                    Some((mut buf, offset)) => {
                        buf.drain(..offset);
                        buf.resize(size_hint, 0);
                        lower
                            .as_mut()
                            .commit_rx_buffer(buf, 0)
                            .map_err(|(mut buf, e)| {
                                buf.clear();
                                ssl.inner_data_mut().rx_buf = Some((buf, 0));
                                e
                            })?;
                    }
                    None => {
                        let buf =
                            ready!(lower.as_mut().poll_rx_buffer(cx)).map_err(|(mut buf, e)| {
                                buf.clear();
                                ssl.inner_data_mut().rx_buf = Some((buf, 0));
                                e
                            })?;
                        ssl.inner_data_mut().rx_buf.insert((buf, 0));
                    }
                }
                ssl.inner_data_mut().rx_size_hint = None;
            }
            SslResult::WantWrite => {
                // Case 1: tx_buf is not available. Poll from lower.
                // Case 2: tx_buf was full, and must have been committed to lower. Poll from lower too.
                ssl.inner_data_mut().tx_buf = Some(ready!(lower
                    .as_mut()
                    .poll_tx_buffer(cx, 4096.try_into().unwrap()))?);
            }
        }
    }
}
