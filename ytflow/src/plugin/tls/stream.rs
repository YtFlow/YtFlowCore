use std::future::Future;
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
    lower: Pin<Box<dyn Stream>>,
}

pub struct SslStreamFactory {
    ctx: ctx::SslCtx,
    next: Weak<dyn StreamOutboundFactory>,
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        todo!()
    }

    fn poll_tx_buffer(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        size: std::num::NonZeroUsize,
    ) -> Poll<FlowResult<(Buffer, usize)>> {
        todo!()
    }

    fn commit_tx_buffer(self: Pin<&mut Self>, buffer: Buffer) -> FlowResult<()> {
        todo!()
    }

    fn poll_close_tx(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        todo!()
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
        let mut ssl = ssl::Ssl::new(&self.ctx, bio);
        *ssl.tx_buf() = Some(Vec::with_capacity(4096));

        // Extract initial data from handshake to sent to lower
        let handshake_ret = ssl.do_handshake();
        if let SslResult::Fatal = handshake_ret {
            return Err(FlowError::UnexpectedData);
        }
        let lower_initial_data = match ssl.tx_buf() {
            Some(b) => b.as_slice(),
            None => return Err(FlowError::UnexpectedData),
        };
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

        todo!()
    }
}

fn poll_ssl_action(
    cx: &mut Context<'_>,
    act: impl Fn(&mut ssl::Ssl) -> SslResult,
    ssl: &mut ssl::Ssl,
    mut lower: Pin<&mut dyn Stream>,
) -> Poll<FlowResult<c_int>> {
    loop {
        match act(ssl) {
            SslResult::Ok(n) => break Poll::Ready(Ok(n)),
            SslResult::Fatal => break Poll::Ready(Err(FlowError::UnexpectedData)),
            SslResult::WantRead => {
                let (rx_buf, offset) = match ssl.rx_buf().as_mut() {
                    Some(buf) => buf,
                    None => {
                        let buf =
                            ready!(lower.as_mut().poll_rx_buffer(cx)).map_err(|(mut buf, e)| {
                                buf.clear();
                                *ssl.rx_buf() = Some((buf, 0));
                                e
                            })?;
                        ssl.rx_buf().insert((buf, 0))
                    }
                };
                todo!();
            }
            SslResult::WantWrite => {
                todo!();
            }
        }
    }
}
