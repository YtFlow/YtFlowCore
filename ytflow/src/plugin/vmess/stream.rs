use std::num::NonZeroUsize;
use std::task::{ready, Context, Poll};

use crate::flow::*;

use super::protocol::body::{RxCrypto, TxCrypto};

pub(super) struct VMessClientStream<RxC, TxC> {
    pub(super) lower: Box<dyn Stream>,
    pub(super) reader: StreamReader,
    pub(super) rx_crypto: RxC,
    pub(super) rx_buf: Option<Buffer>,
    pub(super) tx_crypto: TxC,
    pub(super) tx_chunks: (usize, usize, usize),
}

impl<RxC: RxCrypto + Send + Sync, TxC: TxCrypto + Send + Sync> Stream
    for VMessClientStream<RxC, TxC>
{
    fn poll_request_size(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        let size = loop {
            let expected = self.rx_crypto.expected_next_size_len();
            if let Some(size) =
                ready!(self
                    .reader
                    .poll_peek_at_least(cx, &mut *self.lower, expected, |buf| {
                        self.rx_crypto.on_size(&mut buf[..expected])
                    }))??
            {
                self.reader.advance(expected);
                break size;
            }
        };
        Poll::Ready(if size == 0 {
            // Somehow it appears once with server: v2ray-core v5.4.1 win x64
            // Not sure how to reproduce
            Err(FlowError::Eof)
        } else {
            Ok(SizeHint::AtLeast(size))
        })
    }

    fn commit_rx_buffer(&mut self, buffer: Buffer) -> Result<(), (Buffer, FlowError)> {
        self.rx_buf = Some(buffer);
        Ok(())
    }

    fn poll_rx_buffer(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        let len = self.rx_crypto.expected_next_chunk_len();
        let Self {
            rx_buf: rx_buf_opt,
            rx_crypto,
            reader,
            lower,
            ..
        } = &mut *self;
        let rx_buf = rx_buf_opt.as_mut().unwrap();
        let res = ready!(reader.poll_read_exact(cx, &mut **lower, len, |buf| {
            let chunk = rx_crypto.on_chunk(buf)?;
            rx_buf.extend_from_slice(chunk);
            Ok(())
        }))
        .flatten();
        let rx_buf = rx_buf_opt.take().unwrap();
        if let Err(e) = res {
            return Poll::Ready(Err((rx_buf, e)));
        }
        Poll::Ready(Ok(rx_buf))
    }

    fn poll_tx_buffer(
        &mut self,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        let (pre_overhead, post_overhead) = self.tx_crypto.calculate_overhead(size.get());
        let mut buf = ready!(self.lower.poll_tx_buffer(
            cx,
            (size.get() + pre_overhead + post_overhead)
                .try_into()
                .unwrap(),
        ))?;
        self.tx_chunks = (buf.len(), pre_overhead, post_overhead);
        buf.resize(buf.len() + pre_overhead, 0);
        Poll::Ready(Ok(buf))
    }

    fn commit_tx_buffer(&mut self, mut buffer: Buffer) -> FlowResult<()> {
        let (offset, pre_overhead_len, post_overhead_len) = self.tx_chunks;
        let payload_len = buffer.len() - pre_overhead_len - offset;
        buffer.resize(
            offset + pre_overhead_len + payload_len + post_overhead_len,
            0,
        );
        let (pre_overhead, remaining) = buffer[offset..].split_at_mut(pre_overhead_len);
        let (payload, post_overhead) = remaining.split_at_mut(payload_len);
        let post_overhead = &mut post_overhead[..post_overhead_len];
        self.tx_crypto.seal(pre_overhead, payload, post_overhead);
        self.lower.commit_tx_buffer(buffer)
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.poll_flush_tx(cx)
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.poll_close_tx(cx)
    }
}
