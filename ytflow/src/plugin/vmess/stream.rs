use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::sync::oneshot;

use crate::flow::*;

use super::protocol::body::{RxCrypto, TxCrypto};
use super::protocol::header::{HeaderDecryptResult, ResponseHeaderDec};

enum TxCloseState {
    FlushingLastChunk,
    AwaitingRxClose,
    ClosingLower,
}

pub(super) struct VMessClientStream<D, RxC, TxC> {
    lower: Box<dyn Stream>,
    reader: StreamReader,
    header_dec: Option<D>,
    rx_crypto: RxC,
    rx_buf: Option<Buffer>,
    rx_close_chan_tx: Option<oneshot::Sender<()>>,
    rx_close_chan_rx: Option<oneshot::Receiver<()>>,
    tx_crypto: TxC,
    tx_chunks: (usize, usize, usize),
    tx_close_state: TxCloseState,
}

impl<D, RxC, TxC> VMessClientStream<D, RxC, TxC> {
    pub fn new(
        stream: Box<dyn Stream>,
        reader: StreamReader,
        header_dec: D,
        rx_crypto: RxC,
        tx_crypto: TxC,
    ) -> Self {
        Self {
            lower: stream,
            reader,
            header_dec: Some(header_dec),
            rx_crypto,
            rx_buf: None,
            rx_close_chan_rx: None,
            rx_close_chan_tx: None,
            tx_crypto,
            tx_chunks: Default::default(),
            tx_close_state: TxCloseState::FlushingLastChunk,
        }
    }
}

impl<
        D: ResponseHeaderDec + Send + Sync,
        RxC: RxCrypto + Send + Sync,
        TxC: TxCrypto + Send + Sync,
    > Stream for VMessClientStream<D, RxC, TxC>
{
    fn poll_request_size(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        if let Some(header_dec) = self.header_dec.as_mut() {
            let mut expected = 1;
            loop {
                let read_head_res = ready!(self.reader.poll_peek_at_least(
                    cx,
                    &mut *self.lower,
                    expected,
                    |buf| {
                        let res = header_dec.decrypt_res(&mut buf[..]);
                        if let HeaderDecryptResult::Complete { res: _, len } = res {
                            // Trick for aes-cfb body to continue from aes-cfb header dec state.
                            // AesCfb header dec should not mutate data inplace.
                            // For AEAD header, we don't care.
                            self.rx_crypto.peek_header_ciphertext(&mut buf[..len]);
                        }
                        res
                    }
                ))?;
                match read_head_res {
                    HeaderDecryptResult::Invalid => {
                        return Poll::Ready(Err(FlowError::UnexpectedData))
                    }
                    HeaderDecryptResult::Incomplete { total_required } => expected = total_required,
                    HeaderDecryptResult::Complete { res: _, len } => {
                        // TODO: res?
                        self.reader.advance(len);
                        self.header_dec = None;
                        let (tx, rx) = oneshot::channel();
                        self.rx_close_chan_tx = Some(tx);
                        self.rx_close_chan_rx = Some(rx);
                        break;
                    }
                }
            }
        }
        let expected = self.rx_crypto.expected_next_size_len();
        let size_res = ready!(self
            .reader
            .poll_read_exact(cx, &mut *self.lower, expected, |buf| {
                self.rx_crypto.on_size(buf)
            }))
        .flatten();
        if let Err(_) | Ok(0) = &size_res {
            self.rx_close_chan_tx = None;
        }
        Poll::Ready(match size_res {
            // Required by the protocol
            Ok(0) => Err(FlowError::Eof),
            Ok(size) => Ok(SizeHint::AtLeast(size)),
            Err(e) => Err(e),
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
            self.rx_close_chan_tx = None;
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
        // buffer may have zero length. See `poll_close_tx`.
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
        // If `lower` is a WebSocket stream which does not support half close, closing it immediately
        // will cause rx to terminate prematurely even with unsent data.
        loop {
            match self.tx_close_state {
                TxCloseState::FlushingLastChunk => {
                    // As required by the protocol, the last chunk with size 0 inside indicates Eof.
                    ready!(self.lower.poll_flush_tx(cx))?;
                    self.tx_close_state = TxCloseState::AwaitingRxClose;
                }
                TxCloseState::AwaitingRxClose => {
                    let Some(close_rx) = &mut self.rx_close_chan_rx else {
                        self.tx_close_state = TxCloseState::ClosingLower;
                        continue;
                    };
                    let _ = ready!(Pin::new(close_rx).poll(cx)).ok();
                    self.tx_close_state = TxCloseState::ClosingLower;
                }
                TxCloseState::ClosingLower => break self.lower.poll_close_tx(cx),
            }
        }
    }
}
