use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;

use crate::flow::*;

pub(super) struct InitialDataExtractStream {
    pub(super) data: Arc<Mutex<Option<Buffer>>>,
}

impl Stream for InitialDataExtractStream {
    fn poll_request_size(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<FlowResult<SizeHint>> {
        Poll::Pending
    }

    fn commit_rx_buffer(
        self: Pin<&mut Self>,
        _buffer: Buffer,
        _offset: usize,
    ) -> Result<(), (Buffer, FlowError)> {
        panic!("InitialDataExtractStream: should not commit rx buffer without requesting size");
    }

    fn poll_rx_buffer(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        Poll::Pending
    }

    fn poll_tx_buffer(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        size: std::num::NonZeroUsize,
    ) -> Poll<FlowResult<(Buffer, usize)>> {
        let mut buf = self.data.lock();
        let mut buf = buf
            .take()
            .expect("InitialDataExtractStream: should not poll tx buffer without committing first");
        let offset = buf.len();
        buf.resize(size.get() + offset, 0);
        Poll::Ready(Ok((buf, 0)))
    }

    fn commit_tx_buffer(self: Pin<&mut Self>, buffer: Buffer) -> FlowResult<()> {
        let mut buf = self.data.lock();
        *buf = Some(buffer);
        Ok(())
    }

    fn poll_close_tx(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        Poll::Ready(Ok(()))
    }
}
