use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;

use crate::flow::*;

pub(super) struct InitialDataExtractStream {
    pub(super) data: Arc<Mutex<Option<Buffer>>>,
}

impl Stream for InitialDataExtractStream {
    fn poll_request_size(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        Poll::Pending
    }

    fn commit_rx_buffer(&mut self, _buffer: Buffer) -> Result<(), (Buffer, FlowError)> {
        panic!("InitialDataExtractStream: should not commit rx buffer without requesting size");
    }

    fn poll_rx_buffer(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        Poll::Pending
    }

    fn poll_tx_buffer(
        &mut self,
        _cx: &mut Context<'_>,
        size: std::num::NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        let mut buf = self.data.lock();
        let mut buf = buf
            .take()
            .expect("InitialDataExtractStream: should not poll tx buffer without committing first");
        buf.reserve(size.get());
        Poll::Ready(Ok(buf))
    }

    fn commit_tx_buffer(&mut self, buffer: Buffer) -> FlowResult<()> {
        let mut buf = self.data.lock();
        *buf = Some(buffer);
        Ok(())
    }

    fn poll_flush_tx(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close_tx(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        Poll::Ready(Ok(()))
    }
}
