use std::mem::ManuallyDrop;

use std::sync::Weak;
use std::task::{Context, Poll};

use crate::flow::*;

struct FallbackStream<F: FnOnce(Box<dyn Stream>) + Unpin> {
    tx_closed: bool,
    lower: ManuallyDrop<Box<dyn Stream>>,
    on_fallback: ManuallyDrop<F>,
}

impl<F: FnOnce(Box<dyn Stream>) + Send + Sync + Unpin> Stream for FallbackStream<F> {
    fn poll_request_size(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        self.lower.poll_request_size(cx)
    }

    fn commit_rx_buffer(&mut self, buffer: Buffer) -> Result<(), (Buffer, FlowError)> {
        self.lower.commit_rx_buffer(buffer)
    }

    fn poll_rx_buffer(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        self.lower.poll_rx_buffer(cx)
    }

    fn poll_tx_buffer(
        &mut self,
        cx: &mut Context<'_>,
        size: std::num::NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        self.lower.poll_tx_buffer(cx, size)
    }

    fn commit_tx_buffer(&mut self, buffer: Buffer) -> FlowResult<()> {
        self.lower.commit_tx_buffer(buffer)
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.poll_flush_tx(cx)
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.tx_closed = true;
        self.lower.as_mut().poll_close_tx(cx)
    }
}

impl<F: FnOnce(Box<dyn Stream>) + Unpin> Drop for FallbackStream<F> {
    fn drop(&mut self) {
        unsafe {
            let lower = ManuallyDrop::take(&mut self.lower);
            let on_fallback = ManuallyDrop::take(&mut self.on_fallback);
            if !self.tx_closed {
                (on_fallback)(lower);
            }
        }
    }
}

pub struct FallbackHandler {
    next: Weak<dyn StreamHandler>,
    fallback: Weak<dyn StreamHandler>,
}

impl StreamHandler for FallbackHandler {
    fn on_stream(&self, lower: Box<dyn Stream>, context: Box<FlowContext>) {
        let fallback = self.fallback.clone();
        let context_clone = context.clone();
        let next = match self.next.upgrade() {
            Some(n) => n,
            None => return,
        };
        next.on_stream(
            Box::new(FallbackStream {
                tx_closed: false,
                lower: ManuallyDrop::new(lower),
                on_fallback: ManuallyDrop::new(move |lower| {
                    if let Some(fallback) = fallback.upgrade() {
                        fallback.on_stream(lower, context)
                    }
                }),
            }),
            context_clone,
        );
    }
}

// TODO: FallbackOutputHandler
