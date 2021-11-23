use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use async_trait::async_trait;

use crate::flow::context::FlowContext;
use crate::flow::error::{FlowError, FlowResult};

// TODO: custom buffer with offset
pub type Buffer = Vec<u8>;

#[derive(Debug, Clone, Copy)]
pub enum SizeHint {
    AtLeast(usize),
    Unknown { overhead: usize },
}

impl SizeHint {
    #[inline]
    pub fn with_min_content(self, content_len: usize) -> usize {
        match self {
            Self::AtLeast(min) => min,
            Self::Unknown { overhead } => overhead + content_len,
        }
    }
}

impl Default for SizeHint {
    fn default() -> SizeHint {
        Self::Unknown { overhead: 0 }
    }
}

pub trait Stream: Send + Sync {
    // Read
    fn poll_request_size(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>>;
    fn commit_rx_buffer(
        self: Pin<&mut Self>,
        buffer: Buffer,
        offset: usize,
    ) -> Result<(), (Buffer, FlowError)>;
    fn poll_rx_buffer(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>>;

    // Write
    fn poll_tx_buffer(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<(Buffer, usize)>>;
    fn commit_tx_buffer(self: Pin<&mut Self>, buffer: Buffer) -> FlowResult<()>;

    fn poll_close_tx(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>>;
}

#[macro_export]
macro_rules! get_request_size_boxed {
    ($s: expr) => {
        ::futures::future::poll_fn(|cx| $s.as_mut().poll_request_size(cx)).await
    };
}

#[macro_export]
macro_rules! get_rx_buffer_boxed {
    ($s: expr) => {
        ::futures::future::poll_fn(|cx| $s.as_mut().poll_rx_buffer(cx)).await
    };
}

#[macro_export]
macro_rules! get_tx_buffer_boxed {
    ($s: expr, $size: expr) => {
        ::futures::future::poll_fn(|cx| $s.as_mut().poll_tx_buffer(cx, $size)).await
    };
}

#[macro_export]
macro_rules! close_tx_boxed {
    ($s: expr) => {
        ::futures::future::poll_fn(|cx| $s.as_mut().poll_close_tx(cx)).await
    };
}

pub trait StreamHandler: Send + Sync {
    fn on_stream(&self, lower: Pin<Box<dyn Stream>>, context: Box<FlowContext>);
}

#[async_trait]
pub trait StreamOutboundFactory: Send + Sync {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<Pin<Box<dyn Stream>>>;
}
