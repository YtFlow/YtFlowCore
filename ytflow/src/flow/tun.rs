use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;

pub type TunBufferSignature = [*mut usize; 2];

pub struct TunBufferToken {
    /// Opaque data
    signature: TunBufferSignature,
    pub data: &'static mut [u8],
}

unsafe impl Send for TunBufferToken {}
unsafe impl Sync for TunBufferToken {}

impl TunBufferToken {
    /// # Safety
    ///
    /// User must ensure `signature` can be sent to other threads safely.
    pub unsafe fn new(signature: TunBufferSignature, data: &'static mut [u8]) -> Self {
        Self { signature, data }
    }
    pub fn into_parts(self) -> (TunBufferSignature, &'static mut [u8]) {
        (self.signature, self.data)
    }
}

pub trait Tun: Send + Sync {
    // Read
    fn blocking_recv(&self) -> Option<Buffer>;
    fn return_recv_buffer(&self, buf: Buffer);

    // Write
    fn get_tx_buffer(&self) -> Option<TunBufferToken>;
    fn send(&self, buf: TunBufferToken, len: usize);
    fn return_tx_buffer(&self, buf: TunBufferToken);
}
