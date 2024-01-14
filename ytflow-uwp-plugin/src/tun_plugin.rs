use std::mem::transmute;

use ytflow::flow::*;

use flume::{Receiver, Sender, TrySendError};
use windows::Networking::Vpn::{VpnChannel, VpnPacketBuffer};
use windows::Storage::Streams::Buffer as NativeBuffer;

unsafe fn token_to_native_buffer(token: TunBufferToken) -> (VpnPacketBuffer, NativeBuffer) {
    let ([vpn_buffer_ptr, buffer_ptr], _) = token.into_parts();
    (transmute(vpn_buffer_ptr), transmute(buffer_ptr))
}

pub(super) struct VpnTun {
    pub(super) channel: VpnChannel,
    pub(super) tx: Sender<VpnPacketBuffer>,
    pub(super) rx: Receiver<Buffer>,
    pub(super) dummy_socket: std::net::UdpSocket,
}

impl VpnTun {
    fn send_buffer(&self, vpn_buffer: VpnPacketBuffer) {
        if let Err(TrySendError::Full(vpn_buffer)) = self.tx.try_send(vpn_buffer) {
            // TODO: intentionally block?
            // VpnPacketBuffer must be returned back to system to dealloc
            let _ = self.dummy_socket.send(&[1][..]);
            let _ = self.tx.send(vpn_buffer);
        }
        if self.tx.len() == 1 {
            let _ = self.dummy_socket.send(&[1][..]);
        }
    }
}

impl Tun for VpnTun {
    // Read
    fn blocking_recv(&self) -> Option<Buffer> {
        self.rx.recv().ok()
    }
    fn return_recv_buffer(&self, _buf: Buffer) {}

    // Write
    fn get_tx_buffer(&self) -> Option<TunBufferToken> {
        let vpn_buffer = self.channel.GetVpnReceivePacketBuffer().ok()?;
        let mut buffer = vpn_buffer.Buffer().ok()?;
        Some(unsafe {
            let data = crate::vpn_plugin::query_slice_from_ibuffer_mut(&mut buffer);
            TunBufferToken::new([transmute(vpn_buffer), transmute(buffer)], data)
        })
    }
    fn send(&self, buf: TunBufferToken, len: usize) {
        let (vpn_buffer, buffer) = unsafe { token_to_native_buffer(buf) };
        // In case SetLength fails, try to consume the invalid packet as well to prevent leak.
        let _ = buffer.SetLength(len as u32);
        self.send_buffer(vpn_buffer);
    }
    fn return_tx_buffer(&self, buf: TunBufferToken) {
        let (vpn_buffer, _) = unsafe { token_to_native_buffer(buf) };
        // Try to consume the potentially invalid packet to prevent leak.
        self.send_buffer(vpn_buffer);
    }
}

impl Drop for VpnTun {
    fn drop(&mut self) {
        // Signal to Decapsulate to drain all tx buffers (if any) and shutdown the channel.
        let _ = self.dummy_socket.send(&[1][..]);
    }
}
