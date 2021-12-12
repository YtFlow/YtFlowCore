use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use futures::future::poll_fn;
use futures::ready;
use tokio::time::timeout;

use super::tcp_socket_entry::*;
use crate::flow::*;

pub(super) struct IpStackStream {
    pub(super) socket_entry: TcpSocketEntry,
    pub(super) rx_buf: Option<Buffer>,
    pub(super) tx_buf: Option<(Buffer, usize)>,
}

impl IpStackStream {
    pub(super) async fn handshake(&mut self) -> Result<(), ()> {
        timeout(
            Duration::from_millis(1000 * 60),
            poll_fn(|cx| {
                self.socket_entry.lock().with_socket(|s| {
                    if s.may_send() {
                        return Poll::Ready(());
                    }
                    s.register_send_waker(cx.waker());
                    Poll::Pending
                })
            }),
        )
        .await
        .map_err(|_| ())
    }
}

impl Stream for IpStackStream {
    // Read
    fn poll_request_size(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        Poll::Ready(Ok(Default::default()))
    }

    fn commit_rx_buffer(&mut self, buffer: Buffer) -> Result<(), (Buffer, FlowError)> {
        self.rx_buf = Some(buffer);
        Ok(())
    }

    fn poll_rx_buffer(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        let Self {
            socket_entry,
            rx_buf,
            ..
        } = &mut *self;
        let mut socket_guard = socket_entry.lock();
        ready!(socket_guard.with_socket(|socket| {
            let buffer = rx_buf
                .as_mut()
                .expect("Polling empty rx buffer from ip_stack");
            let offset = buffer.len();
            let target_len = std::cmp::min(buffer.capacity(), socket.recv_queue() + offset);
            buffer.resize(target_len, 0);
            match socket.recv_slice(&mut buffer[offset..]) {
                Ok(0) => {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
                Ok(s) => {
                    buffer.truncate(offset + s);
                    Poll::Ready(Ok(()))
                }
                Err(_) => Poll::Ready(Err((rx_buf.take().unwrap(), FlowError::Eof))),
            }
        }))?;
        socket_guard.poll();
        drop(socket_guard);
        Poll::Ready(Ok(rx_buf.take().unwrap()))
    }

    // Write
    fn poll_tx_buffer(
        &mut self,
        cx: &mut Context<'_>,
        size: std::num::NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        let Self {
            tx_buf,
            socket_entry,
            ..
        } = &mut *self;
        let (buffer, read_at) = tx_buf
            .as_mut()
            .expect("IpStackStream: cannot pull buffer without committing");
        while buffer.capacity() >= size.get()
            && buffer.capacity() - buffer.len() + *read_at < size.get()
        {
            let mut socket_guard = socket_entry.lock();
            match socket_guard.with_socket(|s| s.send_slice(&buffer[*read_at..])) {
                Ok(0) => {
                    socket_guard.with_socket(|s| s.register_send_waker(cx.waker()));
                    return Poll::Pending;
                }
                Ok(len) => {
                    *read_at += len;
                    socket_guard.poll();
                    continue;
                }
                Err(_) => return Poll::Ready(Err(FlowError::Eof)),
            }
        }
        let (mut buf, read_at) = tx_buf.take().unwrap();
        buf.drain(..read_at);
        buf.reserve(size.get());
        Poll::Ready(Ok(buf))
    }

    fn commit_tx_buffer(&mut self, buffer: Buffer) -> FlowResult<()> {
        self.tx_buf = Some((buffer, 0));
        Ok(())
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        let Self {
            tx_buf,
            socket_entry,
            ..
        } = &mut *self;
        let (tx_buf, read_at) = tx_buf
            .as_mut()
            .expect("IpStackStream: cannot flush without committing");
        let mut socket_guard = socket_entry.lock();
        while tx_buf.len() > *read_at {
            match socket_guard.with_socket(|s| s.send_slice(&tx_buf[*read_at..])) {
                Ok(0) => {
                    socket_guard.with_socket(|s| s.register_send_waker(cx.waker()));
                    return Poll::Pending;
                }
                Ok(s) => {
                    *read_at += s;
                    socket_guard.poll();
                }
                Err(_) => return Poll::Ready(Err(FlowError::Eof)),
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        // Send remaining data in tx buf
        if self.tx_buf.is_some() {
            ready!(self.poll_flush_tx(cx))?;
        }

        // Send remaining data in socket buffer and FIN
        let mut socket_guard = self.socket_entry.lock();
        let res = socket_guard.with_socket(|s| {
            if s.send_queue() > 0 {
                s.register_send_waker(cx.waker());
                Poll::Pending
            } else {
                s.close();
                Poll::Ready(Ok(()))
            }
        });
        socket_guard.poll();
        res
    }
}

impl Drop for IpStackStream {
    fn drop(&mut self) {
        let local_port = self.socket_entry.local_port;
        let mut socket_guard = self.socket_entry.lock();
        socket_guard.with_socket(|s| s.abort());
        socket_guard.poll();
        socket_guard.guard.tcp_sockets.remove(&local_port);
    }
}
