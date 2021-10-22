use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use futures::future::poll_fn;
use futures::ready;
use tokio::time::timeout;

use super::tcp_socket_entry::*;
use super::*;
use crate::flow::*;

pub struct RxBufDesc {
    buffer: Buffer,
    offset: usize,
}

pub(super) struct IpStackStream<P: IpTxBuf> {
    pub(super) socket_entry: TcpSocketEntry<P>,
    pub(super) rx_buf: Option<RxBufDesc>,
    pub(super) tx_buf: Option<(Buffer, usize)>,
}

impl<P: IpTxBuf> IpStackStream<P> {
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

impl<P: IpTxBuf> Stream for IpStackStream<P> {
    // Read
    fn poll_request_size(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<FlowResult<SizeHint>> {
        Poll::Ready(Ok(Default::default()))
    }

    fn commit_rx_buffer(
        mut self: Pin<&mut Self>,
        buffer: Buffer,
        offset: usize,
    ) -> Result<(), (Buffer, FlowError)> {
        self.rx_buf = Some(RxBufDesc { buffer, offset });
        Ok(())
    }

    fn poll_rx_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        let Self {
            socket_entry,
            rx_buf,
            ..
        } = &mut *self;
        let mut socket_guard = socket_entry.lock();
        ready!(socket_guard.with_socket(|socket| {
            let RxBufDesc { buffer, offset } = rx_buf.as_mut().unwrap();
            match socket.recv_slice(&mut buffer[*offset..]) {
                Ok(0) => {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
                Ok(s) => {
                    *offset += s;
                    Poll::Ready(Ok(()))
                }
                Err(_) => Poll::Ready(Err((rx_buf.take().unwrap().buffer, FlowError::Eof))),
            }
        }))?;
        socket_guard.poll();
        drop(socket_guard);
        let RxBufDesc {
            mut buffer, offset, ..
        } = rx_buf.take().unwrap();
        buffer.truncate(offset);
        Poll::Ready(Ok(buffer))
    }

    // Write
    fn poll_tx_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        size: std::num::NonZeroUsize,
    ) -> Poll<FlowResult<(Buffer, usize)>> {
        let Self {
            tx_buf,
            socket_entry,
            ..
        } = &mut *self;
        loop {
            let (buffer, read_at) = tx_buf.as_mut().unwrap();
            if buffer.len() <= *read_at {
                let mut buf = std::mem::replace(buffer, Vec::new());
                *tx_buf = None;
                buf.resize(size.into(), 0);
                break Poll::Ready(Ok((buf, 0)));
            } else {
                let mut socket_guard = socket_entry.lock();
                match socket_guard.with_socket(|s| s.send_slice(&buffer[*read_at..])) {
                    Ok(0) => {
                        socket_guard.with_socket(|s| s.register_send_waker(cx.waker()));
                        break Poll::Pending;
                    }
                    Ok(len) => {
                        *read_at += len;
                        socket_guard.poll();
                        continue;
                    }
                    Err(_) => break Poll::Ready(Err(FlowError::Eof)),
                }
            }
        }
    }

    fn commit_tx_buffer(mut self: Pin<&mut Self>, buffer: Buffer) -> FlowResult<()> {
        let Self {
            tx_buf,
            socket_entry,
            ..
        } = &mut *self;
        let mut socket_guard = socket_entry.lock();
        let written = socket_guard
            .with_socket(|s| s.send_slice(&buffer[..]))
            .map_err(|_| FlowError::Eof);
        socket_guard.poll();
        drop(socket_guard);
        *tx_buf = Some((buffer, written.as_ref().map_or(0, |w| *w)));
        written.map(|_| ())
    }

    fn poll_close_tx(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        let Self {
            socket_entry,
            tx_buf,
            ..
        } = &mut *self.as_mut();
        if let Some((tx_buf, offset)) = tx_buf
            .as_mut()
            .filter(|(tx_buf, offset)| tx_buf.len() != *offset)
        {
            // Send remaining data in tx buf
            let mut socket_guard = socket_entry.lock();
            ready!(
                socket_guard.with_socket(|s| match s.send_slice(&tx_buf[*offset..]) {
                    Ok(sent) => {
                        *offset += sent;
                        if *offset != tx_buf.len() {
                            Poll::Ready(())
                        } else {
                            s.register_send_waker(cx.waker());
                            Poll::Pending
                        }
                    }
                    Err(_) => Poll::Ready(()),
                })
            );
            socket_guard.poll();
        }
        // Send remaining data in socket buffer and FIN
        let mut socket_guard = socket_entry.lock();
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

impl<P: IpTxBuf> Drop for IpStackStream<P> {
    fn drop(&mut self) {
        let local_port = self.socket_entry.local_port;
        let mut socket_guard = self.socket_entry.lock();
        socket_guard.with_socket(|s| s.abort());
        socket_guard.poll();
        socket_guard.guard.tcp_sockets.remove(&local_port);
    }
}
