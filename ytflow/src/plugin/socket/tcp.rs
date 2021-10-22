use std::io::{self, ErrorKind::WouldBlock};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Weak;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::ready;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpSocket;

use crate::flow::*;

pub(super) struct RxBufDesc {
    buffer: Buffer,
    offset: usize,
}

pub(super) struct TcpStream {
    pub(super) inner: tokio::net::TcpStream,
    pub(super) rx_buf: Option<RxBufDesc>,
    pub(super) tx_buf: Option<(Buffer, usize)>,
}

impl Stream for TcpStream {
    fn poll_request_size(
        self: std::pin::Pin<&mut Self>,
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
        let Self { inner, rx_buf, .. } = &mut *self;
        loop {
            if let Err(_) = ready!(inner.poll_read_ready(cx)) {
                break Poll::Ready(Err((rx_buf.take().unwrap().buffer, FlowError::Eof)));
            };
            let RxBufDesc { buffer, offset } = rx_buf.as_mut().unwrap();
            match inner.try_read(&mut buffer[*offset..]) {
                Err(e) if e.kind() == WouldBlock => {
                    continue;
                }
                Err(e) => {
                    // TODO: log error
                    break Poll::Ready(Err((rx_buf.take().unwrap().buffer, FlowError::Eof)));
                }
                Ok(0) => {
                    break Poll::Ready(Err((rx_buf.take().unwrap().buffer, FlowError::Eof)));
                }
                Ok(len) => {
                    buffer.truncate(*offset + len);
                    break Poll::Ready(Ok(rx_buf.take().unwrap().buffer));
                }
            }
        }
    }

    fn poll_tx_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<(Buffer, usize)>> {
        let Self { inner, tx_buf, .. } = &mut *self;
        loop {
            let (buffer, read_at) = tx_buf.as_mut().unwrap();
            if buffer.len() <= *read_at {
                let mut buf = std::mem::replace(buffer, Vec::new());
                *tx_buf = None;
                buf.resize(size.into(), 0);
                break Poll::Ready(Ok((buf, 0)));
            } else {
                ready!(inner.poll_write_ready(cx)).map_err(|_| FlowError::Eof)?;
                let len = inner
                    .try_write(&buffer[*read_at..])
                    .map_err(|_| FlowError::Eof)?;
                *read_at += len;
            }
        }
    }

    fn commit_tx_buffer(mut self: Pin<&mut Self>, buffer: Buffer) -> FlowResult<()> {
        let Self { inner, tx_buf, .. } = &mut *self;
        let written = inner.try_write(&*buffer).or_else(|e| {
            if e.kind() == WouldBlock {
                Ok(0)
            } else {
                // TODO: log error
                Err(FlowError::Eof)
            }
        });
        *tx_buf = Some((buffer, written.as_ref().map_or(0, |w| *w)));
        written.map(|_| ())
    }

    fn poll_close_tx(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        let Self { inner, tx_buf, .. } = &mut *self;

        while let Some((tx_buf, offset)) = tx_buf
            .as_mut()
            .filter(|(tx_buf, offset)| tx_buf.len() != *offset)
        {
            if ready!(inner.poll_write_ready(cx)).is_err() {
                break;
            }
            let written = match inner.try_write(&tx_buf[*offset..]) {
                Ok(w) => w,
                Err(_) => break,
            };
            *offset += written;
        }

        let _ = ready!(Pin::new(inner).poll_shutdown(cx));
        Poll::Ready(Ok(()))
    }
}

pub(super) async fn dial_v4(
    dest: SocketAddrV4,
    bind_addr: SocketAddrV4,
) -> io::Result<tokio::net::TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(if dest.ip().is_loopback() {
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
    } else {
        bind_addr.into()
    })?;
    socket.connect(dest.into()).await
}

pub(super) async fn dial_v6(
    dest: SocketAddrV6,
    bind_addr: SocketAddrV6,
) -> io::Result<tokio::net::TcpStream> {
    let socket = TcpSocket::new_v6()?;
    socket.bind(if dest.ip().is_loopback() {
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)
    } else {
        bind_addr.into()
    })?;
    socket.connect(dest.into()).await
}
