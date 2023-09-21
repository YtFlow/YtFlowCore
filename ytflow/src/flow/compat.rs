use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Buffer, FlowError, FlowResult, SizeHint, Stream, StreamReader};

pub struct CompatStream {
    pub inner: Box<dyn Stream>,
    pub reader: StreamReader,
}

pub struct CompatFlow<S> {
    inner: S,
    rx_buf: Option<Buffer>,
    tx_buf: Option<(Buffer, usize)>,
}

fn convert_error(err: FlowError) -> io::Error {
    use std::io::{Error, ErrorKind};
    match err {
        FlowError::Io(io) => io,
        FlowError::Eof => Error::new(ErrorKind::BrokenPipe, "The stream has reached EOF"),
        FlowError::NoOutbound => {
            Error::new(ErrorKind::NotConnected, "The outbound is not available")
        }
        FlowError::UnexpectedData => Error::new(ErrorKind::InvalidData, "Received unexpected data"),
    }
}

impl<S: AsyncRead + AsyncWrite + Send + 'static> CompatFlow<S> {
    pub fn new(inner: S, tx_buf_size: usize) -> Self {
        Self {
            inner,
            rx_buf: None,
            tx_buf: Some((Vec::with_capacity(tx_buf_size), 0)),
        }
    }
}

impl AsyncRead for CompatStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Self { inner, reader } = &mut *self;
        let res = ready!(reader.poll_peek_at_least(cx, &mut **inner, 1, |data| {
            let to_read = buf.remaining().min(data.len());
            buf.put_slice(&data[..to_read]);
            to_read
        }))
        .or_else(|e| {
            if let FlowError::Eof = &e {
                Ok(0)
            } else {
                Err(e)
            }
        })
        .map_err(convert_error)?;
        self.reader.advance(res);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CompatStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let len = match buf.len().try_into() {
            Ok(len) => len,
            Err(_) => return Poll::Ready(Ok(0)),
        };
        let inner = self.inner.as_mut();
        let mut tx_buf = ready!(inner.poll_tx_buffer(cx, len)).map_err(convert_error)?;
        tx_buf.extend_from_slice(buf);
        inner.commit_tx_buffer(tx_buf).map_err(convert_error)?;
        let _ = inner.poll_flush_tx(cx);
        Poll::Ready(Ok(len.get()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.inner
            .poll_flush_tx(cx)
            .map(|r| r.map_err(convert_error))
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.inner
            .poll_close_tx(cx)
            .map(|r| r.map_err(convert_error))
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for CompatFlow<S> {
    // Read
    fn poll_request_size(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        Poll::Ready(Ok(SizeHint::Unknown { overhead: 0 }))
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
            inner,
            rx_buf: rx_buf_opt,
            ..
        } = &mut *self;
        let rx_buf = rx_buf_opt.as_mut().unwrap();

        let mut read_buf = ReadBuf::uninit(rx_buf.spare_capacity_mut());
        if let Err(e) = ready!(Pin::new(inner).poll_read(cx, &mut read_buf)) {
            return Poll::Ready(Err((rx_buf_opt.take().unwrap(), e.into())));
        }

        let filled = read_buf.filled().len();
        let mut rx_buf = rx_buf_opt.take().unwrap();
        if filled == 0 {
            Poll::Ready(Err((rx_buf, FlowError::Eof)))
        } else {
            unsafe {
                rx_buf.set_len(rx_buf.len() + filled);
            }
            Poll::Ready(Ok(rx_buf))
        }
    }

    // Write
    fn poll_tx_buffer(
        &mut self,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        ready!(self.poll_flush_tx(cx))?;
        let (mut tx_buf, _) = self.tx_buf.take().unwrap();
        tx_buf.clear();
        tx_buf.reserve(size.get());
        Poll::Ready(Ok(tx_buf))
    }
    fn commit_tx_buffer(&mut self, buffer: Buffer) -> FlowResult<()> {
        self.tx_buf = Some((buffer, 0));
        Ok(())
    }
    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        let Self { tx_buf, inner, .. } = self;
        let (tx_buf, offset) = tx_buf
            .as_mut()
            .expect("Polling CompatFlow without previous buffer committed");
        while *offset < tx_buf.len() {
            let written = ready!(Pin::new(&mut *inner).poll_write(cx, &tx_buf[*offset..]))?;
            *offset += written;
        }
        ready!(Pin::new(&mut *inner).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        ready!(self.poll_flush_tx(cx))?;
        ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}
