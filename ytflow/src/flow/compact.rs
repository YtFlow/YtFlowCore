use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Buffer, FlowError, Stream, StreamReader};

pub struct CompactStream {
    inner: Pin<Box<dyn Stream>>,
    reader: StreamReader,
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

impl AsyncRead for CompactStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Self { inner, reader } = &mut *self;
        let res = ready!(reader.poll_peek_at_least(cx, inner.as_mut(), 1, |data| {
            let to_read = buf.remaining().min(data.len());
            buf.put_slice(&data[..to_read]);
            to_read
        }))
        .map_err(convert_error)?;
        self.reader.advance(res);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CompactStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let len = match buf.len().try_into() {
            Ok(len) => len,
            Err(_) => return Poll::Ready(Ok(0)),
        };
        let mut inner = self.inner.as_mut();
        let (mut tx_buf, offset) = ready!(inner.poll_tx_buffer(cx, len)).map_err(convert_error)?;
        tx_buf[offset..(offset + len.get())].copy_from_slice(buf);
        Poll::Ready(Ok(len.get()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.inner
            .as_mut()
            .poll_close_tx(cx)
            .map(|r| r.map_err(convert_error))
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.inner
            .as_mut()
            .poll_close_tx(cx)
            .map(|r| r.map_err(convert_error))
    }
}
