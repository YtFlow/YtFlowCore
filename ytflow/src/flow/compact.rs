use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Buffer, FlowError, FlowResult, SizeHint, Stream, StreamReader};

pub struct CompactStream {
    pub inner: Pin<Box<dyn Stream>>,
    pub reader: StreamReader,
}

pub struct CompactFlow<S> {
    pub inner: S,
    pub rx_buf: Option<(Buffer, usize)>,
    pub tx_buf: Option<(Buffer, usize)>,
    pub waker: Option<Waker>,
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

impl<S: AsyncWrite + Unpin> CompactFlow<S> {
    fn poll_try_write(&mut self) -> Poll<()> {
        let Self {
            tx_buf: tx_buf_opt,
            inner,
            waker,
            ..
        } = &mut *self;
        let (tx_buf, offset) = match tx_buf_opt {
            Some(buf) => buf,
            None => return Poll::Ready(()),
        };
        if let Some(waker) = waker.as_ref() {
            let mut cx = Context::from_waker(waker);
            while *offset < tx_buf.len() {
                let poll_res = Pin::new(&mut *inner).poll_write(&mut cx, &tx_buf[*offset..]);
                match poll_res {
                    Poll::Ready(Ok(written)) => *offset += written,
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        Poll::Ready(())
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
        let inner = self.inner.as_mut();
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

impl<S: AsyncRead + AsyncWrite + Send + Sync + Unpin> Stream for CompactFlow<S> {
    // Read
    fn poll_request_size(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        Poll::Ready(Ok(SizeHint::Unknown { overhead: 0 }))
    }
    fn commit_rx_buffer(
        mut self: Pin<&mut Self>,
        buffer: Buffer,
        offset: usize,
    ) -> Result<(), (Buffer, FlowError)> {
        self.rx_buf = Some((buffer, offset));
        Ok(())
    }
    fn poll_rx_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        let Self {
            inner,
            rx_buf: rx_buf_opt,
            ..
        } = &mut *self;
        let (rx_buf, offset) = rx_buf_opt.as_mut().unwrap();

        let len = rx_buf.len();
        let mut read_buf = ReadBuf::uninit(rx_buf.spare_capacity_mut());
        unsafe { read_buf.assume_init(len) };
        read_buf.set_filled(*offset);
        if let Err(e) = ready!(Pin::new(inner).poll_read(cx, &mut read_buf)) {
            return Poll::Ready(Err((rx_buf_opt.take().unwrap().0, e.into())));
        }

        let filled = read_buf.filled().len();
        let (mut rx_buf, offset) = rx_buf_opt.take().unwrap();
        if filled == offset {
            Poll::Ready(Err((rx_buf, FlowError::Eof)))
        } else {
            rx_buf.truncate(filled);
            Poll::Ready(Ok(rx_buf))
        }
    }

    // Write
    fn poll_tx_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<(Buffer, usize)>> {
        if self
            .waker
            .as_ref()
            .filter(|w| cx.waker().will_wake(w))
            .is_none()
        {
            self.waker = Some(cx.waker().clone());
        }
        let Self {
            tx_buf: tx_buf_opt,
            inner,
            ..
        } = &mut *self;
        let (tx_buf, offset) = tx_buf_opt.as_mut().expect("CompactFlow: tx_buf not set");
        while *offset < tx_buf.len() {
            let written = ready!(Pin::new(&mut *inner).poll_write(cx, &tx_buf[*offset..]))?;
            *offset += written;
        }
        tx_buf.resize(size.get(), 0);
        Poll::Ready(Ok((tx_buf_opt.take().unwrap().0, 0)))
    }
    fn commit_tx_buffer(mut self: Pin<&mut Self>, buffer: Buffer) -> FlowResult<()> {
        self.tx_buf = Some((buffer, 0));
        let _ = self.poll_try_write();
        Ok(())
    }

    fn poll_close_tx(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        let Self { tx_buf, inner, .. } = &mut *self;
        if let Some((tx_buf, offset)) = tx_buf.as_mut() {
            while *offset < tx_buf.len() {
                let written =
                    ready!(Pin::new(&mut *inner).poll_write(&mut *cx, &tx_buf[*offset..]))?;
                *offset += written;
            }
        }

        ready!(Pin::new(inner).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}
