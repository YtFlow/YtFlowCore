use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;

use super::{Buffer, FlowError, FlowResult, SizeHint, Stream, StreamReader};

pub struct CompactStream {
    pub inner: Pin<Box<dyn Stream>>,
    pub reader: StreamReader,
}

enum CompactFlowTxState<S> {
    Writing(JoinHandle<(Buffer, WriteHalf<S>, Option<io::Error>)>),
    NoBuffer(WriteHalf<S>, Waker),
}

pub struct CompactFlow<S> {
    pub rx_inner: ReadHalf<S>,
    pub rx_buf: Option<(Buffer, usize)>,
    tx_buf: CompactFlowTxState<S>,
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

fn poll_join_handle<T>(handle: &mut JoinHandle<T>, cx: &mut Context<'_>) -> Poll<T> {
    match ready!(Pin::new(handle).poll(cx)).map_err(|e| e.try_into_panic()) {
        Ok(r) => Poll::Ready(r),
        Err(Ok(e)) => std::panic::resume_unwind(e),
        Err(Err(_)) => panic!("A CompactFlow write has been expectedly aborted"),
    }
}

impl<S: AsyncRead + AsyncWrite + Send + 'static> CompactFlow<S> {
    pub fn new(inner: S, tx_buf_size: usize) -> Self {
        let (rx, tx) = tokio::io::split(inner);
        Self {
            rx_inner: rx,
            rx_buf: None,
            tx_buf: CompactFlowTxState::Writing(tokio::spawn(async move {
                (vec![0; tx_buf_size], tx, None)
            })),
        }
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

impl<S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static> Stream for CompactFlow<S> {
    // Read
    fn poll_request_size(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<FlowResult<SizeHint>> {
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
            rx_inner: inner,
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
        let (mut buf, tx) = match &mut self.tx_buf {
            CompactFlowTxState::NoBuffer(_, _) => {
                panic!("Polling CompactFlow without previous buffer committed")
            }
            CompactFlowTxState::Writing(handle) => {
                let (buf, tx, e) = ready!(poll_join_handle(handle, cx));
                if let Some(e) = e {
                    return Poll::Ready(Err(e.into()));
                }
                (buf, tx)
            }
        };
        self.tx_buf = CompactFlowTxState::NoBuffer(tx, cx.waker().clone());
        buf.clear();
        buf.resize(size.get(), 0);
        Poll::Ready(Ok((buf, 0)))
    }
    fn commit_tx_buffer(mut self: Pin<&mut Self>, buffer: Buffer) -> FlowResult<()> {
        let mut offset = 0;
        loop {
            match &mut self.tx_buf {
                CompactFlowTxState::NoBuffer(tx, waker) => {
                    if buffer.len() == offset {
                        break;
                    }
                    match Pin::new(tx)
                        .poll_write(&mut Context::from_waker(&waker), &buffer[offset..])
                    {
                        Poll::Ready(Ok(written)) => {
                            offset += written;
                        }
                        Poll::Ready(Err(e)) => return Err(e.into()),
                        Poll::Pending => break,
                    }
                }
                CompactFlowTxState::Writing(_) => {
                    panic!("Cannot commit tx buffer when an inflight write is not ready")
                }
            }
        }
        // We have to use a spawn here because we have no access to a waker
        // that guarantees to wake up the same task to continue writing.
        replace_with::replace_with_or_abort(&mut self.tx_buf, move |tx| match tx {
            CompactFlowTxState::NoBuffer(mut tx, waker) => {
                CompactFlowTxState::Writing(tokio::spawn(async move {
                    let mut e = None;
                    if offset < buffer.len() {
                        if let Err(err) = tx.write_all(&buffer[offset..]).await {
                            e = Some(err);
                        }
                    }
                    (buffer, tx, e)
                }))
            }
            CompactFlowTxState::Writing(_) => {
                unreachable!("CompactFlowTxState has been checked not to hold a task")
            }
        });
        Ok(())
    }

    fn poll_close_tx(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        // if let CompactFlowTxState::Writing(handle) = &mut self.tx_buf {
        match &mut self.tx_buf {
            CompactFlowTxState::Writing(handle) => {
                let (buf, mut tx, e) = ready!(poll_join_handle(handle, cx));
                if let Some(e) = e {
                    return Poll::Ready(Err(e.into()));
                }
                let res = Pin::new(&mut tx).poll_flush(cx);
                self.tx_buf = CompactFlowTxState::NoBuffer(tx, cx.waker().clone());
                res
            }
            CompactFlowTxState::NoBuffer(tx, _) => Pin::new(tx).poll_flush(cx),
        }
        .map(|r| r.map_err(Into::into))
    }
}
