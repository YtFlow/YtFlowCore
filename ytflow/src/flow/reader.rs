use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{future::poll_fn, ready};

use super::*;

pub enum StreamReader {
    PollSizeHint(Buffer),
    PollBuffer,
}

impl StreamReader {
    pub fn new() -> Self {
        StreamReader::PollSizeHint(Vec::with_capacity(4096))
    }

    pub fn buf_mut(&mut self) -> Option<&mut Buffer> {
        match self {
            StreamReader::PollSizeHint(buf) => Some(buf),
            _ => None,
        }
    }

    fn poll_core<T, C: FnOnce(&mut Buffer) -> T>(
        &mut self,
        cx: &mut Context<'_>,
        mut stream: Pin<&mut dyn Stream>,
        len: usize,
        on_data: C,
    ) -> Poll<FlowResult<T>> {
        loop {
            match self {
                StreamReader::PollSizeHint(buf) => {
                    if buf.len() >= len {
                        return Poll::Ready(Ok(on_data(buf)));
                    }
                    let size_hint =
                        ready!(stream.as_mut().poll_request_size(cx))?.with_min_content(4096);
                    let mut buf = std::mem::replace(buf, Vec::new());
                    let already_read = buf.len();
                    buf.resize(already_read + size_hint, 0);
                    if let Err((b, e)) = stream.as_mut().commit_rx_buffer(buf, already_read) {
                        *self = StreamReader::PollSizeHint(b);
                        return Poll::Ready(Err(e));
                    };
                    *self = StreamReader::PollBuffer;
                }
                StreamReader::PollBuffer => match ready!(stream.as_mut().poll_rx_buffer(cx)) {
                    Ok(buf) => *self = StreamReader::PollSizeHint(buf),
                    Err((buf, e)) => {
                        *self = StreamReader::PollSizeHint(buf);
                        return Poll::Ready(Err(e));
                    }
                },
            }
        }
    }

    pub fn poll_peek_at_least<T, C: FnOnce(&mut [u8]) -> T>(
        &mut self,
        cx: &mut Context<'_>,
        mut stream: Pin<&mut dyn Stream>,
        len: usize,
        on_data: C,
    ) -> Poll<FlowResult<T>> {
        self.poll_core(cx, stream, len, |buf| on_data(&mut *buf))
    }

    pub fn poll_read_exact<T, C: FnOnce(&mut [u8]) -> T>(
        &mut self,
        cx: &mut Context<'_>,
        stream: Pin<&mut dyn Stream>,
        len: usize,
        on_data: C,
    ) -> Poll<FlowResult<T>> {
        self.poll_core(cx, stream, len, |buf| {
            let ret = on_data(&mut buf[..len]);
            buf.drain(..len);
            ret
        })
    }

    pub async fn peek_at_least<T, C: FnOnce(&mut [u8]) -> T, P: DerefMut<Target = dyn Stream>>(
        &mut self,
        mut stream: &mut Pin<P>,
        len: usize,
        on_data: C,
    ) -> FlowResult<T> {
        let mut on_data = Some(on_data);
        poll_fn(|cx| {
            self.poll_peek_at_least(cx, stream.as_mut(), len, |b| on_data.take().unwrap()(b))
        })
        .await
    }

    pub async fn read_exact<T, C: FnOnce(&mut [u8]) -> T>(
        &mut self,
        mut stream: Pin<&mut dyn Stream>,
        len: usize,
        on_data: C,
    ) -> FlowResult<T> {
        let mut on_data = Some(on_data);
        poll_fn(|cx| self.poll_read_exact(cx, stream.as_mut(), len, |b| on_data.take().unwrap()(b)))
            .await
    }
}
