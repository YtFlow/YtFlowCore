use std::task::{Context, Poll};

use futures::{future::poll_fn, ready};

use super::*;

pub enum StreamReader {
    PollSizeHint(Buffer, usize),
    PollBuffer(usize),
}

impl StreamReader {
    pub fn new(capacity: usize) -> Self {
        StreamReader::PollSizeHint(Vec::with_capacity(capacity), 0)
    }

    pub fn advance(&mut self, len: usize) {
        match self {
            StreamReader::PollSizeHint(buf, offset) => {
                let new_offset = *offset + len;
                let remaining = buf.len() - new_offset;
                // Move at most 1024 bytes to the front
                // FIXME: is 1024 a good threshold?
                if remaining < 1024 {
                    buf.drain(..new_offset);
                    *offset = remaining;
                } else {
                    *offset = new_offset;
                }
            }
            StreamReader::PollBuffer(offset) => *offset += len,
        }
    }

    fn poll_core<T, C: FnOnce(&mut [u8]) -> T>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut dyn Stream,
        len: usize,
        on_data: C,
    ) -> Poll<FlowResult<T>> {
        loop {
            match self {
                StreamReader::PollSizeHint(buf, offset) => {
                    if buf.len() - *offset >= len {
                        return Poll::Ready(Ok(on_data(&mut buf[*offset..])));
                    }

                    let size_hint = ready!(stream.poll_request_size(cx))?.with_min_content(4096);
                    let mut buf = std::mem::replace(buf, Vec::new());
                    buf.reserve(size_hint);
                    if let Err((b, e)) = stream.commit_rx_buffer(buf) {
                        *self = StreamReader::PollSizeHint(b, 0);
                        return Poll::Ready(Err(e));
                    };
                    *self = StreamReader::PollBuffer(*offset);
                }
                StreamReader::PollBuffer(offset) => match ready!(stream.poll_rx_buffer(cx)) {
                    Ok(buf) => *self = StreamReader::PollSizeHint(buf, *offset),
                    Err((buf, e)) => {
                        *self = StreamReader::PollSizeHint(buf, 0);
                        return Poll::Ready(Err(e));
                    }
                },
            }
        }
    }

    pub fn poll_peek_at_least<T, C: FnOnce(&mut [u8]) -> T>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut dyn Stream,
        len: usize,
        on_data: C,
    ) -> Poll<FlowResult<T>> {
        self.poll_core(cx, stream, len, |buf| on_data(&mut *buf))
    }

    pub fn poll_read_exact<T, C: FnOnce(&mut [u8]) -> T>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut dyn Stream,
        len: usize,
        on_data: C,
    ) -> Poll<FlowResult<T>> {
        let res = self.poll_core(cx, stream, len, |buf| on_data(&mut buf[..len]));
        if let Poll::Ready(Ok(_)) = &res {
            self.advance(len);
        }
        res
    }

    pub async fn peek_at_least<T, C: FnOnce(&mut [u8]) -> T>(
        &mut self,
        stream: &mut dyn Stream,
        len: usize,
        on_data: C,
    ) -> FlowResult<T> {
        let mut on_data = Some(on_data);
        poll_fn(|cx| self.poll_peek_at_least(cx, stream, len, |b| on_data.take().unwrap()(b))).await
    }

    pub async fn read_exact<T, C: FnOnce(&mut [u8]) -> T>(
        &mut self,
        stream: &mut dyn Stream,
        len: usize,
        on_data: C,
    ) -> FlowResult<T> {
        let mut on_data = Some(on_data);
        poll_fn(|cx| self.poll_read_exact(cx, stream, len, |b| on_data.take().unwrap()(b))).await
    }
}
