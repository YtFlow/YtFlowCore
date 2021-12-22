use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::task::{Context, Poll};

use flume::r#async::RecvStream;
use futures::{ready, Stream};
use tokio::time::{interval, Interval};

use super::{Buffer, DatagramSession, DestinationAddr, FlowResult};

pub trait MultiplexedDatagramSession: Send + Sync {
    fn on_close(&mut self);
    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()>;
    fn send_to(&mut self, src: DestinationAddr, buf: Buffer);
}

type MultiplexedDatagramRx = RecvStream<'static, (DestinationAddr, Buffer)>;

pub struct MultiplexedDatagramSessionAdapter<S: MultiplexedDatagramSession> {
    inner: S,
    rx: Option<MultiplexedDatagramRx>,
    has_io_within_tick: bool,
    timer: ManuallyDrop<Interval>,
}

impl<S: MultiplexedDatagramSession> Drop for MultiplexedDatagramSessionAdapter<S> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<S: MultiplexedDatagramSession> MultiplexedDatagramSessionAdapter<S> {
    pub fn new(inner: S, rx: MultiplexedDatagramRx, timeout: u64) -> Self {
        Self {
            inner,
            rx: Some(rx),
            has_io_within_tick: true,
            timer: ManuallyDrop::new(interval(tokio::time::Duration::from_secs(timeout))),
        }
    }

    fn close(&mut self) {
        if let Some(_) = self.rx.take() {
            // Safety: rx is taken out exactly once.
            unsafe { drop(ManuallyDrop::take(&mut self.timer)) };
            self.inner.on_close();
        }
    }
}

impl<S: MultiplexedDatagramSession> DatagramSession for MultiplexedDatagramSessionAdapter<S> {
    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.inner.poll_send_ready(cx)
    }
    fn send_to(&mut self, src: DestinationAddr, buf: Buffer) {
        self.has_io_within_tick = true;
        if self.rx.is_none() {
            // Already closed
            return;
        }
        self.inner.send_to(src, buf);
    }
    fn poll_recv_from(&mut self, cx: &mut Context) -> Poll<Option<(DestinationAddr, Buffer)>> {
        let rx = Pin::new(match self.rx.as_mut() {
            Some(rx) => rx,
            None => return Poll::Ready(None),
        });
        match rx.poll_next(cx) {
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some((dst, buf))) => {
                self.has_io_within_tick = true;
                Poll::Ready(Some((dst, buf)))
            }
            Poll::Pending => {
                ready!(self.timer.poll_tick(cx));
                // Time is up at this point
                if std::mem::replace(&mut self.has_io_within_tick, false) {
                    Poll::Pending
                } else {
                    self.close();
                    Poll::Ready(None)
                }
            }
        }
    }
    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.poll_send_ready(cx).map(|()| Ok(()))
    }
}
