use std::sync::atomic::Ordering;
use std::sync::Weak;
use std::task::Poll;

use futures::future::poll_fn;

use super::StatHandle;
use crate::flow::*;

pub struct DatagramForwardHandler {
    pub outbound: Weak<dyn DatagramSessionFactory>,
    pub stat: StatHandle,
}

impl DatagramSessionHandler for DatagramForwardHandler {
    fn on_session(&self, mut session: Box<dyn DatagramSession>, context: Box<FlowContext>) {
        let outbound = match self.outbound.upgrade() {
            Some(o) => o,
            None => return,
        };
        let stat = self.stat.clone();
        tokio::spawn(async move {
            let mut lower = outbound.bind(context).await?;
            struct StatCountGuard(StatHandle);
            impl Drop for StatCountGuard {
                fn drop(&mut self) {
                    self.0
                        .inner
                        .udp_session_count
                        .fetch_sub(1, Ordering::Relaxed);
                }
            }
            let stat = StatCountGuard(stat.clone());
            stat.0
                .inner
                .udp_session_count
                .fetch_add(1, Ordering::Relaxed);
            let mut uplink_buf = None::<(_, Buffer)>;
            let mut downlink_buf = None::<(_, Buffer)>;
            poll_fn(|cx| {
                #[allow(unreachable_code)]
                loop {
                    if let Some((addr, buf)) = uplink_buf.take() {
                        match lower.as_mut().poll_send_ready(cx) {
                            Poll::Ready(()) => {
                                let len = buf.len();
                                lower.as_mut().send_to(addr, buf);
                                stat.0
                                    .inner
                                    .uplink_written
                                    .fetch_add(len as u64, Ordering::Relaxed);
                                continue;
                            }
                            Poll::Pending => uplink_buf = Some((addr, buf)),
                        }
                    } else {
                        let _ = lower.as_mut().poll_send_ready(cx);
                        match session.as_mut().poll_recv_from(cx) {
                            Poll::Ready(b @ Some(_)) => (uplink_buf = b, continue).1,
                            Poll::Ready(None) => return Poll::Ready(()),
                            Poll::Pending => {}
                        }
                    }
                    if let Some((addr, buf)) = downlink_buf.take() {
                        match session.as_mut().poll_send_ready(cx) {
                            Poll::Ready(()) => {
                                let len = buf.len();
                                session.as_mut().send_to(addr, buf);
                                stat.0
                                    .inner
                                    .downlink_written
                                    .fetch_add(len as u64, Ordering::Relaxed);
                                continue;
                            }
                            Poll::Pending => downlink_buf = Some((addr, buf)),
                        }
                    } else {
                        let _ = session.as_mut().poll_send_ready(cx);
                        match lower.as_mut().poll_recv_from(cx) {
                            Poll::Ready(b @ Some(_)) => (downlink_buf = b, continue).1,
                            Poll::Ready(None) => return Poll::Ready(()),
                            Poll::Pending => break,
                        }
                    }
                }
                Poll::Pending
            })
            .await;
            futures::future::try_join(
                poll_fn(|cx| lower.as_mut().poll_shutdown(cx)),
                poll_fn(|cx| session.as_mut().poll_shutdown(cx)),
            )
            .await?;
            FlowResult::Ok(())
        });
    }
}
