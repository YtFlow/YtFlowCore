use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::FairMutex;
use smoltcp::socket::{SocketHandle, TcpSocket};

use super::*;

pub(super) struct TcpSocketEntry {
    pub(super) socket_handle: SocketHandle,
    pub(super) local_port: u16,
    pub(super) stack: Arc<FairMutex<IpStackInner>>,
    pub(super) most_recent_scheduled_poll: Arc<AtomicI64>,
}

impl TcpSocketEntry {
    pub fn lock(&self) -> SocketEntryGuard<'_> {
        SocketEntryGuard {
            entry: self,
            guard: self.stack.lock(),
        }
    }
}

pub(super) struct SocketEntryGuard<'s> {
    pub(super) entry: &'s TcpSocketEntry,
    pub(super) guard: FairMutexGuard<'s, IpStackInner>,
}

impl<'s> SocketEntryGuard<'s> {
    pub fn with_socket<R>(&mut self, f: impl FnOnce(&mut TcpSocket) -> R) -> R {
        let TcpSocketEntry {
            local_port,
            socket_handle,
            ..
        } = self.entry;
        let set = self.guard.tcp_sockets.get_mut(local_port).unwrap();
        let mut socket = set.get::<TcpSocket<'static>>(*socket_handle);
        f(&mut socket)
    }

    pub fn poll(&mut self) {
        let now = Instant::now();
        let Self { entry, guard } = self;
        let TcpSocketEntry {
            local_port,
            stack,
            most_recent_scheduled_poll,
            ..
        } = entry;
        let IpStackInner {
            netif, tcp_sockets, ..
        } = &mut **guard;
        let set = tcp_sockets.get_mut(local_port).unwrap();
        let _ = netif.poll(set, now.into());
        if let Some(delay) = netif.poll_delay(set, now.into()) {
            let scheduled_poll_milli = (smoltcp::time::Instant::from(now) + delay).total_millis();
            if scheduled_poll_milli >= most_recent_scheduled_poll.load(Ordering::Relaxed).into() {
                return;
            }
            // TODO: CAS spin loop
            most_recent_scheduled_poll.store(scheduled_poll_milli, Ordering::Relaxed);

            tokio::spawn(schedule_repoll(
                stack.clone(),
                *local_port,
                now + delay.into(),
                Arc::clone(most_recent_scheduled_poll),
            ));
        }
    }
}
