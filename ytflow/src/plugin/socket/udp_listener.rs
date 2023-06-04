use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Weak};
use std::task::{ready, Context, Poll};

use flume::{bounded, SendError};

use crate::flow::*;

pub fn listen_udp(
    next: Weak<dyn DatagramSessionHandler>,
    addr: impl ToSocketAddrs + Send + 'static,
) -> io::Result<tokio::task::JoinHandle<()>> {
    let mut session_map = BTreeMap::new();
    let listener = std::net::UdpSocket::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(tokio::spawn(async move {
        let listener = Arc::new(
            tokio::net::UdpSocket::from_std(listener)
                .expect("Calling listen_udp when runtime is not set"),
        );
        let listen_addr: DestinationAddr = match listener.local_addr() {
            Ok(addr) => addr,
            // TODO: log error
            Err(_) => return,
        }
        .into();
        let mut buf = [0u8; 4096];
        loop {
            let (size, from) = match listener.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => {
                    // TODO: log error
                    break;
                }
            };
            let tx = session_map.entry(from).or_insert_with(|| {
                let (tx, rx) = bounded(64);
                if let Some(next) = next.upgrade() {
                    next.on_session(
                        Box::new(MultiplexedDatagramSessionAdapter::new(
                            InboundUdpSession {
                                socket: listener.clone(),
                                tx_buf: None,
                            },
                            rx.into_stream(),
                            120,
                        )),
                        Box::new(FlowContext::new_af_sensitive(from, listen_addr.clone())),
                    );
                }
                tx
            });
            if let Err(SendError(_)) = tx
                .send_async((listen_addr.clone(), buf[..size].to_vec()))
                .await
            {
                session_map.remove(&from);
            }
        }
    }))
}

struct InboundUdpSession {
    socket: Arc<tokio::net::UdpSocket>,
    tx_buf: Option<(SocketAddr, Buffer)>,
}

impl MultiplexedDatagramSession for InboundUdpSession {
    fn on_close(&mut self) {}

    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let _ = ready!(self.socket.poll_send_ready(cx)).ok();
        if let Some((addr, buf)) = &mut self.tx_buf {
            let _ = ready!(self.socket.poll_send_to(cx, buf, *addr));
            self.tx_buf = None;
        }
        Poll::Ready(())
    }

    fn send_to(&mut self, src: DestinationAddr, buf: Buffer) {
        let HostName::Ip(ip) = &src.host else { return; };
        self.tx_buf = Some((SocketAddr::new(*ip, src.port), buf));
    }
}
