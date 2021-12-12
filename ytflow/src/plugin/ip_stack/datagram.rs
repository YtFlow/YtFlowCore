use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use flume::r#async::RecvStream;
use futures::{ready, Stream};
use tokio::time::Interval;

use super::*;
use crate::flow::*;

pub(super) struct IpStackDatagramSession {
    pub(super) stack: Arc<FairMutex<IpStackInner>>,
    pub(super) local_endpoint: IpAddress,
    pub(super) local_port: u16,
    pub(super) rx: Option<RecvStream<'static, (DestinationAddr, Buffer)>>,
    pub(super) has_io_within_tick: bool,
    pub(super) timer: ManuallyDrop<Interval>,
}

impl IpStackDatagramSession {
    fn close(&mut self) {
        if let Some(_) = self.rx.take() {
            // Safety: SocketEntry is taken out exactly once.
            unsafe { drop(ManuallyDrop::take(&mut self.timer)) };
            let mut stack_guard = self.stack.lock();
            stack_guard.udp_sockets.remove(&self.local_port);
        }
    }
}

impl DatagramSession for IpStackDatagramSession {
    fn poll_send_ready(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
    fn send_to(&mut self, src: DestinationAddr, buf: Buffer) {
        self.has_io_within_tick = true;
        let payload_len: u16 = match buf.len().try_into().ok().filter(|&l| l <= 1500 - 48) {
            Some(l) => l,
            // Ignore oversized packet
            None => return,
        };
        let _from_ip = match &src.dest {
            Destination::Ip(ip) => ip,
            // TODO: print diagnostic message: Cannot send datagram to unresolved destination
            _ => return,
        };
        if self.rx.is_none() {
            // Already closed
            return;
        }
        let mut stack_guard = self.stack.lock();
        use smoltcp::phy::{Device, TxToken};
        let sender = stack_guard.netif.device_mut().transmit();
        let ip_buf = match sender {
            Some(b) => b,
            None => return,
        };
        match (&self.local_endpoint, &src.dest) {
            (IpAddress::Ipv4(dst_v4), Destination::Ip(IpAddr::V4(src_ip))) => {
                let src_ip: Ipv4Address = src_ip.clone().into();
                let _ = ip_buf.consume(
                    smoltcp::time::Instant::from_micros_const(0),
                    buf.len() + 48,
                    |ip_buf| {
                        let mut ip_packet = Ipv4Packet::new_unchecked(ip_buf);
                        ip_packet.set_version(4);
                        ip_packet.set_header_len(20);
                        ip_packet.set_total_len(20 + 8 + payload_len);
                        ip_packet.set_dont_frag(true);
                        ip_packet.set_hop_limit(255);
                        ip_packet.set_protocol(IpProtocol::Udp);
                        ip_packet.set_dst_addr(dst_v4.clone());
                        ip_packet.set_src_addr(src_ip.clone());
                        let mut udp_packet = UdpPacket::new_unchecked(ip_packet.payload_mut());
                        udp_packet.set_dst_port(self.local_port);
                        udp_packet.set_src_port(src.port);
                        udp_packet.set_len(8 + payload_len);
                        udp_packet.payload_mut()[..buf.len()].copy_from_slice(&buf);
                        udp_packet.fill_checksum(&src_ip.into(), &dst_v4.clone().into());
                        ip_packet.fill_checksum();
                        Ok(())
                    },
                );
            }
            (IpAddress::Ipv6(_dst_v6), _) => todo!(),
            // Ignore unmatched IP version
            _ => return,
        }
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
    fn poll_shutdown(&mut self, _cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for IpStackDatagramSession {
    fn drop(&mut self) {
        self.close();
    }
}
