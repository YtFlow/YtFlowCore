mod datagram;
mod stream;
mod tcp_socket_entry;

use std::collections::btree_map::{BTreeMap, Entry};
use std::future::Future;
use std::mem::ManuallyDrop;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

use flume::{bounded, Sender, TrySendError};
use parking_lot::{const_fair_mutex, FairMutex, FairMutexGuard};
use smoltcp::iface::{Interface, InterfaceBuilder, Route, Routes};
use smoltcp::phy::{Checksum, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::{SocketSet, TcpSocket};
use smoltcp::storage::RingBuffer;
use smoltcp::wire::{
    IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket,
};
use tokio::time::{interval, sleep_until};

use crate::flow::*;
use crate::log::debug_log;

// The 'static lifetime is used to workaround the restrictions on the lifetime of Device.
// The user should register RX packets before calling any receive operations.
// We must ensure every receive operation does not access invalidated buffers.
type RxBuf = Option<&'static mut [u8]>;

struct Device<P>(RxBuf, P);

impl<'d, P: IpTxBuf> smoltcp::phy::Device<'d> for Device<P> {
    type RxToken = RxToken;
    type TxToken = TxToken<'d, P>;
    fn receive(&'d mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let Self(rx_buf, p) = self;
        rx_buf.take().map(move |r| (RxToken(r), TxToken(p)))
    }
    fn transmit(&'d mut self) -> Option<Self::TxToken> {
        Some(TxToken(&mut self.1))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut checksum = ChecksumCapabilities::default();
        checksum.tcp = Checksum::Tx;
        checksum.udp = Checksum::Tx;
        checksum.ipv4 = Checksum::Tx;
        checksum.icmpv4 = Checksum::Tx;
        let mut dev = DeviceCapabilities::default();
        dev.medium = Medium::Ip;
        dev.max_transmission_unit = 1500;
        dev.checksum = checksum;
        dev
    }
}

struct RxToken(&'static mut [u8]);
impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, _timestamp: smoltcp::time::Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(self.0)
    }
}

pub trait IpTxBuf: 'static + Send {
    type Buf: AsRef<[u8]> + AsMut<[u8]>;
    fn request(&mut self, len: usize) -> Self::Buf;
    fn send(&mut self, buf: Self::Buf);
}

struct TxToken<'d, P: 'static>(&'d mut P);
impl<'d, P: IpTxBuf> smoltcp::phy::TxToken for TxToken<'d, P> {
    fn consume<R, F>(
        self,
        _timestamp: smoltcp::time::Instant,
        len: usize,
        f: F,
    ) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buf = self.0.request(len);
        let res = f(buf.as_mut());
        self.0.send(buf);
        res
    }
}

pub struct IpStack<P: IpTxBuf> {
    inner: Arc<FairMutex<IpStackInner<P>>>,
    flow_manager: Arc<Manager>,
    tcp_next: Weak<dyn StreamHandler>,
    udp_next: Weak<dyn DatagramSessionHandler>,
}

struct IpStackInner<P: IpTxBuf> {
    netif: Interface<'static, Device<P>>,
    // TODO: (router) also record src ip
    tcp_sockets: BTreeMap<u16, SocketSet<'static>>,
    udp_sockets: BTreeMap<u16, Sender<(DestinationAddr, Buffer)>>,
}

impl<P: IpTxBuf> IpStack<P> {
    pub fn new(r: Arc<Manager>, p: P) -> Self {
        let netif = InterfaceBuilder::new(Device(None, p))
            .ip_addrs(vec![IpCidr::new(
                Ipv4Address::new(192, 168, 3, 1).into(),
                0,
            )])
            .any_ip(true)
            .routes(Routes::new(
                // TODO: replace with into_iter in Rust Edition 2021
                std::array::IntoIter::new([(
                    IpCidr::new(Ipv4Address::UNSPECIFIED.into(), 0),
                    // TODO: Custom IP Address
                    Route::new_ipv4_gateway(Ipv4Address::new(192, 168, 3, 1)),
                )])
                .collect::<BTreeMap<_, _>>(),
            ))
            .finalize();
        let mut resolver_opt = None;
        let sock_outbound = Arc::new_cyclic(|sock_outbound| {
            let redir_factory = Arc::new(crate::plugin::redirect::DatagramSessionRedirectFactory {
                remote_peer: || DestinationAddr {
                    dest: Destination::Ip([192, 168, 0, 1].into()),
                    port: 53,
                },
                next: sock_outbound.clone() as _,
            }) as _;
            std::mem::forget(Arc::clone(&redir_factory));
            let resolver = Arc::new(crate::plugin::fakeip::FakeIp::new(
                [11, 17],
                [0x26, 0x0c, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ));
            let resolver2 = Arc::clone(&resolver);
            r.rt.spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_millis(3000)).await;
                let res = resolver2
                    .resolve_ipv4(String::from("www.baidu.com"))
                    .await
                    .unwrap();
                crate::log::debug_log(format!("{:?}", res));
            });
            std::mem::forget(Arc::clone(&resolver));
            resolver_opt = Some(Arc::downgrade(&resolver));
            crate::plugin::socket::SocketOutboundFactory {
                resolver: Arc::downgrade(&resolver) as _,
                netif_selector: crate::plugin::netif::NetifSelector::new(
                    crate::plugin::netif::SelectionMode::Auto,
                    crate::plugin::netif::FamilyPreference::PreferIpv4,
                )
                .unwrap(),
            }
        });
        let tcp_outbound = Arc::downgrade(&sock_outbound) as _;
        let udp_outbound = Arc::downgrade(&sock_outbound) as _;
        std::mem::forget(sock_outbound);
        let resolver = resolver_opt.unwrap();
        IpStack {
            inner: Arc::new(const_fair_mutex(IpStackInner {
                netif,
                tcp_sockets: BTreeMap::new(),
                udp_sockets: BTreeMap::new(),
            })),
            flow_manager: r,
            tcp_next: {
                let redirect_outbound =
                    Arc::new(crate::plugin::redirect::StreamRedirectOutboundFactory {
                        remote_peer: || DestinationAddr {
                            dest: Destination::Ip([127, 0, 0, 1].into()),
                            port: 8388,
                        },
                        next: Weak::clone(&tcp_outbound),
                    }) as _;
                let ss_outbound = crate::plugin::shadowsocks::create_factory(
                    "xchacha20-ietf-poly1305",
                    "biubiubiu",
                    Arc::downgrade(&redirect_outbound),
                )
                .unwrap();
                let forward_handler = Arc::new(crate::plugin::forward::StreamForwardHandler {
                    outbound: tcp_outbound.clone(),
                }) as _;
                let reverse_handler =
                    Arc::new(crate::plugin::resolve_dest::StreamReverseResolver {
                        resolver: resolver.clone(),
                        next: Arc::downgrade(&forward_handler),
                    });
                let ret = Arc::downgrade(&reverse_handler);
                std::mem::forget(forward_handler);
                std::mem::forget(ss_outbound);
                std::mem::forget(redirect_outbound);
                std::mem::forget(reverse_handler);
                ret
            },
            udp_next: {
                let forward_handler = Arc::new(crate::plugin::forward::DatagramForwardHandler {
                    outbound: udp_outbound,
                });
                let dns_handler = Arc::new(crate::plugin::dns_server::DnsDatagramHandler::new(
                    16,
                    resolver.clone(),
                    10,
                )) as _;
                let ret = Arc::downgrade(&dns_handler);
                std::mem::forget(forward_handler);
                std::mem::forget(dns_handler);
                ret
            },
        }
    }

    pub fn push_ip_packets(&self, packets: impl Iterator<Item = &'static mut [u8]>) {
        struct NetifGuard<'a, P: IpTxBuf>(FairMutexGuard<'a, IpStackInner<P>>);
        impl<'a, P: IpTxBuf> Drop for NetifGuard<'a, P> {
            fn drop(&mut self) {
                self.0.netif.device_mut().0 = None;
            }
        }
        let Self {
            inner,
            flow_manager,
            ..
        } = self;
        let mut netif_guard = NetifGuard(inner.lock());

        #[inline]
        fn process_tcp<P: IpTxBuf>(
            stack: &IpStack<P>,
            guard: &mut NetifGuard<'_, P>,
            src_addr: IpAddr,
            dst_addr: smoltcp::wire::IpAddress,
            src_port: u16,
            dst_port: u16,
            is_syn: bool,
            packet: &'static mut [u8],
        ) {
            let IpStackInner {
                netif,
                tcp_sockets,
                udp_sockets,
            } = &mut *guard.0;

            let dev = netif.device_mut();
            dev.0 = Some(packet);

            let tcp_socket_count = tcp_sockets.len();
            let set = match tcp_sockets.entry(src_port) {
                Entry::Occupied(ent) => ent.into_mut(),
                Entry::Vacant(_) if !is_syn || tcp_socket_count >= 1 << 10 => return,
                Entry::Vacant(vac) => {
                    let next = match stack.tcp_next.upgrade() {
                        Some(n) => n,
                        None => return,
                    };
                    let mut socket = TcpSocket::new(
                        // Note: The buffer sizes effectively affect overall throughput.
                        RingBuffer::new(vec![0; 1024 * 14]),
                        RingBuffer::new(vec![0; 10240]),
                    );
                    socket
                        .listen(IpEndpoint::new(dst_addr.into(), dst_port))
                        // This unwrap cannot panic for a valid TCP packet because:
                        // 1) The socket is just created
                        // 2) dst_port != 0
                        .unwrap();
                    socket.set_nagle_enabled(false);
                    // The default ACK delay (10ms) significantly reduces uplink throughput.
                    // Maybe due to the delay when sending ACK packets?
                    socket.set_ack_delay(None);
                    let mut set = SocketSet::new([None]);
                    let socket_handle = set.add(socket);
                    let ctx = FlowContext {
                        local_peer: SocketAddr::new(src_addr, src_port).into(),
                        remote_peer: DestinationAddr {
                            dest: Destination::Ip(smoltcp_addr_to_std(dst_addr.into())),
                            port: dst_port,
                        },
                    };
                    let set = vac.insert(set);
                    stack.flow_manager.rt.spawn({
                        let stack = stack.inner.clone();
                        async move {
                            let mut stream = stream::IpStackStream {
                                socket_entry: tcp_socket_entry::TcpSocketEntry {
                                    socket_handle,
                                    stack,
                                    local_port: src_port,
                                    most_recent_scheduled_poll: Arc::new(AtomicI64::new(i64::MAX)),
                                },
                                rx_buf: None,
                                tx_buf: Some((vec![0; 4 * 1024], 4 * 1024)),
                            };
                            if stream.handshake().await.is_ok() {
                                next.on_stream(Box::pin(stream) as _, Box::new(ctx));
                            }
                        }
                    });
                    set
                }
            };
            let now = Instant::now();
            let _ = netif.poll(set, now.into());
            // Polling the socket may wake a read/write waker. When a task polls the tx/rx
            // buffer from the corresponding stream, a delayed poll will be rescheduled.
            // Therefore, we don't have to poll the socket here.
        }

        #[inline]
        fn process_udp<P: IpTxBuf>(
            stack: &IpStack<P>,
            guard: &mut NetifGuard<'_, P>,
            src_addr: IpAddr,
            dst_addr: smoltcp::wire::IpAddress,
            src_port: u16,
            dst_port: u16,
            payload: &mut [u8],
        ) {
            let tx = match guard.0.udp_sockets.entry(src_port) {
                Entry::Occupied(ent) => ent.into_mut(),
                Entry::Vacant(vac) => {
                    let next = match stack.udp_next.upgrade() {
                        Some(next) => next,
                        None => return,
                    };
                    let (tx, rx) = bounded(48);
                    let stack_inner = stack.inner.clone();
                    let manager = stack.flow_manager.clone();
                    stack.flow_manager.rt.spawn(async move {
                        next.on_session(
                            Box::pin(datagram::IpStackDatagramSession {
                                stack: stack_inner,
                                local_endpoint: src_addr.into(),
                                local_port: src_port,
                                rx: Some(rx.into_stream()),
                                has_io_within_tick: true,
                                timer: ManuallyDrop::new(interval(
                                    tokio::time::Duration::from_secs(120),
                                )),
                            }),
                            Box::new(FlowContext {
                                local_peer: SocketAddr::new(src_addr, src_port),
                                remote_peer: DestinationAddr {
                                    dest: Destination::Ip(smoltcp_addr_to_std(dst_addr.into())),
                                    port: dst_port,
                                },
                            }),
                        );
                    });
                    vac.insert(tx)
                }
            };
            if let Err(TrySendError::Disconnected(_)) = tx.try_send((
                DestinationAddr {
                    dest: Destination::Ip(smoltcp_addr_to_std(dst_addr.into())),
                    port: dst_port,
                },
                payload.to_vec(),
            )) {
                guard.0.udp_sockets.remove(&src_port);
            }
            // Drop packet when buffer is full
        }

        for packet in packets {
            if packet.len() < 20 {
                continue;
            }
            match packet[0] >> 4 {
                0b0100 => {
                    let mut ipv4_packet = match Ipv4Packet::new_checked(packet) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let (src_addr, dst_addr) = (ipv4_packet.src_addr(), ipv4_packet.dst_addr());
                    match ipv4_packet.protocol() {
                        IpProtocol::Tcp => {
                            let p = match TcpPacket::new_checked(ipv4_packet.payload_mut()) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            let (src_port, dst_port, is_syn) =
                                (p.src_port(), p.dst_port(), p.syn());
                            process_tcp(
                                self,
                                &mut netif_guard,
                                smoltcp_addr_to_std(src_addr.into()),
                                dst_addr.into(),
                                src_port,
                                dst_port,
                                is_syn,
                                ipv4_packet.into_inner(),
                            );
                        }
                        IpProtocol::Udp => {
                            let mut p = match UdpPacket::new_checked(ipv4_packet.payload_mut()) {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            let (src_port, dst_port) = (p.src_port(), p.dst_port());
                            process_udp(
                                self,
                                &mut netif_guard,
                                smoltcp_addr_to_std(src_addr.into()),
                                dst_addr.into(),
                                src_port,
                                dst_port,
                                p.payload_mut(),
                            );
                        }
                        _ => continue,
                    }
                }
                0b0110 => {
                    // TODO: IPv6
                    continue;
                }
                _ => continue,
            };
        }
    }
}

fn schedule_repoll<P: IpTxBuf>(
    stack: Arc<FairMutex<IpStackInner<P>>>,
    local_port: u16,
    poll_at: Instant,
    most_recent_scheduled_poll: Arc<AtomicI64>,
) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
    debug_log(format!("Scheduled repoll: {:?}", poll_at));
    let stack_cloned = stack.clone();
    Box::pin(async move {
        sleep_until(tokio::time::Instant::from_std(poll_at.into())).await;
        if smoltcp::time::Instant::from(Instant::now()).total_millis()
            > most_recent_scheduled_poll.load(Ordering::Relaxed)
        {
            // A more urgent poll was scheduled.
            return;
        }
        let mut stack_guard = stack.lock();
        let IpStackInner {
            netif, tcp_sockets, ..
        } = &mut *stack_guard;
        let set = match tcp_sockets.get_mut(&local_port) {
            Some(s) => s,
            None => return,
        };
        let _ = netif.poll(set, poll_at.into());
        if let Some(delay) = netif.poll_delay(set, poll_at.into()) {
            let scheduled_poll_milli =
                (smoltcp::time::Instant::from(Instant::now()) + delay).total_millis();
            if scheduled_poll_milli >= most_recent_scheduled_poll.load(Ordering::Relaxed).into() {
                return;
            }
            // TODO: CAS spin loop
            most_recent_scheduled_poll.store(scheduled_poll_milli, Ordering::Relaxed);

            tokio::spawn(schedule_repoll(
                stack_cloned,
                local_port,
                poll_at + delay.into(),
                most_recent_scheduled_poll,
            ));
        }
    }) as _
}

fn smoltcp_addr_to_std(addr: IpAddress) -> IpAddr {
    match addr {
        IpAddress::Ipv4(ip) => IpAddr::V4(ip.into()),
        IpAddress::Ipv6(ip) => IpAddr::V6(ip.into()),
        _ => panic!("Cannot convert unknown smoltcp address to std address"),
    }
}
