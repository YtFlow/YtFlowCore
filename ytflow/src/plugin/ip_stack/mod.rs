mod datagram;
mod stream;
mod tcp_socket_entry;

use std::collections::btree_map::{BTreeMap, Entry};
use std::future::Future;
use std::mem::ManuallyDrop;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use flume::{bounded, Sender, TrySendError};
use smoltcp::iface::{Interface, InterfaceBuilder, Route, Routes, SocketHandle};
use smoltcp::phy::{Checksum, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::TcpSocket;
use smoltcp::storage::RingBuffer;
use smoltcp::wire::{
    IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet,
    TcpPacket, UdpPacket,
};
use tokio::time::sleep_until;

use crate::flow::*;
use crate::log::debug_log;

struct Device {
    tx: Option<TunBufferToken>,
    rx: Option<Buffer>,
    tun: Arc<dyn Tun>,
}

impl<'d> smoltcp::phy::Device<'d> for Device {
    type RxToken = RxToken<'d>;
    type TxToken = TxToken<'d>;
    fn receive(&'d mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let Self { tx, rx, tun } = self;
        rx.as_ref()?;
        if tx.is_none() {
            *tx = Some(tun.get_tx_buffer()?);
        };
        Some((RxToken(rx, &**tun), TxToken(tx, &**tun)))
    }
    fn transmit(&'d mut self) -> Option<Self::TxToken> {
        let Self { tx, tun, .. } = self;
        if tx.is_none() {
            *tx = Some(tun.get_tx_buffer()?);
        };
        Some(TxToken(tx, &**tun))
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

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(rx_buf) = self.rx.take() {
            self.tun.return_recv_buffer(rx_buf);
        }
        if let Some(tx_token) = self.tx.take() {
            self.tun.return_tx_buffer(tx_token);
        }
    }
}

struct RxToken<'d>(&'d mut Option<Buffer>, &'d dyn Tun);
impl<'d> smoltcp::phy::RxToken for RxToken<'d> {
    fn consume<R, F>(self, _timestamp: smoltcp::time::Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let buf = self
            .0
            .take()
            .expect("Consuming a RxToken without tx buffer set");

        struct BufReturnGuard<'d>(ManuallyDrop<Buffer>, &'d dyn Tun);
        impl<'d> Drop for BufReturnGuard<'d> {
            fn drop(&mut self) {
                unsafe {
                    self.1.return_recv_buffer(ManuallyDrop::take(&mut self.0));
                }
            }
        }
        let mut guard = BufReturnGuard(ManuallyDrop::new(buf), self.1);

        f(&mut guard.0)
    }
}

struct TxToken<'d>(&'d mut Option<TunBufferToken>, &'d dyn Tun);
impl<'d> smoltcp::phy::TxToken for TxToken<'d> {
    fn consume<R, F>(
        self,
        _timestamp: smoltcp::time::Instant,
        len: usize,
        f: F,
    ) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let buf = self
            .0
            .as_mut()
            .expect("Consuming a TxToken without tx buffer set");
        if len > buf.data.len() {
            panic!("smoltcp cannot write a packet to a TUN interface with smaller MTU set.")
        }
        let res = f(&mut buf.data[..len]);
        self.1.send(self.0.take().unwrap(), len);
        res
    }
}

type IpStack = Arc<Mutex<IpStackInner>>;

struct IpStackInner {
    netif: Interface<'static, Device>,
    // TODO: (router) also record src ip
    tcp_sockets: BTreeMap<SocketAddr, SocketHandle>,
    udp_sockets: BTreeMap<SocketAddr, Sender<(DestinationAddr, Buffer)>>,
    tcp_next: Weak<dyn StreamHandler>,
    udp_next: Weak<dyn DatagramSessionHandler>,
}

pub fn run(
    tun: Arc<dyn Tun>,
    tcp_next: Weak<dyn StreamHandler>,
    udp_next: Weak<dyn DatagramSessionHandler>,
) -> tokio::task::JoinHandle<()> {
    let netif = InterfaceBuilder::new(
        Device {
            tx: None,
            rx: None,
            tun: tun.clone(),
        },
        Vec::with_capacity(64),
    )
    .ip_addrs(vec![IpCidr::new(
        Ipv4Address::new(192, 168, 3, 1).into(),
        0,
    )])
    .any_ip(true)
    .routes(Routes::new(
        [
            (
                IpCidr::new(Ipv4Address::UNSPECIFIED.into(), 0),
                // TODO: Custom IP Address
                Route::new_ipv4_gateway(Ipv4Address::new(192, 168, 3, 1)),
            ),
            (
                IpCidr::new(Ipv6Address::UNSPECIFIED.into(), 0),
                Route::new_ipv6_gateway(Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            ),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>(),
    ))
    .finalize();

    let stack = Arc::new(Mutex::new(IpStackInner {
        netif,
        tcp_sockets: BTreeMap::new(),
        udp_sockets: BTreeMap::new(),
        tcp_next,
        udp_next,
    }));
    tokio::runtime::Handle::current().spawn_blocking(move || {
        while let Some(recv_buf) = tun.blocking_recv() {
            process_packet(&stack, recv_buf);
        }
    })
}

fn process_packet(stack: &IpStack, packet: Buffer) {
    if packet.len() < 20 {
        return;
    }
    match packet[0] >> 4 {
        0b0100 => {
            let mut ipv4_packet = match Ipv4Packet::new_checked(packet) {
                Ok(p) => p,
                Err(_) => return,
            };
            let (src_addr, dst_addr) = (ipv4_packet.src_addr(), ipv4_packet.dst_addr());
            match ipv4_packet.protocol() {
                IpProtocol::Tcp => {
                    let p = match TcpPacket::new_checked(ipv4_packet.payload_mut()) {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let (src_port, dst_port, is_syn) = (p.src_port(), p.dst_port(), p.syn());
                    process_tcp(
                        stack,
                        SocketAddr::new(smoltcp_addr_to_std(src_addr.into()), src_port),
                        dst_addr.into(),
                        dst_port,
                        is_syn,
                        ipv4_packet.into_inner(),
                    );
                }
                IpProtocol::Udp => {
                    let mut p = match UdpPacket::new_checked(ipv4_packet.payload_mut()) {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let (src_port, dst_port) = (p.src_port(), p.dst_port());
                    process_udp(
                        stack,
                        SocketAddr::new(smoltcp_addr_to_std(src_addr.into()), src_port),
                        dst_addr.into(),
                        dst_port,
                        p.payload_mut(),
                    );
                }
                _ => {}
            }
        }
        0b0110 => {
            let mut ipv6_packet = match Ipv6Packet::new_checked(packet) {
                Ok(p) => p,
                Err(_) => return,
            };
            let (src_addr, dst_addr) = (ipv6_packet.src_addr(), ipv6_packet.dst_addr());
            match ipv6_packet.next_header() {
                IpProtocol::Tcp => {
                    let p = match TcpPacket::new_checked(ipv6_packet.payload_mut()) {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let (src_port, dst_port, is_syn) = (p.src_port(), p.dst_port(), p.syn());
                    process_tcp(
                        stack,
                        SocketAddr::new(smoltcp_addr_to_std(src_addr.into()), src_port),
                        dst_addr.into(),
                        dst_port,
                        is_syn,
                        ipv6_packet.into_inner(),
                    );
                }
                IpProtocol::Udp => {
                    let mut p = match UdpPacket::new_checked(ipv6_packet.payload_mut()) {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let (src_port, dst_port) = (p.src_port(), p.dst_port());
                    process_udp(
                        stack,
                        SocketAddr::new(smoltcp_addr_to_std(src_addr.into()), src_port),
                        dst_addr.into(),
                        dst_port,
                        p.payload_mut(),
                    );
                }
                _ => {}
            }
        }
        _ => {}
    };
}

fn process_tcp(
    stack: &IpStack,
    src_addr: SocketAddr,
    dst_addr: smoltcp::wire::IpAddress,
    dst_port: u16,
    is_syn: bool,
    packet: Buffer,
) {
    let mut guard = stack.lock().unwrap();
    let IpStackInner {
        netif,
        tcp_sockets,
        tcp_next,
        ..
    } = &mut *guard;

    let dev = netif.device_mut();
    dev.rx = Some(packet);

    let tcp_socket_count = tcp_sockets.len();
    if let Entry::Vacant(vac) = tcp_sockets.entry(src_addr) {
        if !is_syn || tcp_socket_count >= 1 << 10 {
            return;
        }
        let next = match tcp_next.upgrade() {
            Some(n) => n,
            None => return,
        };
        let mut socket = TcpSocket::new(
            // Note: The buffer sizes effectively affect overall throughput.
            RingBuffer::new(vec![0; 1024 * 14]),
            RingBuffer::new(vec![0; 10240]),
        );
        socket
            .listen(IpEndpoint::new(dst_addr, dst_port))
            // This unwrap cannot panic for a valid TCP packet because:
            // 1) The socket is just created
            // 2) dst_port != 0
            .unwrap();
        socket.set_nagle_enabled(false);
        // The default ACK delay (10ms) significantly reduces uplink throughput.
        // Maybe due to the delay when sending ACK packets?
        socket.set_ack_delay(None);
        let socket_handle = netif.add_socket(socket);
        vac.insert(socket_handle);
        let ctx = FlowContext::new(
            src_addr,
            DestinationAddr {
                host: HostName::Ip(smoltcp_addr_to_std(dst_addr)),
                port: dst_port,
            },
        );
        tokio::spawn({
            let stack = stack.clone();
            async move {
                let mut stream = stream::IpStackStream {
                    socket_entry: tcp_socket_entry::TcpSocketEntry {
                        socket_handle,
                        stack,
                        local_endpoint: src_addr,
                        most_recent_scheduled_poll: Arc::new(AtomicI64::new(i64::MAX)),
                    },
                    rx_buf: None,
                    tx_buf: Some((Vec::with_capacity(4 * 1024), 0)),
                };
                if stream.handshake().await.is_ok() {
                    next.on_stream(Box::new(stream) as _, Buffer::new(), Box::new(ctx));
                }
            }
        });
    };
    let now = Instant::now();
    let _ = netif.poll(now.into());
    // Polling the socket may wake a read/write waker. When a task polls the tx/rx
    // buffer from the corresponding stream, a delayed poll will be rescheduled.
    // Therefore, we don't have to poll the socket here.
}

fn process_udp(
    stack: &IpStack,
    src_addr: SocketAddr,
    dst_addr: smoltcp::wire::IpAddress,
    dst_port: u16,
    payload: &mut [u8],
) {
    let mut guard = stack.lock().unwrap();
    let IpStackInner {
        udp_sockets,
        udp_next,
        ..
    } = &mut *guard;
    let tx = match udp_sockets.entry(src_addr) {
        Entry::Occupied(ent) => ent.into_mut(),
        Entry::Vacant(vac) => {
            let next = match udp_next.upgrade() {
                Some(next) => next,
                None => return,
            };
            let (tx, rx) = bounded(48);
            let stack_inner = stack.clone();
            tokio::spawn(async move {
                next.on_session(
                    Box::new(MultiplexedDatagramSessionAdapter::new(
                        datagram::IpStackDatagramSession {
                            stack: stack_inner,
                            local_endpoint: src_addr.into(),
                        },
                        rx.into_stream(),
                        120,
                    )),
                    Box::new(FlowContext::new_af_sensitive(
                        src_addr,
                        DestinationAddr {
                            host: HostName::Ip(smoltcp_addr_to_std(dst_addr)),
                            port: dst_port,
                        },
                    )),
                );
            });
            vac.insert(tx)
        }
    };
    if let Err(TrySendError::Disconnected(_)) = tx.try_send((
        DestinationAddr {
            host: HostName::Ip(smoltcp_addr_to_std(dst_addr)),
            port: dst_port,
        },
        payload.to_vec(),
    )) {
        udp_sockets.remove(&src_addr);
    }
    // Drop packet when buffer is full
}

fn schedule_repoll(
    stack: Arc<Mutex<IpStackInner>>,
    poll_at: Instant,
    most_recent_scheduled_poll: Arc<AtomicI64>,
) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
    debug_log(format!("Scheduled repoll: {:?}", poll_at));
    let stack_cloned = stack.clone();
    Box::pin(async move {
        sleep_until(tokio::time::Instant::from_std(poll_at)).await;
        if smoltcp::time::Instant::from(Instant::now()).total_millis()
            > most_recent_scheduled_poll.load(Ordering::Relaxed)
        {
            // A more urgent poll was scheduled.
            return;
        }
        let mut stack_guard = stack.lock().unwrap();
        let _ = stack_guard.netif.poll(poll_at.into());
        if let Some(delay) = stack_guard.netif.poll_delay(poll_at.into()) {
            let scheduled_poll_milli =
                (smoltcp::time::Instant::from(Instant::now()) + delay).total_millis();
            if scheduled_poll_milli >= most_recent_scheduled_poll.load(Ordering::Relaxed) {
                return;
            }
            // TODO: CAS spin loop
            most_recent_scheduled_poll.store(scheduled_poll_milli, Ordering::Relaxed);

            tokio::spawn(schedule_repoll(
                stack_cloned,
                poll_at + Duration::from(delay),
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
