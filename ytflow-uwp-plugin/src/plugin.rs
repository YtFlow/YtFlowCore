use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::Arc;

use flume::{bounded, Receiver, Sender, TryRecvError, TrySendError};
// use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError, TrySendError};
use windows::{implement, Interface, Result};

use ytflow::config::Config;
use ytflow::flow::Manager;
use ytflow::plugin::ip_stack::{IpStack, IpTxBuf};

use crate::bindings::Windows;
use crate::bindings::Windows::Foundation::Collections::IVectorView;
use crate::bindings::Windows::Networking::HostName;
use crate::bindings::Windows::Networking::Sockets::DatagramSocket;
use crate::bindings::Windows::Networking::Vpn::{
    VpnChannel, VpnDomainNameAssignment, VpnDomainNameInfo, VpnDomainNameType, VpnPacketBuffer,
    VpnPacketBufferList, VpnRoute, VpnRouteAssignment,
};
use crate::bindings::Windows::Storage::Streams::Buffer;
use crate::bindings::Windows::Win32::System::WinRT::IBufferByteAccess;
use crate::collections::SimpleHostNameVectorView;

fn query_slice_from_ibuffer(buf: &Buffer) -> &[u8] {
    let len = buf.Length().unwrap() as _;
    let byte_access: IBufferByteAccess = buf.cast().unwrap();
    #[allow(unused_unsafe)]
    unsafe {
        let ptr = byte_access.Buffer().unwrap();
        from_raw_parts(ptr, len)
    }
}

/// Safety: user must ensure the output slice does not outlive the buffer instance.
unsafe fn query_slice_from_ibuffer_mut(buf: &mut Buffer) -> &'static mut [u8] {
    let len = buf.Length().unwrap() as _;
    let byte_access: IBufferByteAccess = buf.cast().unwrap();
    #[allow(unused_unsafe)]
    unsafe {
        let ptr = byte_access.Buffer().unwrap();
        from_raw_parts_mut(ptr, len)
    }
}

struct VpnPacketTxBuffer(VpnPacketBuffer, Buffer);

impl AsRef<[u8]> for VpnPacketTxBuffer {
    fn as_ref(&self) -> &[u8] {
        query_slice_from_ibuffer(&self.1)
    }
}
impl AsMut<[u8]> for VpnPacketTxBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { query_slice_from_ibuffer_mut(&mut self.1) }
    }
}

struct VpnBuf {
    channel: VpnChannel,
    tx: Sender<VpnPacketBuffer>,
    dummy_socket: UdpSocket,
}

// TODO: why?
unsafe impl Send for VpnBuf {}

impl IpTxBuf for VpnBuf {
    type Buf = VpnPacketTxBuffer;

    fn request(&mut self, len: usize) -> Self::Buf {
        let vpn_buffer = self.channel.GetVpnReceivePacketBuffer().unwrap();
        let buffer = vpn_buffer.Buffer().unwrap();
        buffer.SetLength(len as u32).unwrap();
        VpnPacketTxBuffer(vpn_buffer, buffer)
    }

    fn send(&mut self, buf: Self::Buf) {
        let VpnPacketTxBuffer(vpn_buffer, _buffer) = buf;
        if let Err(TrySendError::Full(vpn_buffer)) = self.tx.try_send(vpn_buffer) {
            // TODO: intentionally block?
            // VpnPacketBuffer must be returned back to system to dealloc
            let _ = self.dummy_socket.send(&[1][..]);
            let _ = self.tx.send(vpn_buffer);
        }
        if self.tx.len() == 1 {
            let _ = self.dummy_socket.send(&[1][..]);
        }
    }
}

#[implement(Windows::Networking::Vpn::IVpnPlugIn)]
pub struct VpnPlugIn {
    // stack: Option<IpStack<VpnBuf>>,
    // manager: Option<Arc<Manager>>,
    tx_buf_rx: Option<Receiver<VpnPacketBuffer>>,
    rx_buf_tx: Option<Sender<Vec<u8>>>,
}

#[allow(non_snake_case)]
impl VpnPlugIn {
    pub fn new() -> Self {
        Self {
            // stack: None,
            // manager: None,
            tx_buf_rx: None,
            rx_buf_tx: None,
        }
    }

    fn Connect(&mut self, channel: &Option<VpnChannel>) -> Result<()> {
        let channel = channel.as_ref().unwrap();

        let transport = DatagramSocket::new()?;
        channel.AssociateTransport(&transport, None)?;
        let lo_host = HostName::CreateHostName("127.0.0.1")?;
        transport.BindEndpointAsync(lo_host.clone(), "")?.get()?;
        let b_transport =
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).unwrap();
        transport
            .ConnectAsync(
                lo_host.clone(),
                b_transport.local_addr().unwrap().port().to_string(),
            )?
            .get()?;
        let transport_port = transport
            .Information()?
            .LocalPort()?
            .to_string()
            .parse()
            .unwrap();
        b_transport
            .connect(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                transport_port,
            )))
            .unwrap();

        let dnsAssignment = VpnDomainNameAssignment::new()?;
        let dnsinfo = VpnDomainNameInfo::CreateVpnDomainNameInfo(
            ".",
            VpnDomainNameType::Suffix,
            Into::<IVectorView<_>>::into(SimpleHostNameVectorView(
                vec![HostName::CreateHostName("114.114.114.114")?].into(),
            )),
            Into::<IVectorView<_>>::into(SimpleHostNameVectorView(vec![].into())),
        )?;
        dnsAssignment.DomainNameList()?.Append(dnsinfo)?;
        let routeScope = VpnRouteAssignment::new()?;
        routeScope.SetExcludeLocalSubnets(true)?;
        routeScope
            .Ipv4InclusionRoutes()?
            .Append(VpnRoute::CreateVpnRoute(
                HostName::CreateHostName("192.168.0.31")?,
                32,
            )?)?;
        // routeScope
        //     .Ipv4InclusionRoutes()?
        //     .Append(VpnRoute::CreateVpnRoute(
        //         HostName::CreateHostName("128.0.0.0")?,
        //         1,
        //     )?)?;
        routeScope
            .Ipv4InclusionRoutes()?
            .Append(VpnRoute::CreateVpnRoute(
                HostName::CreateHostName("114.114.114.114")?,
                32,
            )?)?;
        routeScope
            .Ipv4InclusionRoutes()?
            .Append(VpnRoute::CreateVpnRoute(
                HostName::CreateHostName("11.17.0.0")?,
                16,
            )?)?;

        let manager = Arc::new(Manager::new(&Config::new()));
        // TODO: bounded? capacity?
        let (tx_buf_tx, tx_buf_rx) = bounded(16);
        let (rx_buf_tx, rx_buf_rx) = bounded::<Vec<u8>>(16);
        // self.manager = Some(manager.clone());
        std::thread::spawn({
            let channel = channel.clone().cast()?;
            let manager = manager.clone();
            move || {
                let stack = IpStack::new(
                    manager,
                    VpnBuf {
                        channel,
                        tx: tx_buf_tx,
                        dummy_socket: b_transport,
                    },
                );
                while let Ok(buf) = rx_buf_rx.recv() {
                    let boxed_buf = buf.into_boxed_slice();
                    let len = boxed_buf.len();
                    let ptr = Box::into_raw(boxed_buf);
                    struct Guard(*mut [u8]);
                    impl Drop for Guard {
                        fn drop(&mut self) {
                            unsafe { Box::from_raw(self.0) };
                        }
                    }
                    let _g = Guard(ptr);
                    stack.push_ip_packets(std::array::IntoIter::new([unsafe {
                        std::slice::from_raw_parts_mut(ptr as *mut u8, len)
                    }]));
                }
            }
        });
        self.tx_buf_rx = Some(tx_buf_rx);
        self.rx_buf_tx = Some(rx_buf_tx);

        channel.StartWithMainTransport(
            Into::<IVectorView<_>>::into(SimpleHostNameVectorView(
                vec![HostName::CreateHostName("192.168.3.1")?].into(),
            )),
            None,
            None,
            routeScope,
            dnsAssignment,
            1512,
            3,
            false,
            transport,
        )?;

        Ok(())
    }
    fn Disconnect(&mut self, channel: &Option<VpnChannel>) -> Result<()> {
        channel.as_ref().unwrap().Stop()?;
        self.tx_buf_rx = None;
        self.rx_buf_tx = None;
        Ok(())
    }
    fn GetKeepAlivePayload(
        &self,
        _channel: &Option<VpnChannel>,
        keepAlivePacket: &mut Option<VpnPacketBuffer>,
    ) -> Result<()> {
        *keepAlivePacket = None;
        Ok(())
    }
    fn Encapsulate(
        &self,
        _channel: &Option<VpnChannel>,
        packets: &Option<VpnPacketBufferList>,
        _encapulatedPackets: &Option<VpnPacketBufferList>,
    ) -> Result<()> {
        let packets = packets.as_ref().unwrap().clone();
        let rx_buf_tx = match self.rx_buf_tx.as_ref() {
            Some(t) => t,
            None => return Ok(()),
        };
        let packet_count = packets.Size()?;
        for _ in 0..packet_count {
            let vpn_buffer = packets.RemoveAtBegin()?;
            let mut buffer = vpn_buffer.Buffer()?;
            let slice = unsafe { query_slice_from_ibuffer_mut(&mut buffer) };
            let mut buf = Vec::with_capacity(slice.len());
            unsafe {
                std::ptr::copy_nonoverlapping(slice.as_mut_ptr(), buf.as_mut_ptr(), slice.len());
                buf.set_len(slice.len());
            }
            if let Err(_) = rx_buf_tx.send(buf) {
                return Ok(());
            }
            packets.Append(vpn_buffer)?;
        }
        Ok(())
    }
    fn Decapsulate(
        &self,
        _channel: &Option<VpnChannel>,
        _encapBuffer: &Option<VpnPacketBuffer>,
        decapsulatedPackets: &Option<VpnPacketBufferList>,
        _controlPacketsToSend: &Option<VpnPacketBufferList>,
    ) -> Result<()> {
        let decapsulatedPackets = decapsulatedPackets.as_ref().unwrap().clone();
        let tx_buf_rx = match &self.tx_buf_rx {
            Some(rx) => rx,
            None => return Ok(()),
        };
        let mut idle_loop_count = 0;
        loop {
            match tx_buf_rx.try_recv() {
                Ok(buf) => {
                    idle_loop_count = 0;
                    decapsulatedPackets.Append(buf)?;
                }
                Err(TryRecvError::Disconnected) => return Ok(()),
                Err(TryRecvError::Empty) if idle_loop_count < 8 => {
                    idle_loop_count += 1;
                    continue;
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_play() -> super::Result<()> {
        use crate::bindings::Windows::Networking::Vpn::*;
        use std::mem::transmute;
        let ass = VpnRouteAssignment::new()?;
        unsafe { println!("{:?}", ass.Ipv4InclusionRoutes()?.Size()?) };
        Ok(())
    }
}
