use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::rc::Rc;
use std::slice::from_raw_parts_mut;
use std::string::ToString;
use std::sync::Arc;

use crate::collections::SimpleHostNameVectorView;

use flume::{bounded, Receiver, Sender, TryRecvError};
use windows as Windows;
use windows::core::{implement, Interface, Result};
use windows::Foundation::Collections::IVectorView;
use windows::Networking::HostName;
use windows::Networking::Sockets::DatagramSocket;
use windows::Networking::Vpn::{
    VpnChannel, VpnDomainNameAssignment, VpnDomainNameInfo, VpnDomainNameType, VpnPacketBuffer,
    VpnPacketBufferList, VpnRoute, VpnRouteAssignment,
};
use windows::Storage::Streams::Buffer;
use windows::Win32::System::WinRT::IBufferByteAccess;

/// Safety: user must ensure the output slice does not outlive the buffer instance.
pub(crate) unsafe fn query_slice_from_ibuffer_mut(buf: &mut Buffer) -> &'static mut [u8] {
    let len = buf.Length().unwrap() as _;
    let byte_access: IBufferByteAccess = buf.cast().unwrap();
    #[allow(unused_unsafe)]
    unsafe {
        let ptr = byte_access.Buffer().unwrap();
        from_raw_parts_mut(ptr, len)
    }
}

fn connect_with_factory(
    transport: &DatagramSocket,
    factory: &ytflow::config::plugin::VpnTunFactory,
    channel: &VpnChannel,
) -> Result<()> {
    let ipv4 = factory
        .ipv4
        .as_ref()
        .map(ToString::to_string)
        .map(HostName::CreateHostName)
        .transpose()?
        .map(|h| IVectorView::from(SimpleHostNameVectorView(vec![h].into())));
    let ipv6 = factory
        .ipv6
        .as_ref()
        .map(ToString::to_string)
        .map(HostName::CreateHostName)
        .transpose()?
        .map(|h| IVectorView::from(SimpleHostNameVectorView(vec![h].into())));

    let route_scope = VpnRouteAssignment::new()?;
    route_scope.SetExcludeLocalSubnets(true)?;
    for route4 in &factory.ipv4_route {
        route_scope
            .Ipv4InclusionRoutes()?
            .Append(VpnRoute::CreateVpnRoute(
                HostName::CreateHostName(route4.first_address().to_string())?,
                route4.network_length(),
            )?)?;
    }
    for route6 in &factory.ipv6_route {
        route_scope
            .Ipv6InclusionRoutes()?
            .Append(VpnRoute::CreateVpnRoute(
                HostName::CreateHostName(route6.first_address().to_string())?,
                route6.network_length(),
            )?)?;
    }

    let dns_assignments = VpnDomainNameAssignment::new()?;
    let dns_hosts: Result<Vec<_>> = factory
        .dns
        .iter()
        .map(ToString::to_string)
        .map(HostName::CreateHostName)
        .collect();
    let proxy: Result<Vec<_>> = factory
        .web_proxy
        .iter()
        .copied()
        .map(HostName::CreateHostName)
        .collect();
    let dnsinfo = VpnDomainNameInfo::CreateVpnDomainNameInfo(
        ".",
        VpnDomainNameType::Suffix,
        IVectorView::<_>::from(SimpleHostNameVectorView(dns_hosts?.into())),
        IVectorView::<_>::from(SimpleHostNameVectorView(proxy?.into())),
    )?;
    dns_assignments.DomainNameList()?.Append(dnsinfo)?;

    channel.StartWithMainTransport(
        ipv4,
        ipv6,
        None,
        route_scope,
        dns_assignments,
        1512,
        3,
        false,
        transport,
    )
}

struct VpnPlugInInner {
    tx_buf_rx: Receiver<VpnPacketBuffer>,
    rx_buf_tx: Sender<Vec<u8>>,
    rt: ytflow::tokio::runtime::Runtime,
}

#[implement(Windows::Networking::Vpn::IVpnPlugIn)]
pub struct VpnPlugIn(Option<VpnPlugInInner>);

#[allow(non_snake_case)]
impl VpnPlugIn {
    pub fn new() -> Self {
        Self(None)
    }

    fn Connect(&mut self, channel: &Option<VpnChannel>) -> Result<()> {
        let channel = channel.as_ref().unwrap();

        if self.0.is_some() {
            return channel.TerminateConnection("A fresh reconnect is required");
        }

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

        // Load VPN configurations.
        let db_path: &'static std::path::Path = todo!("Get DB path from localstorage");
        let db = match ytflow::data::Database::open(db_path) {
            Ok(db) => db,
            Err(e) => return channel.TerminateConnection(format!("Cannot open database: {}", e)),
        };
        let conn = match db.connect() {
            Ok(conn) => conn,
            Err(e) => {
                return channel.TerminateConnection(format!("Cannot connect to database: {}", e))
            }
        };

        fn load_plugins(
            profile_id: usize,
            conn: &ytflow::data::Connection,
        ) -> ytflow::data::DataResult<
            std::result::Result<(Vec<ytflow::data::Plugin>, Vec<ytflow::data::Plugin>), String>,
        > {
            use ytflow::data::{Plugin, Profile};
            let profile_id = match Profile::query_by_id(profile_id, &conn)? {
                Some(p) => p.id,
                None => return Ok(Err(format!("Profile {} not found", profile_id))),
            };
            let entry_plugins = Plugin::query_entry_by_profile(profile_id, conn)?;
            let all_plugins = Plugin::query_all_by_profile(profile_id, conn)?;
            Ok(Ok((entry_plugins, all_plugins)))
        }

        let profile_id: usize = todo!("Load profile id from localstorage");
        let (entry_plugins, all_plugins) = match load_plugins(profile_id, &conn) {
            Ok(Ok(p)) => p,
            Ok(Err(s)) => return channel.TerminateConnection(s),
            Err(e) => {
                return channel.TerminateConnection(format!("Failed to load plugins from: {}", e))
            }
        };

        let (factory, errors) =
            ytflow::config::ProfilePluginFactory::parse_profile(entry_plugins.iter(), &all_plugins);
        if !errors.is_empty() {
            let it = std::iter::once(String::from("Failed to parse plugins: "));
            let it = it.chain(errors.iter().map(ToString::to_string));
            let strs: Vec<_> = it.collect();
            return channel.TerminateConnection(strs.join("\r\n"));
        }

        let rt = match ytflow::tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                return channel.TerminateConnection(format!("Cannot create tokio runtime: {}", e))
            }
        };

        let tx_buf_rx_cell = Rc::new(RefCell::new(None));
        let rx_buf_tx_cell = Rc::new(RefCell::new(None));
        ytflow::config::plugin::ON_VPNTUN.with(|cb| {
            let tx_buf_rx_cell = tx_buf_rx_cell.clone();
            let rx_buf_tx_cell = rx_buf_tx_cell.clone();
            let channel = channel.clone();
            *cb.borrow_mut() = Some(Box::new(move |f| {
                // TODO: bounded? capacity?
                let (tx_buf_tx, tx_buf_rx) = bounded(16);
                let (rx_buf_tx, rx_buf_rx) = bounded::<Vec<u8>>(16);
                *tx_buf_rx_cell.borrow_mut() = Some(tx_buf_rx);
                *rx_buf_tx_cell.borrow_mut() = Some(rx_buf_tx);

                let _ = connect_with_factory(&transport, f, &channel);

                Arc::new(super::tun_plugin::VpnTun {
                    tx: tx_buf_tx,
                    rx: rx_buf_rx,
                    dummy_socket: b_transport,
                    channel,
                })
            }));
        });

        let rt_handle = rt.handle();
        let (set, errors) = factory.load_all(&rt_handle);
        let (tx_buf_rx, rx_buf_tx) = if let (Some(tx_buf_rx), Some(rx_buf_tx), []) = (
            tx_buf_rx_cell.borrow_mut().take(),
            rx_buf_tx_cell.borrow_mut().take(),
            &*errors,
        ) {
            (tx_buf_rx, rx_buf_tx)
        } else {
            let error_str = if errors.is_empty() {
                String::from("There must be exactly one vpn-tun plugin in a profile")
            } else {
                let it = std::iter::once(String::from("Failed to instantiate plugins: "));
                let it = it.chain(errors.iter().map(ToString::to_string));
                it.collect::<Vec<_>>().join("\r\n")
            };
            {
                let _enter_guard = rt_handle.enter();
                drop(set);
            }
            rt.shutdown_background();
            ytflow::config::plugin::ON_VPNTUN.with(|cb| drop(cb.borrow_mut().take()));
            return channel.TerminateConnection(error_str);
        };

        self.0 = Some(VpnPlugInInner {
            tx_buf_rx,
            rx_buf_tx,
            rt,
        });
        Ok(())
    }
    fn Disconnect(&mut self, channel: &Option<VpnChannel>) -> Result<()> {
        channel.as_ref().unwrap().Stop()?;
        if let Some(inner) = self.0.take() {
            let _enter_guard = inner.rt.enter();
            drop(inner.rx_buf_tx);
            drop(inner.tx_buf_rx);
        }
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
        let rx_buf_tx = match &self.0 {
            Some(t) => &t.rx_buf_tx,
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
        let tx_buf_rx = match &self.0 {
            Some(r) => &r.tx_buf_rx,
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
