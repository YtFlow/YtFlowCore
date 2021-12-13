use std::net::{SocketAddr, SocketAddrV6};
use widestring::ucstr::U16CStr;

use super::super::*;
use windows::Foundation::EventRegistrationToken;
use windows::Networking::Connectivity::*;
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::*;

const INET: u16 = AF_INET.0 as u16;
const INET6: u16 = AF_INET6.0 as u16;

#[derive(Debug)]
enum Rate {
    Recommended,
    Backup,
    NotRecommended,
}

// https://docs.rs/ipconfig/0.2.2/x86_64-pc-windows-msvc/src/ipconfig/adapter.rs.html#58-72
fn enum_adapters() -> Vec<(Netif, Rate)> {
    let mut adapters_addresses_buffer = Vec::new();
    let mut buf_len: u32 = 16384;
    let mut result = ERROR_BUFFER_OVERFLOW.0;
    unsafe {
        while result == ERROR_BUFFER_OVERFLOW.0 {
            adapters_addresses_buffer.resize(buf_len as usize, 0);

            result = GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_INCLUDE_GATEWAYS,
                std::ptr::null_mut(),
                adapters_addresses_buffer.as_mut_ptr() as *mut _,
                &mut buf_len as *mut _,
            );
        }
    }
    let mut ret = Vec::new();
    if result != ERROR_SUCCESS.0 {
        return ret;
    }
    let mut adapter_addresses_ptr =
        adapters_addresses_buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    while !adapter_addresses_ptr.is_null() {
        if let Some(adapter) = unsafe { get_adapter(&mut adapter_addresses_ptr) } {
            ret.push(adapter);
        }
    }
    ret
}

unsafe fn get_adapter(
    adapter_addresses_ptr: &mut *mut IP_ADAPTER_ADDRESSES_LH,
) -> Option<(Netif, Rate)> {
    let adapter_addresses = &**adapter_addresses_ptr;
    *adapter_addresses_ptr = adapter_addresses.Next;

    let rate = if adapter_addresses.OperStatus != IfOperStatusUp
        || adapter_addresses.FirstGatewayAddress.is_null()
        || adapter_addresses.PhysicalAddressLength == 0
    {
        Rate::NotRecommended
    } else if adapter_addresses.IfType == IF_TYPE_IEEE80211 {
        Rate::Backup
    } else {
        Rate::Recommended
    };

    let adapter_name = U16CStr::from_ptr_str(adapter_addresses.FriendlyName.0).to_string_lossy();

    let (mut ipv4_addr, mut ipv6_addr) = (None, None);
    let mut unicast_address_ptr = adapter_addresses.FirstUnicastAddress;
    while !unicast_address_ptr.is_null() {
        let sockaddr = &(*unicast_address_ptr).Address;
        unicast_address_ptr = (*unicast_address_ptr).Next;
        match get_sockaddr(sockaddr) {
            Some(SocketAddr::V4(addr)) if ipv4_addr.is_none() => ipv4_addr = Some(addr),
            Some(SocketAddr::V6(addr)) if ipv6_addr.is_none() => ipv6_addr = Some(addr),
            _ => continue,
        }
    }

    let mut dns_servers = vec![];
    let mut dns_server_ptr = adapter_addresses.FirstDnsServerAddress;
    while !dns_server_ptr.is_null() {
        let sockaddr = &(*dns_server_ptr).Address;
        dns_server_ptr = (*dns_server_ptr).Next;
        dns_servers.push(match get_sockaddr(sockaddr) {
            Some(addr) => addr.ip(),
            None => continue,
        });
    }
    Some((
        Netif {
            name: adapter_name,
            ipv4_addr,
            ipv6_addr,
            dns_servers,
        },
        rate,
    ))
}

fn get_sockaddr(addr: &SOCKET_ADDRESS) -> Option<SocketAddr> {
    use std::mem::{size_of, transmute};

    let addr_len = addr.iSockaddrLength;
    let addr = addr.lpSockaddr;
    unsafe {
        match (*addr).sa_family {
            INET6 if addr_len >= size_of::<SOCKADDR_IN6>() as _ => {
                let addr = &(*(addr as *mut SOCKADDR_IN6));
                Some(
                    SocketAddrV6::new(
                        transmute::<_, [u8; 16]>(addr.sin6_addr).into(),
                        u16::from_be(addr.sin6_port),
                        u32::from_be(addr.sin6_flowinfo),
                        addr.Anonymous.sin6_scope_id,
                    )
                    .into(),
                )
            }
            INET if addr_len >= size_of::<SOCKADDR_IN>() as _ => {
                let addr = &(*(addr as *mut SOCKADDR_IN));
                Some(SocketAddr::new(
                    transmute::<_, [u8; 4]>(addr.sin_addr).into(),
                    u16::from_be(addr.sin_port),
                ))
            }
            _ => None,
        }
    }
}

pub fn select(name: &str) -> Option<Netif> {
    let adapters = enum_adapters();
    adapters
        .into_iter()
        .find(|(a, _)| a.name == name)
        .map(|(a, _)| a)
}

pub fn select_best() -> Option<Netif> {
    let adapters = enum_adapters();
    let mut backup = None;
    for (adapter, rate) in adapters {
        match rate {
            Rate::Recommended => return Some(adapter),
            Rate::Backup if backup.is_none() => backup = Some(adapter),
            _ => continue,
        }
    }
    backup
}

pub struct ChangeMonitor {
    event_token: EventRegistrationToken,
}

impl ChangeMonitor {
    pub fn new<C: Fn() + 'static>(callback: C) -> ChangeMonitor {
        let event_token = NetworkInformation::NetworkStatusChanged(
            NetworkStatusChangedEventHandler::new(move |_sender| Ok(callback())),
        )
        .unwrap();
        ChangeMonitor { event_token }
    }
}

impl Drop for ChangeMonitor {
    fn drop(&mut self) {
        NetworkInformation::RemoveNetworkStatusChanged(self.event_token).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapters() {
        for adapter in enum_adapters() {
            eprintln!("{:?}", adapter);
        }
    }

    #[test]
    fn test_select() {
        // eprintln!("{:?}", select("WLAN"));
        eprintln!("{:?}", select_best());
    }

    // #[test]
    fn test_notify() {
        use std::sync::{Arc, Condvar, Mutex};
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        {
            let pair = pair.clone();
            ChangeMonitor::new(move || {
                eprintln!("Changed");
                let mut guard = pair.0.lock().unwrap();
                *guard = true;
                pair.1.notify_one();
            });
        }
        let mut guard = pair.0.lock().unwrap();
        while !*guard {
            guard = pair.1.wait(guard).unwrap();
        }
        eprintln!("Done");
    }
}
