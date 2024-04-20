use std::io;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::sync::Weak;

use fruity::core::Arc as ObjcArc;
use libc::sockaddr;
use nix::sys::socket::{SockaddrLike, SockaddrStorage};
use tokio::sync::oneshot::{self, Receiver};

use super::ffi::{self, DNSServiceErrorType};
use super::*;
use crate::flow::*;
use crate::plugin::netif::NetifSelector;

pub struct Resolver {
    dispatch_queue: ObjcArc<DispatchQueue>,
    selector: Weak<NetifSelector>,
}

struct DnsService {
    sd_ref: ffi::DNSServiceRef,
}

unsafe impl Send for DnsService {}
unsafe impl Sync for DnsService {}

impl Drop for DnsService {
    fn drop(&mut self) {
        if !self.sd_ref.is_null() {
            unsafe { ffi::DNSServiceRefDeallocate(self.sd_ref) };
        }
    }
}

impl Resolver {
    pub fn new(selector: Weak<NetifSelector>) -> Self {
        let dispatch_queue = DispatchQueueBuilder::new()
            .label(CStr::from_bytes_with_nul(b"com.bdbai.ytflow.core.resolver\0").unwrap())
            .attr(DispatchQueueAttributes::SERIAL) // Ensure race-free access to context pointer
            .build();
        Self {
            dispatch_queue,
            selector,
        }
    }
}

#[derive(Default)]
struct LookupResult {
    v4: ResolvedV4,
    v6: ResolvedV6,
    error_code: DNSServiceErrorType,
}

struct LookupCallbackContext {
    result: LookupResult,
    tx: tokio::sync::oneshot::Sender<LookupResult>,
}

#[allow(non_snake_case)]
extern "C" fn handle_dns_callback(
    sdRef: ffi::DNSServiceRef,
    flags: ffi::DNSServiceFlags,
    _interfaceIndex: u32,
    errorCode: DNSServiceErrorType,
    _hostname: *const ::std::os::raw::c_char,
    address: *const sockaddr,
    _ttl: u32,
    context: *mut ::std::os::raw::c_void,
) {
    if errorCode == 0 {
        unsafe {
            let context = &mut *(context as *mut LookupCallbackContext);
            let sockaddr = unsafe { SockaddrStorage::from_raw(address, None).unwrap() };
            let to_add = flags & ffi::kDNSServiceFlagsAdd != 0;
            match (sockaddr.as_sockaddr_in(), sockaddr.as_sockaddr_in6()) {
                (Some(v4), _) => {
                    let ip = *SocketAddrV4::from(*v4).ip();
                    if to_add {
                        context.result.v4.push(ip);
                    } else {
                        context.result.v4.retain(|i| ip != *i);
                    }
                }
                (_, Some(v6)) => {
                    let ip = *SocketAddrV6::from(*v6).ip();
                    if to_add {
                        context.result.v6.push(*SocketAddrV6::from(*v6).ip())
                    } else {
                        context.result.v6.retain(|i| ip != *i);
                    }
                }
                _ => {}
            }
        }
    }
    if errorCode != 0 || (flags & ffi::kDNSServiceFlagsMoreComing == 0) {
        let _dns_service = DnsService { sd_ref: sdRef }; // Deallocate sdRef
        unsafe {
            let context = *Box::from_raw(context as *mut LookupCallbackContext); // Deallocate context
            let LookupCallbackContext { mut result, tx } = context;
            result.error_code = errorCode;
            let _ = tx.send(result);
        }
    }
}

impl Resolver {
    fn start_dns_lookup(
        &self,
        domain: String,
        protocol: ffi::DNSServiceProtocol,
    ) -> FlowResult<Receiver<LookupResult>> {
        let (tx, rx) = oneshot::channel();
        let Some(selector) = self.selector.upgrade() else {
            return Err(io::Error::from(io::ErrorKind::NotConnected).into());
        };
        let idx = selector.cached_netif.load().get_idx()?;
        let ctx = Box::into_raw(Box::new(LookupCallbackContext {
            result: Default::default(),
            tx,
        }));
        let mut dns_service = DnsService {
            sd_ref: std::ptr::null_mut(),
        };
        let err = unsafe {
            let Ok(domain) = CString::new(domain) else {
                return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
            };
            ffi::DNSServiceGetAddrInfo(
                &mut dns_service.sd_ref as *mut _ as _,
                ffi::kDNSServiceFlagsReturnIntermediates | ffi::kDNSServiceFlagsTimeout,
                idx,
                protocol,
                domain.as_ptr(),
                Some(handle_dns_callback),
                ctx as _,
            )
        };
        if err != 0 {
            unsafe {
                drop(Box::from(ctx));
            }
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("dnssd returned code {} for IP lookup", err),
            )
            .into());
        }
        let err = unsafe {
            ffi::DNSServiceSetDispatchQueue(
                dns_service.sd_ref as *mut _ as _,
                &*self.dispatch_queue as *const _ as _,
            )
        };
        if err != 0 {
            unsafe {
                drop(Box::from(ctx));
            }
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("failed to set dispatch queue: {} for IP lookup", err),
            )
            .into());
        }
        std::mem::forget(dns_service); // The callback will be responsible for deallocations
        Ok(rx)
    }

    pub async fn resolve_ipv4(&self, domain: String) -> ResolveResultV4 {
        let res = self
            .start_dns_lookup(domain, ffi::kDNSServiceProtocol_IPv4)?
            .await
            .unwrap();
        match res {
            LookupResult {
                error_code: ffi::kDNSServiceErr_NoSuchRecord,
                ..
            } => Err(io::Error::new(io::ErrorKind::NotFound, "DNS record not found").into()),
            LookupResult { error_code, v4, .. } if v4.is_empty() => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("dnssd returned code {} during IPv4 lookup", error_code),
            )
            .into()),
            _ => Ok(res.v4), // TODO: log errors with normal records
        }
    }
    pub async fn resolve_ipv6(&self, domain: String) -> ResolveResultV6 {
        let res = self
            .start_dns_lookup(domain, ffi::kDNSServiceProtocol_IPv6)?
            .await
            .unwrap();
        match res {
            LookupResult {
                error_code: ffi::kDNSServiceErr_NoSuchRecord,
                ..
            } => Err(io::Error::new(io::ErrorKind::NotFound, "DNS record not found").into()),
            LookupResult { error_code, v6, .. } if v6.is_empty() => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("dnssd returned code {} during IPv6 lookup", error_code),
            )
            .into()),
            _ => Ok(res.v6), // TODO: log errors with normal records
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::netif::sys::Netif;
    use crate::plugin::netif::{FamilyPreference, SelectionMode};

    #[tokio::test]
    async fn test_lookup() {
        let selector = NetifSelector::new(
            SelectionMode::Manual("en0".into()),
            FamilyPreference::Both,
            |_| None,
        );
        selector.cached_netif.store(Arc::new(Netif {
            name: "en0".into(),
            bsd_name: CString::from_vec_with_nul(b"en0\0"[..].into()).unwrap(),
        }));
        let resolver = super::Resolver::new(Arc::downgrade(&selector));
        let now = std::time::SystemTime::now();
        println!(
            "{:?} {:?}",
            resolver.resolve_ipv6("google.com".into()).await.unwrap(),
            now.elapsed()
        );
        println!(
            "{:?}",
            resolver
                .resolve_ipv4("baidu.skldjflksdfjkds.com".into())
                .await
                .unwrap_err()
        );
    }
}
