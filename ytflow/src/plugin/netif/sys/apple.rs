mod bind;
mod dns;
/// cbindgen:ignore
mod ffi;

pub use bind::{bind_socket_v4, bind_socket_v6};
pub use dns::Resolver;

use std::ffi::{c_char, CStr, CString};
use std::io;
use std::sync::Mutex;

use block2::ConcreteBlock;
use fruity::core::Arc as ObjcArc;
use fruity::dispatch::{DispatchQueue, DispatchQueueAttributes, DispatchQueueBuilder};
use fruity::objc::NSObject;
use serde::Serialize;

use self::ffi::nw_interface_get_name;

use super::super::*;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Netif {
    pub name: String,
    pub bsd_name: CString,
}

impl Netif {
    fn get_idx(&self) -> io::Result<libc::c_uint> {
        get_netif_idx(&self.bsd_name)
    }
}

fn get_netif_idx(bsd_name: &CStr) -> io::Result<libc::c_uint> {
    let idx: libc::c_uint = unsafe { libc::if_nametoindex(bsd_name.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx)
}

pub struct NetifProvider {
    best_if_bsd_name: Arc<Mutex<CString>>,
    _dispatch_queue: ObjcArc<DispatchQueue>,
    _monitor: ObjcArc<NSObject<'static>>,
}

impl NetifProvider {
    pub fn new<C: Fn() + Clone + Send + 'static>(callback: C) -> NetifProvider {
        let dispatch_queue = DispatchQueueBuilder::new()
            .label(CStr::from_bytes_with_nul(b"com.bdbai.ytflow.core.netifprovider\0").unwrap())
            .attr(DispatchQueueAttributes::SERIAL)
            .build();
        let best_if_bsd_name = Arc::new(Mutex::new(CString::new("").unwrap()));
        let monitor = unsafe { ObjcArc::from_raw(ffi::nw_path_monitor_create()) };
        unsafe {
            let monitor_ptr = &*monitor as *const _ as _;
            let best_if_bsd_name = best_if_bsd_name.clone();
            let block = block2::ConcreteBlock::new(move |path_ptr: usize| {
                unsafe {
                    let best_if_bsd_name = best_if_bsd_name.clone();
                    let enum_block = ConcreteBlock::new(move |if_ptr: usize| -> c_char {
                        unsafe {
                            let name_ptr = nw_interface_get_name(if_ptr as _);
                            *best_if_bsd_name.lock().unwrap() = CStr::from_ptr(name_ptr).to_owned();
                        }
                        false as _
                    })
                    .copy();
                    ffi::nw_path_enumerate_interfaces(
                        path_ptr as *mut _,
                        &*enum_block as *const _ as _,
                    );
                }

                callback();
            })
            .copy();
            ffi::nw_path_monitor_prohibit_interface_type(monitor_ptr, ffi::nw_interface_type_other);
            ffi::nw_path_monitor_prohibit_interface_type(
                monitor_ptr,
                ffi::nw_interface_type_loopback,
            );
            ffi::nw_path_monitor_set_update_handler(monitor_ptr, &*block as *const _ as _);
            ffi::nw_path_monitor_set_queue(monitor_ptr, &*dispatch_queue as *const _ as _);
            ffi::nw_path_monitor_start(monitor_ptr);
        };
        Self {
            best_if_bsd_name,
            _dispatch_queue: dispatch_queue,
            _monitor: monitor,
        }
    }

    fn select_bsd(name: CString) -> Netif {
        Netif {
            name: retrieve_localized_if_name(&name)
                .unwrap_or_else(|| name.to_string_lossy().to_string()),
            bsd_name: name,
        }
    }

    pub fn select(&self, name: &str) -> Option<Netif> {
        Some(Self::select_bsd(CString::new(name).ok()?))
    }

    pub fn select_best(&self) -> Option<Netif> {
        Some(Self::select_bsd(
            self.best_if_bsd_name.lock().unwrap().clone(),
        ))
    }
}

#[cfg(target_os = "ios")]
fn retrieve_localized_if_name(_bsd_name: &CStr) -> Option<String> {
    None
}
#[cfg(target_os = "macos")]
fn retrieve_localized_if_name(bsd_name: &CStr) -> Option<String> {
    unsafe {
        let netifs = ObjcArc::from_raw(ffi::SCNetworkInterfaceCopyAll());
        for idx in 0..netifs.len() {
            let netif = netifs.get_raw_unchecked(idx);
            if netif.is_null() {
                continue;
            }
            let Ok(got_bsd_name) = CStr::from_bytes_with_nul(
                (*ffi::SCNetworkInterfaceGetBSDName(netif))
                    .to_str_with_nul()
                    .as_bytes(),
            ) else {
                continue;
            };
            if bsd_name != got_bsd_name {
                continue;
            }
            return Some((*ffi::SCNetworkInterfaceGetLocalizedDisplayName(netif)).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let _provider = Arc::new_cyclic(|this| {
                let this: Weak<NetifProvider> = this.clone();
                NetifProvider::new(move || {
                    if let Some(this) = this.upgrade() {
                        println!("{:?}", this.select("en0"));
                        println!("{:?}", this.select_best());
                        let _ = tx.try_send(());
                    }
                })
            });
            let _ = rx.recv().await;
        })
    }
}
