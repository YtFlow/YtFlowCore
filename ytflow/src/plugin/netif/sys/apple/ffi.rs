#![allow(non_upper_case_globals, non_camel_case_types)]

use std::ffi::c_char;

use fruity::objc::NSObject;
// https://github.com/AstroHQ/astro-dnssd/blob/c5b3d6957cb5b4f63d841fa1f20808d758a7c583/src/ffi/apple.rs
use libc::{c_uint, sockaddr};

pub type DNSServiceRef = *mut ();
pub type DNSServiceFlags = u32;
pub type DNSServiceProtocol = u32;
pub type DNSServiceErrorType = i32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct dispatch_queue_s {
    pub _address: u8,
}
pub type nw_path_monitor = NSObject<'static>;
pub type dispatch_queue_t = *mut dispatch_queue_s;
pub type nw_path_monitor_t = *mut nw_path_monitor;
pub type nw_path_monitor_update_handler_t = *const (); // To be converted from &Block<_, _>
pub type nw_path_enumerate_interface_handler_t = *const (); // To be converted fro &Block<_, _>
pub type nw_path = NSObject<'static>;
pub type nw_path_t = *mut nw_path;
pub type nw_interface = NSObject<'static>;
pub type nw_interface_t = *mut nw_interface;
pub type nw_interface_type_t = c_uint;

pub const kDNSServiceProtocol_IPv4: DNSServiceProtocol = 1;
pub const kDNSServiceProtocol_IPv6: DNSServiceProtocol = 2;
pub const kDNSServiceFlagsMoreComing: DNSServiceFlags = 0x1;
pub const kDNSServiceFlagsAdd: DNSServiceFlags = 0x2;
pub const kDNSServiceFlagsTimeout: DNSServiceFlags = 0x10000;
pub const kDNSServiceFlagsReturnIntermediates: DNSServiceFlags = 0x1000;
pub const kDNSServiceErr_NoSuchRecord: DNSServiceErrorType = -65554;
pub const nw_interface_type_other: nw_interface_type_t = 0;
pub const nw_interface_type_loopback: nw_interface_type_t = 4;

pub type DNSServiceGetAddrInfoReply = ::std::option::Option<
    unsafe extern "C" fn(
        sdRef: DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        errorCode: DNSServiceErrorType,
        hostname: *const ::std::os::raw::c_char,
        address: *const sockaddr,
        ttl: u32,
        context: *mut ::std::os::raw::c_void,
    ),
>;

#[link(name = "network", kind = "framework")]
extern "C" {
    pub fn DNSServiceGetAddrInfo(
        sdRef: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interfaceIndex: u32,
        protocol: DNSServiceProtocol,
        hostname: *const ::std::os::raw::c_char,
        callBack: DNSServiceGetAddrInfoReply,
        context: *mut ::std::os::raw::c_void,
    ) -> DNSServiceErrorType;
    pub fn DNSServiceSetDispatchQueue(
        service: DNSServiceRef,
        queue: dispatch_queue_t,
    ) -> DNSServiceErrorType;
    pub fn DNSServiceRefDeallocate(sdRef: DNSServiceRef);

    pub fn nw_path_monitor_create() -> nw_path_monitor_t;
    pub fn nw_path_monitor_set_queue(monitor: nw_path_monitor_t, queue: dispatch_queue_t);
    pub fn nw_path_monitor_prohibit_interface_type(
        monitor: nw_path_monitor_t,
        interface_type: nw_interface_type_t,
    );
    pub fn nw_path_monitor_set_update_handler(
        monitor: nw_path_monitor_t,
        callback: nw_path_monitor_update_handler_t,
    );
    pub fn nw_path_monitor_start(monitor: nw_path_monitor_t);
    // pub fn nw_path_monitor_cancel(monitor: nw_path_monitor_t);
    pub fn nw_path_enumerate_interfaces(
        path: nw_path_t,
        enumerate_block: nw_path_enumerate_interface_handler_t,
    );
    pub fn nw_interface_get_name(interface: nw_interface_t) -> *const c_char;
}
