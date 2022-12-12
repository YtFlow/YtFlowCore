use std::os::fd::AsRawFd;

use super::Netif;
use super::*;

pub fn bind_socket_v4(netif: &Netif, socket: &mut socket2::Socket) -> FlowResult<()> {
    let idx = netif.get_idx()?;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            &idx as *const _ as _,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret == -1 {
        Err(std::io::Error::last_os_error())?;
    }
    Ok(())
}

pub fn bind_socket_v6(netif: &Netif, socket: &mut socket2::Socket) -> FlowResult<()> {
    let idx = netif.get_idx()?;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_BOUND_IF,
            &idx as *const _ as _,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret == -1 {
        Err(std::io::Error::last_os_error())?;
    }
    Ok(())
}
