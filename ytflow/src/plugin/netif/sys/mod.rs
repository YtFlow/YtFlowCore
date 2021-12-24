#[cfg(windows)]
mod win;
#[cfg(windows)]
pub(super) use win::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(super) use linux::*;

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("Target OS does not support netif features");
