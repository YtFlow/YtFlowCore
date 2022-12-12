#[cfg(windows)]
mod win;
#[cfg(windows)]
pub(super) use win::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(super) use linux::*;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
pub(super) use apple::*;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos", target_os = "ios")))]
compile_error!("Target OS does not support netif features");
