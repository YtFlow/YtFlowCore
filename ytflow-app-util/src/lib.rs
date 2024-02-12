#![cfg_attr(feature = "ffi", feature(ptr_metadata))]

#[cfg(feature = "ffi")]
pub mod ffi;
pub mod proxy;
pub mod share_link;
pub mod subscription;
