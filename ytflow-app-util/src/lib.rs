#![cfg_attr(feature = "ffi", feature(ptr_metadata))]

pub mod cbor;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod proxy;
pub mod share_link;
pub mod subscription;
