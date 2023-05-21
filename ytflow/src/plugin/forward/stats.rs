use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::Arc;

#[derive(Default)]
pub struct StatInner {
    pub uplink_written: AtomicU64,
    pub downlink_written: AtomicU64,
    pub tcp_connection_count: AtomicU32,
    pub udp_session_count: AtomicU32,
}

#[derive(Clone, Default)]
pub struct StatHandle {
    pub inner: Arc<StatInner>,
}
