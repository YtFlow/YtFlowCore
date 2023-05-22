use std::sync::{atomic::Ordering, Mutex};

use cbor4ii::serde::to_vec;
use serde::Serialize;

use super::StatHandle;
use crate::control::{PluginRequestError, PluginRequestResult, PluginResponder};

#[derive(Clone, Default, Serialize, PartialEq, Eq)]
struct StatInfo {
    uplink_written: u64,
    downlink_written: u64,
    tcp_connection_count: u32,
    udp_session_count: u32,
}

pub struct Responder {
    stat: StatHandle,
    last_stat: Mutex<(StatInfo, u32)>,
}

impl Responder {
    pub fn new(stat: StatHandle) -> Self {
        Self {
            stat,
            last_stat: Mutex::new((StatInfo::default(), u32::MAX)),
        }
    }
}

fn stat_snapshot(stat: &StatHandle) -> StatInfo {
    let inner = &stat.inner;
    StatInfo {
        uplink_written: inner.uplink_written.load(Ordering::Relaxed),
        downlink_written: inner.downlink_written.load(Ordering::Relaxed),
        tcp_connection_count: inner.tcp_connection_count.load(Ordering::Relaxed),
        udp_session_count: inner.udp_session_count.load(Ordering::Relaxed),
    }
}

impl PluginResponder for Responder {
    fn collect_info(&self, hashcode: &mut u32) -> Option<Vec<u8>> {
        let stat = {
            let mut last_stat_guard = self.last_stat.lock().unwrap();
            let (last_stat, last_hashcode) = &mut *last_stat_guard;
            let new_stat = stat_snapshot(&self.stat);
            if new_stat == *last_stat {
                if *last_hashcode == *hashcode {
                    return None;
                }
            } else {
                *last_stat = new_stat.clone();
                *last_hashcode = (*last_hashcode).wrapping_add(1);
            }
            *hashcode = *last_hashcode;
            new_stat
        };
        Some(to_vec(vec![], &stat).unwrap())
    }

    fn on_request(&self, _func: &str, _params: &[u8]) -> PluginRequestResult<Vec<u8>> {
        Err(PluginRequestError::NoSuchFunc)
    }
}
