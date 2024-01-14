use std::ops::RangeInclusive;

use cidr::IpCidr;
use serde::Deserialize;
use smallvec::SmallVec;

#[cfg(feature = "plugins")]
pub mod datagram;
#[cfg(feature = "plugins")]
mod rule;
#[cfg(feature = "plugins")]
pub mod stream;

use crate::config::HumanRepr;

#[cfg(feature = "plugins")]
pub use rule::Rule;

#[derive(Clone, Deserialize)]
pub struct Condition {
    pub ip_ranges: SmallVec<[HumanRepr<IpCidr>; 2]>,
    pub port_ranges: SmallVec<[HumanRepr<RangeInclusive<u16>>; 4]>,
}
