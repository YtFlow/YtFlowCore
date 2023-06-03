use std::net::IpAddr;
use std::sync::Arc;

use maxminddb::geoip2;
use smallvec::SmallVec;

use crate::plugin::rule_dispatcher::RuleHandle;

pub(crate) type GeoIpRuleMap = SmallVec<[(String, RuleHandle); 2]>;

pub struct GeoIpSet {
    pub(crate) geoip_reader: maxminddb::Reader<Arc<[u8]>>,
    pub(crate) iso_code_rule: GeoIpRuleMap,
}

impl GeoIpSet {
    pub fn query(&self, ip: IpAddr) -> impl Iterator<Item = RuleHandle> {
        let country: Option<geoip2::Country> = self.geoip_reader.lookup(ip).ok();
        country
            .and_then(|c| c.country)
            .and_then(|c| c.iso_code)
            .and_then(|c| {
                self.iso_code_rule
                    .iter()
                    .find(|(rc, _)| rc == c)
                    .map(|(_, r)| *r)
            })
            .into_iter()
    }
}
