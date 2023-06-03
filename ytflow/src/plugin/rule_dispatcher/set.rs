use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{rules, ActionHandle, RuleHandle};

fn aggregate_rules(it: impl Iterator<Item = RuleHandle>) -> Option<RuleHandle> {
    it.min_by_key(|r| r.rule_id())
}

pub struct RuleSet {
    pub(super) should_resolve: bool,
    pub(super) dst_geoip: Option<rules::GeoIpSet>,
}

impl RuleSet {
    pub(super) fn should_resolve(&self) -> bool {
        self.should_resolve
    }
    pub(super) fn r#match(
        &self,
        _src: SocketAddr,
        dst_ip_v4: Option<Ipv4Addr>,
        dst_ip_v6: Option<Ipv6Addr>,
        _dst_domain: Option<&str>,
        _dst_port: u16,
    ) -> Option<ActionHandle> {
        // TODO: customize aggregation strategy
        let geoip_res = self.dst_geoip.as_ref().and_then(|geoip| {
            let v4_it = dst_ip_v4.into_iter().flat_map(|ip| geoip.query(ip.into()));
            let v6_it = dst_ip_v6.into_iter().flat_map(|ip| geoip.query(ip.into()));
            aggregate_rules(v4_it.chain(v6_it))
        });
        // TODO: chain more
        geoip_res.map(|r| r.action())
    }
    pub(super) fn match_domain(&self, _domain: &str) -> Option<ActionHandle> {
        // TODO:
        None
    }
}
