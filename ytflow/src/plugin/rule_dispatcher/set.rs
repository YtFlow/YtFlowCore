use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;

use aho_corasick::AhoCorasick;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use regex::bytes::RegexSet;

use super::{rules, ActionHandle, RuleHandle, RuleId};

fn aggregate_rules(it: impl Iterator<Item = RuleHandle>) -> Option<RuleHandle> {
    it.min_by_key(|r| r.rule_id())
}

pub(super) type IdRangeHandle = (Range<usize>, RuleHandle);

pub(super) struct RuleMappedRegexSet {
    pub(super) handle_map: Vec<IdRangeHandle>,
    pub(super) regex_set: RegexSet,
}

pub(super) struct RuleMappedAhoCorasick {
    pub(super) handle_map: Vec<IdRangeHandle>,
    pub(super) ac: AhoCorasick,
}

#[derive(Default)]
pub struct RuleSet {
    pub(super) dst_domain_regex: Option<RuleMappedRegexSet>,
    pub(super) dst_domain_full: Option<RuleMappedAhoCorasick>,
    pub(super) dst_domain_sub: Option<RuleMappedAhoCorasick>,
    pub(super) dst_domain_keyword: Option<RuleMappedAhoCorasick>,
    pub(super) dst_geoip: Option<rules::GeoIpSet>,
    pub(super) dst_ipv4_ordered_set: Vec<(Ipv4Cidr, RuleHandle)>,
    pub(super) dst_ipv6_ordered_set: Vec<(Ipv6Cidr, RuleHandle)>,
    pub(super) r#final: Option<RuleHandle>,
    pub(super) first_resolving_rule_id: Option<RuleId>,
}

impl RuleSet {
    pub fn should_resolve(
        &self,
        _src: Option<SocketAddr>,
        dst_domain: &str,
        _dst_port: Option<u16>,
    ) -> bool {
        match (
            self.first_resolving_rule_id,
            aggregate_rules(self.match_domain_impl(dst_domain).chain(self.r#final)),
        ) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(first_resolving_id), Some(rule)) => rule.rule_id() >= first_resolving_id,
        }
    }
    pub fn r#match(
        &self,
        _src: Option<SocketAddr>,
        dst_ip_v4: Option<Ipv4Addr>,
        dst_ip_v6: Option<Ipv6Addr>,
        dst_domain: Option<&str>,
        _dst_port: Option<u16>,
    ) -> Option<ActionHandle> {
        let min_rule_id = if let (Some(_), Some(_), _) | (Some(_), _, Some(_)) =
            (&dst_domain, &dst_ip_v4, &dst_ip_v6)
        {
            // The domain name has been resolved to IP addresses. Skip all rules that do not require DNS resolution.
            self.first_resolving_rule_id.unwrap_or_default()
        } else {
            Default::default()
        };
        let min_rule_id_filter = |rule: &RuleHandle| rule.rule_id() >= min_rule_id;
        // TODO: customize aggregation strategy
        let domain_res = aggregate_rules(
            dst_domain
                .into_iter()
                .flat_map(|domain| self.match_domain_impl(domain))
                .filter(min_rule_id_filter),
        );
        let v4_res = dst_ip_v4.and_then(|ip| {
            let ip_it = self.match_ipv4_impl(ip);
            let geoip_it = self
                .dst_geoip
                .as_ref()
                .into_iter()
                .flat_map(|geoip| geoip.query(ip.into()));
            aggregate_rules(ip_it.chain(geoip_it).filter(min_rule_id_filter))
        });
        let v6_res = dst_ip_v6.and_then(|ip| {
            let ip_it = self.match_ipv6_impl(ip);
            let geoip_it = self
                .dst_geoip
                .as_ref()
                .into_iter()
                .flat_map(|geoip| geoip.query(ip.into()));
            aggregate_rules(ip_it.chain(geoip_it).filter(min_rule_id_filter))
        });
        let final_res = aggregate_rules(
            v4_res
                .into_iter()
                .chain(v6_res)
                .chain(domain_res)
                .chain(self.r#final.filter(min_rule_id_filter)),
        );
        final_res.map(|r| r.action())
    }
}
