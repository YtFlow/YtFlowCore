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
            self.match_domain_impl(dst_domain),
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
        let domain_res = dst_domain.and_then(|domain| self.match_domain_impl(domain));
        // TODO: customize aggregation strategy
        let v4_res = dst_ip_v4.and_then(|ip| {
            let set = &self.dst_ipv4_ordered_set;
            let idx = set.partition_point(|(cidr, _)| ip > cidr.last_address());
            let ip_it = set
                .get(idx)
                .filter(|(cidr, _)| ip >= cidr.first_address())
                .map(|(_, rule)| *rule)
                .into_iter();
            let geoip_it = self
                .dst_geoip
                .as_ref()
                .into_iter()
                .flat_map(|geoip| geoip.query(ip.into()));
            aggregate_rules(ip_it.chain(geoip_it))
        });
        let v6_res = dst_ip_v6.and_then(|ip| {
            let set = &self.dst_ipv6_ordered_set;
            let idx = set.partition_point(|(cidr, _)| ip > cidr.last_address());
            let ip_it = set
                .get(idx)
                .filter(|(cidr, _)| ip >= cidr.first_address())
                .map(|(_, rule)| *rule)
                .into_iter();
            let geoip_it = self
                .dst_geoip
                .as_ref()
                .into_iter()
                .flat_map(|geoip| geoip.query(ip.into()));
            aggregate_rules(ip_it.chain(geoip_it))
        });
        let final_res = aggregate_rules(
            v4_res
                .into_iter()
                .chain(v6_res)
                .chain(domain_res)
                .chain(self.r#final),
        );
        final_res.map(|r| r.action())
    }
    fn match_domain_impl(&self, mut domain: &str) -> Option<RuleHandle> {
        // Safety: given domain is a valid UTF-8 sequence, it should also
        // be a valid UTF-8 sequence after stripping the trailing dot.
        if let Some(rem) = domain.as_bytes().strip_suffix(&[b'.']) {
            domain = unsafe { std::str::from_utf8_unchecked(rem) };
        }
        let full_it = self.dst_domain_full.iter().filter_map(|ac_set| {
            let matches = ac_set.ac.find_overlapping_iter(domain);
            let handle_it = matches
                .into_iter()
                .filter(|m| m.range() == (0..domain.len()))
                .map(|m| {
                    ac_set
                        .handle_map
                        .iter()
                        .find(|(range, _)| range.contains(&m.pattern().as_usize()))
                        .expect("Cannot find a matching rule for domain full")
                        .1
                });
            aggregate_rules(handle_it)
        });
        let sub_it = self.dst_domain_sub.iter().filter_map(|ac_set| {
            let matches = ac_set.ac.find_overlapping_iter(domain);
            let handle_it = matches
                .into_iter()
                .filter(|m| {
                    m.end() == domain.len()
                        && (m.start() == 0 || domain.as_bytes()[m.start() - 1] == b'.')
                })
                .map(|m| {
                    ac_set
                        .handle_map
                        .iter()
                        .find(|(range, _)| range.contains(&m.pattern().as_usize()))
                        .expect("Cannot find a matching rule for domain sub")
                        .1
                });
            aggregate_rules(handle_it)
        });
        let keyword_it = self.dst_domain_keyword.iter().filter_map(|ac_set| {
            let matches = ac_set.ac.find_overlapping_iter(domain);
            let handle_it = matches.into_iter().map(|m| {
                ac_set
                    .handle_map
                    .iter()
                    .find(|(range, _)| range.contains(&m.pattern().as_usize()))
                    .expect("Cannot find a matching rule for domain keyword")
                    .1
            });
            aggregate_rules(handle_it)
        });
        let regex_it = self.dst_domain_regex.iter().filter_map(|regex_set| {
            let matches = regex_set.regex_set.matches(domain.as_bytes());
            let handle_it = matches.into_iter().map(|m| {
                regex_set
                    .handle_map
                    .iter()
                    .find(|(range, _)| range.contains(&m))
                    .expect("Cannot find a matching rule for domain regex")
                    .1
            });
            aggregate_rules(handle_it)
        });
        aggregate_rules(
            full_it
                .chain(sub_it)
                .chain(keyword_it)
                .chain(regex_it)
                .chain(self.r#final),
        )
    }
}
