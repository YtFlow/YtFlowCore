use std::net::{Ipv4Addr, Ipv6Addr};

use cidr::Cidr;

use super::super::{RuleHandle, RuleSet};

fn match_ip_rules<'a, A: cidr::Address + 'a>(
    set: &'a [(A::Cidr, RuleHandle)],
    ip: A,
) -> impl Iterator<Item = RuleHandle> + 'a {
    let idx = set.partition_point(|(cidr, _)| ip > cidr.last_address());
    set[idx..]
        .iter()
        .take_while(move |(cidr, _)| ip >= cidr.first_address())
        .filter(move |(cidr, _)| ip <= cidr.last_address())
        .map(|(_, rule)| *rule)
}

impl RuleSet {
    pub(in super::super) fn match_ipv4_impl(
        &self,
        ip: Ipv4Addr,
    ) -> impl Iterator<Item = RuleHandle> + '_ {
        match_ip_rules(&self.dst_ipv4_ordered_set, ip)
    }
    pub(in super::super) fn match_ipv6_impl(
        &self,
        ip: Ipv6Addr,
    ) -> impl Iterator<Item = RuleHandle> + '_ {
        match_ip_rules(&self.dst_ipv6_ordered_set, ip)
    }
}
