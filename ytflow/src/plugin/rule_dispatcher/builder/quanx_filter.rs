use std::str::FromStr;
use std::{borrow::Cow, collections::BTreeMap};

use aho_corasick::AhoCorasick;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use itertools::Itertools;

use crate::plugin::rule_dispatcher::set::{IdRangeHandle, RuleMappedAhoCorasick};

use super::*;

struct QuanxDomainRule<'s> {
    domain: Cow<'s, [u8]>,
    action: ActionHandle,
}

struct QuanxIpRule<I> {
    set: I,
    action: ActionHandle,
    no_resolve: bool,
}

impl<'s> QuanxDomainRule<'s> {
    fn parse_line<'a>(
        mut segs: impl Iterator<Item = &'s str>,
        action_map: &BTreeMap<&'a str, ActionHandle>,
    ) -> Option<QuanxDomainRule<'s>> {
        let mut domain = Cow::Borrowed(segs.next()?);
        let action = action_map.get(segs.next()?)?;
        if domain.as_bytes().iter().any(|&b| b.is_ascii_uppercase()) {
            domain = Cow::Owned(domain.to_ascii_lowercase());
        }
        Some(Self {
            domain: match domain {
                Cow::Borrowed(b) => Cow::Borrowed(b.as_bytes()),
                Cow::Owned(b) => Cow::Owned(b.into_bytes()),
            },
            action: *action,
        })
    }
}

impl<I> QuanxIpRule<I> {
    fn parse_line<'s>(
        mut segs: impl Iterator<Item = &'s str>,
        mut set_parser: impl FnMut(&str) -> Option<I>,
        action_map: &BTreeMap<&str, ActionHandle>,
    ) -> Option<Self> {
        let item = set_parser(segs.next()?)?;
        let action = action_map.get(segs.next()?)?;
        let no_resolve = segs
            .next()
            .map_or(false, |s| s.eq_ignore_ascii_case("no-resolve"));
        Some(Self {
            set: item,
            action: *action,
            no_resolve,
        })
    }
}

fn push_id_range_handle_into_sorted(
    ranges: &mut Vec<IdRangeHandle>,
    idx: usize,
    handle: RuleHandle,
) {
    if let Some((idx_range, _)) = ranges
        .last_mut()
        .filter(|(_, last)| last.action() == handle.action())
    {
        *idx_range = idx_range.start..idx_range.end.max(idx + 1);
        return;
    }
    ranges.push((idx..idx + 1, handle));
}

fn build_ac_from_line_segs<'s, S: Iterator<Item = &'s str>>(
    lines: impl Iterator<Item = (RuleId, S)>,
    accepted_rule_types: &'static [&'static str],
    action_map: &BTreeMap<&str, ActionHandle>,
    rule_ranges: &mut Vec<IdRangeHandle>,
) -> Option<AhoCorasick> {
    let it = lines
        .filter_map(|(id, mut segs)| {
            let rule_type = segs.next()?;
            accepted_rule_types
                .into_iter()
                .any(|r| rule_type.eq_ignore_ascii_case(r))
                .then_some((id, segs))
        })
        .filter_map(|(id, segs)| Some((id, QuanxDomainRule::parse_line(segs, action_map)?)))
        .enumerate()
        .map(|(ac_id, (rule_id, QuanxDomainRule { domain, action }))| {
            push_id_range_handle_into_sorted(rule_ranges, ac_id, RuleHandle::new(action, rule_id));
            domain
        });
    AhoCorasick::builder().build(it).ok()
}

fn build_ip_rules_from_line_segs<'s, 'r, 'f: 'r, S: Iterator<Item = &'s str>, I>(
    lines: impl Iterator<Item = (RuleId, S)> + 'r,
    accepted_rule_types: &'static [&'static str],
    action_map: &'r BTreeMap<&str, ActionHandle>,
    mut set_parser: impl FnMut(&str) -> Option<I> + 'r,
    first_resolving_rule_id: &'f mut Option<RuleId>,
) -> impl Iterator<Item = (I, RuleHandle)> + 'r {
    lines
        .filter_map(|(id, mut segs)| {
            let rule_type = segs.next()?;
            accepted_rule_types
                .into_iter()
                .any(|r| rule_type.eq_ignore_ascii_case(r))
                .then_some((id, segs))
        })
        .filter_map(move |(id, segs)| {
            Some((
                id,
                QuanxIpRule::parse_line(segs, &mut set_parser, action_map)?,
            ))
        })
        .map(
            move |(
                rule_id,
                QuanxIpRule {
                    set,
                    action,
                    no_resolve,
                },
            )| {
                if !no_resolve {
                    *first_resolving_rule_id =
                        Some(first_resolving_rule_id.unwrap_or(rule_id).min(rule_id));
                }
                let handle = RuleHandle::new(action, rule_id);
                (set, handle)
            },
        )
}

impl RuleSet {
    pub fn load_quanx_filter<'a, 's>(
        lines: impl Iterator<Item = &'s str> + Clone,
        action_map: &BTreeMap<&'a str, ActionHandle>,
        geoip_db: Option<Arc<[u8]>>,
    ) -> Option<Self> {
        let lines = lines
            .map(|l| l.trim())
            .filter(|l| !l.starts_with(&['#', ';']) && !l.is_empty())
            .enumerate()
            .map(|(idx, l)| (idx as u32 + 1, l.split(',').map(|s| s.trim())));
        let (mut full_rule_ranges, mut sub_rule_ranges, mut keyword_rule_ranges) =
            (vec![], vec![], vec![]);
        let (full_ac, sub_ac, keyword_ac) = (
            build_ac_from_line_segs(
                lines.clone(),
                &["host", "domain"],
                action_map,
                &mut full_rule_ranges,
            )?,
            build_ac_from_line_segs(
                lines.clone(),
                &["host-suffix", "domain-suffix"],
                action_map,
                &mut sub_rule_ranges,
            )?,
            build_ac_from_line_segs(
                lines.clone(),
                &["host-keyword", "domain-keyword"],
                action_map,
                &mut keyword_rule_ranges,
            )?,
        );

        let mut first_resolving_rule_id = None;
        let mut ipv4_rules = build_ip_rules_from_line_segs(
            lines.clone(),
            &["ip-cidr"],
            action_map,
            |s| Ipv4Cidr::from_str(s).ok(),
            &mut first_resolving_rule_id,
        )
        .collect_vec();
        ipv4_rules.sort_by_key(|(cidr, handle)| (*cidr, handle.rule_id()));
        let mut ipv6_rules = build_ip_rules_from_line_segs(
            lines.clone(),
            &["ip6-cidr", "ip-cidr6"],
            action_map,
            |s| Ipv6Cidr::from_str(s).ok(),
            &mut first_resolving_rule_id,
        )
        .collect_vec();
        ipv6_rules.sort_by_key(|(cidr, handle)| (*cidr, handle.rule_id()));
        let geoip_rule_it = build_ip_rules_from_line_segs(
            lines.clone(),
            &["geoip"],
            action_map,
            |s| Some(s.to_ascii_uppercase()),
            &mut first_resolving_rule_id,
        );
        let geoip_rules = match geoip_db {
            Some(geoip_db) => Some(GeoIpSet {
                iso_code_rule: geoip_rule_it.collect(),
                geoip_reader: maxminddb::Reader::from_source(geoip_db).ok()?,
            }),
            None => {
                // Make sure side-effects (e.g. updating first_resolving_rule_id) are applied
                geoip_rule_it.for_each(|_| {});
                None
            }
        };

        let final_rule = lines
            .filter_map(|(id, mut segs)| {
                if !segs.next()?.eq_ignore_ascii_case("final") {
                    return None;
                }
                let action = action_map.get(segs.next()?)?;
                Some(RuleHandle::new(*action, id))
            })
            .next();

        Some(Self {
            dst_domain_full: Some(RuleMappedAhoCorasick {
                handle_map: full_rule_ranges,
                ac: full_ac,
            }),
            dst_domain_sub: Some(RuleMappedAhoCorasick {
                handle_map: sub_rule_ranges,
                ac: sub_ac,
            }),
            dst_domain_keyword: Some(RuleMappedAhoCorasick {
                handle_map: keyword_rule_ranges,
                ac: keyword_ac,
            }),
            dst_ipv4_ordered_set: ipv4_rules,
            dst_ipv6_ordered_set: ipv6_rules,
            dst_geoip: geoip_rules,
            r#final: final_rule,
            first_resolving_rule_id,
            ..Default::default()
        })
    }
}
