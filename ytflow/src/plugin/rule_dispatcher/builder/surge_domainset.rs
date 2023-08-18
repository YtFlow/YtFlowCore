use aho_corasick::AhoCorasick;

use crate::plugin::rule_dispatcher::set::RuleMappedAhoCorasick;

use super::*;

impl RuleSet {
    pub fn build_surge_domainset<'s>(
        lines: impl Iterator<Item = &'s str> + Clone,
        action: ActionHandle,
    ) -> Option<Self> {
        let lines = lines
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        let full_ac = AhoCorasick::builder()
            .build(lines.clone().filter(|l| !l.starts_with('.')))
            .ok()?;
        let sub_ac = AhoCorasick::builder()
            .build(lines.clone().filter_map(|l| l.strip_prefix('.')))
            .ok()?;

        // TODO: observe order
        let rule_id = 1;
        Some(Self {
            dst_domain_full: Some(RuleMappedAhoCorasick {
                handle_map: vec![(0..full_ac.patterns_len(), RuleHandle::new(action, rule_id))],
                ac: full_ac,
            }),
            dst_domain_sub: Some(RuleMappedAhoCorasick {
                handle_map: vec![(0..sub_ac.patterns_len(), RuleHandle::new(action, rule_id))],
                ac: sub_ac,
            }),
            ..Default::default()
        })
    }
}
