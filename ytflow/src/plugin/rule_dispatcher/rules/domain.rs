use aho_corasick::Match;

use super::super::{set::RuleMappedAhoCorasick, RuleHandle, RuleSet};

fn match_ac<'a>(
    domain: &'a str,
    ac: &'a RuleMappedAhoCorasick,
    filter: impl FnMut(&Match) -> bool + 'a,
) -> impl Iterator<Item = RuleHandle> + 'a {
    let matches = ac.ac.find_overlapping_iter(domain);
    let handle_it = matches.into_iter().filter(filter).map(|m| {
        ac.handle_map
            .iter()
            .find(|(range, _)| range.contains(&m.pattern().as_usize()))
            .expect("Cannot find a matching rule for domain")
            .1
    });
    handle_it
}

impl RuleSet {
    pub(in super::super) fn match_domain_impl<'a>(
        &'a self,
        mut domain: &'a str,
    ) -> impl Iterator<Item = RuleHandle> + 'a {
        // Safety: given domain is a valid UTF-8 sequence, it should also
        // be a valid UTF-8 sequence after stripping the trailing dot.
        if let Some(rem) = domain.as_bytes().strip_suffix(&[b'.']) {
            domain = unsafe { std::str::from_utf8_unchecked(rem) };
        }
        let full_it = self
            .dst_domain_full
            .iter()
            .flat_map(|ac_set| match_ac(domain, ac_set, |m| m.range() == (0..domain.len())));
        let sub_it = self.dst_domain_sub.iter().flat_map(|ac_set| {
            match_ac(domain, ac_set, |m| {
                m.end() == domain.len()
                    && (m.start() == 0 || domain.as_bytes()[m.start() - 1] == b'.')
            })
        });
        let keyword_it = self
            .dst_domain_keyword
            .iter()
            .flat_map(|ac_set| match_ac(domain, ac_set, |_| true));
        let regex_it = self.dst_domain_regex.iter().flat_map(|regex_set| {
            let matches = regex_set.regex_set.matches(domain.as_bytes());
            let handle_it = matches.into_iter().map(|m| {
                regex_set
                    .handle_map
                    .iter()
                    .find(|(range, _)| range.contains(&m))
                    .expect("Cannot find a matching rule for domain regex")
                    .1
            });
            handle_it
        });
        full_it.chain(sub_it).chain(keyword_it).chain(regex_it)
    }
}
