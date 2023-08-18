use itertools::Itertools;

use super::*;

impl RuleSet {
    pub fn build_dst_geoip_rule(
        code_action_mapping: impl Iterator<Item = (String, ActionHandle)>,
        geoip_db: Arc<[u8]>,
    ) -> Option<Self> {
        let rule_id = 1;

        Some(Self {
            dst_geoip: Some(GeoIpSet {
                iso_code_rule: code_action_mapping
                    .map(|(mut code, action)| {
                        code.make_ascii_uppercase();
                        (code, RuleHandle::new(action, rule_id))
                    })
                    .dedup_by(|(code1, _), (code2, _)| code1 == code2)
                    .collect(),
                geoip_reader: maxminddb::Reader::from_source(geoip_db).ok()?,
            }),
            first_resolving_rule_id: Some(rule_id),
            ..Default::default()
        })
    }
}
