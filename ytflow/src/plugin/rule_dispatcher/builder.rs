use std::sync::{Arc, Weak};

use crate::flow::Resolver;

use super::rules::geoip::GeoIpRuleMap;
use super::rules::GeoIpSet;
use super::set::RuleSet;
use super::{Action, ActionHandle, ActionSet, RuleDispatcher, RuleHandle, RuleId, ACTION_LIMIT};

#[derive(Default)]
pub struct RuleDispatcherBuilder {
    should_resolve: bool,
    actions: ActionSet,
    rule_count: RuleId,
    dst_geoip_reader: Option<maxminddb::Reader<Arc<[u8]>>>,
    dst_geoip_rules: GeoIpRuleMap,
}

impl RuleDispatcherBuilder {
    fn generate_rule_id(&mut self) -> RuleId {
        let id = self.rule_count;
        self.rule_count += 1;
        id
    }
    pub fn add_action(&mut self, action: Action) -> Option<ActionHandle> {
        if self.actions.len() >= ACTION_LIMIT {
            None
        } else {
            let handle = ActionHandle(self.actions.len() as u8);
            self.actions.push(action);
            Some(handle)
        }
    }
    pub fn load_dst_geoip(&mut self, db: Arc<[u8]>) -> Result<(), maxminddb::MaxMindDBError> {
        self.dst_geoip_reader = Some(maxminddb::Reader::from_source(db)?);
        Ok(())
    }
    pub fn add_dst_geoip_rule(
        &mut self,
        mut code: String,
        action: ActionHandle,
        should_resolve: bool,
    ) -> &mut Self {
        self.should_resolve |= should_resolve;
        let rule_id = self.generate_rule_id();
        code.make_ascii_uppercase();
        self.dst_geoip_rules
            .push((code, RuleHandle::new(action, rule_id)));
        self
    }
    pub fn build(
        self,
        resolver: Option<Weak<dyn Resolver>>,
        fallback: Action,
        me: Weak<RuleDispatcher>,
    ) -> RuleDispatcher {
        let Self {
            should_resolve,
            actions,
            dst_geoip_reader,
            dst_geoip_rules,
            ..
        } = self;
        RuleDispatcher {
            resolver,
            rule_set: RuleSet {
                should_resolve,
                dst_geoip: dst_geoip_reader.map(|reader| GeoIpSet {
                    geoip_reader: reader,
                    iso_code_rule: dst_geoip_rules,
                }),
            },
            actions,
            fallback,
            me,
        }
    }
}
