use std::sync::{Arc, Weak};

mod geoip;
mod quanx_filter;
mod surge_domainset;

use crate::flow::Resolver;

use super::dispatcher::ActionSet;
use super::rules::GeoIpSet;
use super::set::RuleSet;
use super::{Action, ActionHandle, RuleDispatcher, RuleHandle, RuleId, ACTION_LIMIT};

#[derive(Default)]
pub struct RuleDispatcherBuilder {
    resolver: Option<Weak<dyn Resolver>>,
    actions: ActionSet,
}

impl RuleDispatcherBuilder {
    pub fn add_action(&mut self, action: Action) -> Option<ActionHandle> {
        if self.actions.len() >= ACTION_LIMIT {
            None
        } else {
            let handle = ActionHandle(self.actions.len() as u8);
            self.actions.push(action);
            Some(handle)
        }
    }

    pub fn set_resolver(&mut self, resolver: Option<Weak<dyn Resolver>>) {
        self.resolver = resolver;
    }

    pub fn build(
        self,
        rule_set: RuleSet,
        fallback: Action,
        me: Weak<RuleDispatcher>,
    ) -> RuleDispatcher {
        let Self { resolver, actions } = self;
        RuleDispatcher {
            resolver,
            rule_set,
            actions,
            fallback,
            me,
        }
    }
}
