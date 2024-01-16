use std::sync::Weak;

#[cfg(feature = "plugins")]
mod builder;
#[cfg(feature = "plugins")]
mod dispatcher;
#[cfg(feature = "plugins")]
mod rules;
#[cfg(feature = "plugins")]
mod set;

use crate::flow::*;
#[cfg(feature = "plugins")]
pub use builder::RuleDispatcherBuilder;
#[cfg(feature = "plugins")]
pub use dispatcher::RuleDispatcher;
#[cfg(feature = "plugins")]
pub use set::RuleSet;

pub const ACTION_LIMIT: usize = 15;

// High 8 bits: ActionHandle (maximum 255 actions, but in doc we say 15)
// Low 24 bits: RuleId (maximum 16M rules, equivalent to 105 copies of SukkaW reject domain set)
#[derive(Clone, Copy, Debug)]
pub struct RuleHandle(u32);
pub type RuleId = u32;
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActionHandle(u8);

impl RuleHandle {
    pub fn new(action: ActionHandle, rule_id: RuleId) -> Self {
        Self((action.0 as u32) << 24 | (rule_id & 0x00ffffff))
    }
    pub fn action(&self) -> ActionHandle {
        ActionHandle((self.0 >> 24) as u8)
    }
    pub fn set_action(&mut self, action: ActionHandle) {
        self.0 = (self.0 & 0x00ffffff) | ((action.0 as u32) << 24);
    }
    pub fn rule_id(&self) -> RuleId {
        self.0 & 0x00ffffff
    }
    pub fn set_rule_id(&mut self, rule_id: RuleId) {
        self.0 = (self.0 & 0xff000000) | (rule_id & 0x00ffffff);
    }
}

pub struct Action {
    pub tcp_next: Weak<dyn StreamHandler>,
    pub udp_next: Weak<dyn DatagramSessionHandler>,
    pub resolver: Weak<dyn Resolver>,
}
