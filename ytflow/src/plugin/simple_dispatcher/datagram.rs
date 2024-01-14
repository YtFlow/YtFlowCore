use std::sync::Weak;

use super::Rule;
use crate::flow::*;

type DatagramRule = Rule<Weak<dyn DatagramSessionHandler>>;

pub struct SimpleDatagramDispatcher {
    pub rules: Vec<DatagramRule>,
    pub fallback: Weak<dyn DatagramSessionHandler>,
}

impl DatagramSessionHandler for SimpleDatagramDispatcher {
    fn on_session(&self, session: Box<dyn DatagramSession>, context: Box<FlowContext>) {
        let handler = self
            .rules
            .iter()
            .find_map(|r| r.matches(&context))
            .unwrap_or_else(|| self.fallback.clone());
        if let Some(handler) = handler.upgrade() {
            handler.on_session(session, context)
        }
    }
}
