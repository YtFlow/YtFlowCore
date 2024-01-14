use std::sync::Weak;

use super::Rule;
use crate::flow::*;

type StreamRule = Rule<Weak<dyn StreamHandler>>;

pub struct SimpleStreamDispatcher {
    pub rules: Vec<StreamRule>,
    pub fallback: Weak<dyn StreamHandler>,
}

impl StreamHandler for SimpleStreamDispatcher {
    fn on_stream(&self, lower: Box<dyn Stream>, initial_data: Buffer, context: Box<FlowContext>) {
        let handler = self
            .rules
            .iter()
            .find_map(|r| r.matches(&context))
            .unwrap_or_else(|| self.fallback.clone());
        if let Some(handler) = handler.upgrade() {
            handler.on_stream(lower, initial_data, context)
        }
    }
}
