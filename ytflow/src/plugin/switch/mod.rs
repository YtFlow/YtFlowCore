pub mod responder;

use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;

pub use responder::Choice;
pub use responder::Responder;

use crate::flow::*;

pub struct CurrentChoice {
    pub idx: u32,
    pub tcp_next: Weak<dyn StreamHandler>,
    pub udp_next: Weak<dyn DatagramSessionHandler>,
}

pub struct Switch {
    pub current_choice: ArcSwap<CurrentChoice>,
}

impl StreamHandler for Switch {
    fn on_stream(&self, lower: Box<dyn Stream>, initial_data: Buffer, context: Box<FlowContext>) {
        let Some(tcp_next) = self.current_choice.load().tcp_next.upgrade() else {
            return;
        };
        tcp_next.on_stream(lower, initial_data, context);
    }
}

impl DatagramSessionHandler for Switch {
    fn on_session(&self, session: Box<dyn DatagramSession>, context: Box<FlowContext>) {
        let Some(udp_next) = self.current_choice.load().udp_next.upgrade() else {
            return;
        };
        udp_next.on_session(session, context);
    }
}
