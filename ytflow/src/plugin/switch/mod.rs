mod responder;

use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;

pub use responder::Choice;
pub use responder::Responder;

use crate::flow::*;

pub struct CurrentChoice {
    pub idx: u32,
    pub tcp_next: Arc<dyn StreamHandler>,
    pub udp_next: Arc<dyn DatagramSessionHandler>,
}

pub struct Switch {
    pub current_choice: ArcSwap<CurrentChoice>,
}

impl StreamHandler for Switch {
    fn on_stream(&self, lower: Box<dyn Stream>, initial_data: Buffer, context: Box<FlowContext>) {
        self.current_choice
            .load()
            .tcp_next
            .on_stream(lower, initial_data, context);
    }
}

impl DatagramSessionHandler for Switch {
    fn on_session(&self, session: Box<dyn DatagramSession>, context: Box<FlowContext>) {
        self.current_choice
            .load()
            .udp_next
            .on_session(session, context);
    }
}
