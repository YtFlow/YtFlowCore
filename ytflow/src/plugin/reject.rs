use crate::flow::*;

pub struct RejectHandler;

impl StreamHandler for RejectHandler {
    fn on_stream(&self, lower: Box<dyn Stream>, _initial_data: Buffer, _context: Box<FlowContext>) {
        drop(lower);
    }
}

impl DatagramSessionHandler for RejectHandler {
    fn on_session(&self, lower: Box<dyn DatagramSession>, _context: Box<FlowContext>) {
        drop(lower);
    }
}
