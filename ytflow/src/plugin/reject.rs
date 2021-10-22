use std::pin::Pin;

use crate::flow::*;

pub struct RejectHandler;

impl StreamHandler for RejectHandler {
    fn on_stream(&self, lower: Pin<Box<dyn Stream>>, _context: Box<FlowContext>) {
        drop(lower);
    }
}
