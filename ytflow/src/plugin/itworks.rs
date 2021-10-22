use std::convert::TryInto;
use std::pin::Pin;

use futures::future::poll_fn;

use crate::flow::context::FlowContext;
use crate::flow::result::FlowResult;
use crate::flow::stream::{SizeHint, Stream, StreamHandler};
use crate::{get_rx_buffer_boxed, get_tx_buffer_boxed};

pub struct ItWorks;

const RESPONSE: &'static [u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 2333\r\n\r\nIt works!!!\r\n";

async fn handle_stream(mut stream: Pin<Box<dyn Stream>>) -> FlowResult<()> {
    let req_size = match poll_fn(|cx| stream.as_mut().poll_request_size(cx)).await? {
        SizeHint::Unknown { overhead } => overhead + 1024,
        SizeHint::AtLeast(s) => std::cmp::max(s, 1024),
    };
    let rx_buf = vec![0; req_size];
    let _ = stream.as_mut().commit_rx_buffer(rx_buf, 0);
    let mut total = 2333 + RESPONSE.len() - 13;
    if let Ok(buf) = get_rx_buffer_boxed!(stream) {
        let str = String::from_utf8_lossy(&buf);
        println!("Received: {}", str);
        if str.contains("favicon") {
            total = RESPONSE.len();
        }
    };
    while total > 0 {
        let write_len = std::cmp::min(total, RESPONSE.len().try_into().unwrap());
        let mut buf = get_tx_buffer_boxed!(stream, write_len.try_into().unwrap())?;
        buf.truncate(write_len);
        buf[..write_len].copy_from_slice(&RESPONSE[..write_len]);
        stream.as_mut().commit_tx_buffer(buf, 0).unwrap();
        total -= write_len;
    }
    stream.as_mut().close_tx().await;
    Ok(())
}

impl StreamHandler for ItWorks {
    fn on_stream(&self, lower: Pin<Box<dyn Stream>>, _context: Box<FlowContext>) {
        tokio::spawn(handle_stream(lower));
    }
}
