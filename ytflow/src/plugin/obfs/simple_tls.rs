// https://github.com/eycorsican/leaf/blob/4b4338b59fe9a35589986ed04215e4d338e49526/leaf/src/proxy/obfs/tls.rs

use std::num::NonZeroUsize;
use std::sync::{Arc, Weak};
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use getrandom::getrandom;

mod packet;
mod template;

use crate::flow::*;

const RESPONSE_HANDSHAKE_SIZE: usize = 96 /* server hello */ + 6 /* change cipher spec */;
const LEN_BUFFER_SIZE: usize = 5;
const MAX_TLS_CHUNK_SIZE: usize = 16 * 1024;

pub struct SimpleTlsOutbound {
    host: Arc<[u8]>,
    next: Weak<dyn StreamOutboundFactory>,
}

struct SimpleTlsOutboundStream {
    lower: Box<dyn Stream>,
    reader: StreamReader,
    awaiting_response: bool,
    rx_buf: Option<Buffer>,
    rx_chunk_size: NonZeroUsize,
    tx_offset: usize,
    tx_total_overhead: usize,
}

impl SimpleTlsOutbound {
    pub fn new(host: impl Into<Arc<[u8]>>, next: Weak<dyn StreamOutboundFactory>) -> Self {
        Self {
            host: host.into(),
            next,
        }
    }
}

#[async_trait]
impl StreamOutboundFactory for SimpleTlsOutbound {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let next = self.next.upgrade().ok_or(FlowError::UnexpectedData)?;
        let (stream, initial_req) = {
            let req = generate_tls_request(&self.host, initial_data);
            next.create_outbound(context, &req).await?
        };

        let reader = StreamReader::new(4096, initial_req);
        Ok((
            Box::new(SimpleTlsOutboundStream {
                lower: stream,
                reader,
                awaiting_response: true,
                rx_buf: None,
                rx_chunk_size: NonZeroUsize::new(1).unwrap(),
                tx_offset: 0,
                tx_total_overhead: 0,
            }),
            Buffer::new(),
        ))
    }
}

impl Stream for SimpleTlsOutboundStream {
    fn poll_request_size(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<SizeHint>> {
        if self.awaiting_response {
            ready!(self.reader.poll_read_exact(
                cx,
                &mut *self.lower,
                RESPONSE_HANDSHAKE_SIZE,
                |_| {}
            ))?;
            self.awaiting_response = false;
        }
        let size =
            ready!(self
                .reader
                .poll_read_exact(cx, &mut *self.lower, LEN_BUFFER_SIZE, |buf| {
                    let buf: &mut [u8; LEN_BUFFER_SIZE] = buf.try_into().unwrap();
                    u16::from_be_bytes([buf[3], buf[4]]) as usize
                }))?;
        self.rx_chunk_size = size.try_into().map_err(|_| FlowError::UnexpectedData)?;
        Poll::Ready(Ok(SizeHint::AtLeast(size)))
    }

    fn commit_rx_buffer(&mut self, buffer: Buffer) -> Result<(), (Buffer, FlowError)> {
        self.rx_buf = Some(buffer);
        Ok(())
    }

    fn poll_rx_buffer(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        let Self {
            reader,
            lower: stream,
            rx_chunk_size,
            rx_buf: rx_buffer_opt,
            ..
        } = self;
        let rx_buffer = rx_buffer_opt
            .as_mut()
            .expect("Polling rx buffer without committing");
        let res = ready!(
            reader.poll_read_exact(cx, &mut **stream, rx_chunk_size.get(), |buf| {
                rx_buffer.extend_from_slice(buf)
            })
        );
        let rx_buffer = rx_buffer_opt.take().unwrap();
        match res {
            Ok(()) => Poll::Ready(Ok(rx_buffer)),
            Err(e) => Poll::Ready(Err((rx_buffer, e))),
        }
    }

    fn poll_tx_buffer(
        &mut self,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<Buffer>> {
        let chunk_count = (size.get() + MAX_TLS_CHUNK_SIZE - 1) / MAX_TLS_CHUNK_SIZE;
        self.tx_total_overhead = chunk_count * LEN_BUFFER_SIZE;
        let mut buf = ready!(self.lower.as_mut().poll_tx_buffer(
            cx,
            (size.get() + self.tx_total_overhead).try_into().unwrap()
        ))?;
        // Reserve size for all headers. If the payload fits into one chunk, we don't need to relocate.
        self.tx_offset = buf.len();
        buf.resize(buf.len() + self.tx_total_overhead, 0);
        Poll::Ready(Ok(buf))
    }

    fn commit_tx_buffer(&mut self, mut buffer: Buffer) -> FlowResult<()> {
        let mut payload_offset = self.tx_offset + self.tx_total_overhead;
        while payload_offset < buffer.len() {
            let chunk_size = (buffer.len() - payload_offset).min(MAX_TLS_CHUNK_SIZE);
            *<&mut [u8; LEN_BUFFER_SIZE]>::try_from(
                &mut buffer[self.tx_offset..self.tx_offset + LEN_BUFFER_SIZE],
            )
            .unwrap() = generate_header(chunk_size as u16);
            self.tx_offset += LEN_BUFFER_SIZE;
            buffer.copy_within(payload_offset..payload_offset + chunk_size, self.tx_offset);
            self.tx_offset += chunk_size;
            payload_offset += chunk_size;
        }
        self.lower.commit_tx_buffer(buffer)
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.poll_flush_tx(cx)
    }

    fn poll_close_tx(&mut self, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.poll_close_tx(cx)
    }
}

fn generate_tls_request(host: &[u8], payload: &[u8]) -> Vec<u8> {
    use std::mem::{size_of_val, transmute};
    use std::time::SystemTime;

    let mut hello = template::CLIENT_HELLO;
    let mut server_name = template::EXT_SERVER_NAME;
    let mut ticket = template::EXT_SESSION_TICKET;
    let other = template::EXT_OTHERS;
    let total_len = payload.len()
        + size_of_val(&hello)
        + size_of_val(&server_name)
        + host.len()
        + size_of_val(&ticket)
        + size_of_val(&other);

    hello.0.len = (total_len as u16 - 5).to_be();
    hello.0.handshake_len_2 = (total_len as u16 - 9).to_be();
    hello.0.random_unix_time = (SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32)
        .to_be();
    getrandom(&mut hello.0.random_bytes).unwrap();
    getrandom(&mut hello.0.session_id).unwrap();
    hello.0.ext_len = ((total_len - size_of_val(&hello)) as u16).to_be();
    ticket.0.session_ticket_ext_len = (payload.len() as u16).to_be();
    server_name.0.ext_len = (host.len() as u16 + 3 + 2).to_be();
    server_name.0.server_name_list_len = (host.len() as u16 + 3).to_be();
    server_name.0.server_name_len = (host.len() as u16).to_be();

    let mut req = Vec::with_capacity(total_len);
    unsafe {
        req.extend_from_slice(&transmute::<_, [u8; 138]>(hello));
        req.extend_from_slice(&transmute::<_, [u8; 4]>(ticket));
        req.extend_from_slice(payload);
        req.extend_from_slice(&transmute::<_, [u8; 9]>(server_name));
        req.extend_from_slice(host);
        req.extend_from_slice(&transmute::<_, [u8; 66]>(other));
    }
    req
}

fn generate_header(payload_len: u16) -> [u8; LEN_BUFFER_SIZE] {
    let mut tls_data_header = [
        0x17, 0x03, 0x03, /* 2 bytes of len goes here */ 0x00, 0x00,
    ];
    tls_data_header[3] = payload_len.to_be_bytes()[0];
    tls_data_header[4] = payload_len.to_be_bytes()[1];
    tls_data_header
}
