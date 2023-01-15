use std::sync::{Arc, Weak};

use async_trait::async_trait;
use base64::prelude::*;
use memchr::memmem;
use rand::{thread_rng, RngCore};

use crate::flow::*;

pub struct SimpleHttpHandler {
    server_line: Arc<[u8]>,
    next: Weak<dyn StreamHandler>,
}

pub struct SimpleHttpOutbound {
    req_line: Arc<[u8]>,
    next: Weak<dyn StreamOutboundFactory>,
}

impl SimpleHttpHandler {
    pub fn new(next: Weak<dyn StreamHandler>) -> Self {
        let mut server_line = Vec::with_capacity(60);
        server_line.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.");
        let mut thread_rng = thread_rng();
        server_line.extend_from_slice((thread_rng.next_u32() % 11).to_string().as_bytes());
        server_line.push(b'.');
        server_line.extend_from_slice((thread_rng.next_u32() % 12).to_string().as_bytes());
        server_line.extend_from_slice(b"\r\nDate: ");
        Self {
            server_line: server_line.into(),
            next,
        }
    }
}

impl SimpleHttpOutbound {
    pub fn new(path: &[u8], host: &[u8], next: Weak<dyn StreamOutboundFactory>) -> Self {
        let mut req_line = Vec::with_capacity(120 + path.len() + host.len());
        req_line.extend_from_slice(b"GET ");
        req_line.extend_from_slice(path);
        req_line.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        req_line.extend_from_slice(host);
        req_line.extend_from_slice(b"\r\nUser-Agent: curl/7.");
        let mut thread_rng = thread_rng();
        req_line.extend_from_slice((thread_rng.next_u32() % 51).to_string().as_bytes());
        req_line.push(b'.');
        req_line.extend_from_slice((thread_rng.next_u32() % 2).to_string().as_bytes());
        req_line.extend_from_slice(
            b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-Websocket-Key: ",
        );
        Self {
            req_line: req_line.into(),
            next,
        }
    }
}

impl StreamHandler for SimpleHttpHandler {
    fn on_stream(
        &self,
        mut lower: Box<dyn Stream>,
        initial_data: Buffer,
        context: Box<FlowContext>,
    ) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => return,
        };
        let server_line = self.server_line.clone();
        tokio::spawn(async move {
            let mut res = crate::get_tx_buffer_boxed!(lower, 255.try_into().unwrap())?;
            res.extend_from_slice(&server_line);
            res.extend_from_slice(chrono::Utc::now().to_rfc2822().as_bytes());
            // "+0000" => "GMT"
            res.drain(res.len() - 5..);
            res.extend_from_slice(
                b"GMT\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-Websocket-Accept: ",
            );

            let mut reader = StreamReader::new(4096, initial_data);
            let mut expected_header_size = 1;
            let mut req_body_pos = 0;
            let mut on_data = |data: &mut [u8]| {
                if data.len() > 1024 {
                    return Err(FlowError::UnexpectedData);
                }

                if let Some(pos) = memmem::find(data, b"\r\n\r\n") {
                    req_body_pos = pos + 4;
                    let ws_key_pos = memmem::find(&data[..pos], b"Sec-Websocket-Key:")
                        .ok_or(FlowError::UnexpectedData)?;
                    let ws_key_end_pos = memmem::find(&data[ws_key_pos..pos], b"\r\n")
                        .ok_or(FlowError::UnexpectedData)?;
                    if ws_key_end_pos - ws_key_pos > 32 {
                        return Err(FlowError::UnexpectedData);
                    }
                    let ws_key = std::str::from_utf8(&data[(ws_key_pos + 18)..ws_key_end_pos])
                        .map_err(|_| FlowError::UnexpectedData)?
                        .trim();
                    res.extend_from_slice(ws_key.as_bytes());
                    Ok(None)
                } else {
                    Ok(Some(data.len()))
                }
            };
            while let Some(read_len) = reader
                .peek_at_least(&mut *lower, expected_header_size, &mut on_data)
                .await??
            {
                expected_header_size = read_len + 1;
            }
            reader.advance(req_body_pos);
            let initial_req = reader.into_buffer().unwrap_or_default();

            res.extend_from_slice(b"\r\n\r\n");

            lower.commit_tx_buffer(res)?;
            next.on_stream(lower, initial_req, context);
            FlowResult::Ok(())
        });
    }
}

#[async_trait]
impl StreamOutboundFactory for SimpleHttpOutbound {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => return Err(FlowError::UnexpectedData),
        };
        let (mut stream, initial_req) = {
            let mut req = Vec::with_capacity(self.req_line.len() + 120);
            req.extend_from_slice(&self.req_line);
            let mut ws_key = [0; 16];
            thread_rng().fill_bytes(&mut ws_key);
            let mut b64 = [0; 32];
            let b64_len = BASE64_URL_SAFE
                .encode_slice(&ws_key, &mut b64)
                .expect("A base64 repr of 16 bytes should not exceed 32 chars");
            req.extend_from_slice(&b64[..b64_len]);
            req.extend_from_slice(b"\r\nContent-Length: ");
            req.extend_from_slice(initial_data.len().to_string().as_bytes());
            req.extend_from_slice(b"\r\n\r\n");
            req.extend_from_slice(initial_data);
            next.create_outbound(context, &req).await?
        };

        let initial_res = {
            let mut reader = StreamReader::new(4096, initial_req);
            let mut expected_header_size = 1;
            let mut req_body_pos = 0;
            let mut on_data = |data: &mut [u8]| {
                if data.len() > 1024 {
                    return Err(FlowError::UnexpectedData);
                }

                Ok(match memmem::find(data, b"\r\n\r\n") {
                    Some(p) => (req_body_pos = p + 4, None).1,
                    None => Some(data.len()),
                })
            };
            while let Some(read_len) = reader
                .peek_at_least(&mut *stream, expected_header_size, &mut on_data)
                .await??
            {
                expected_header_size = read_len + 1;
            }
            reader.advance(req_body_pos);
            reader.into_buffer().unwrap_or_default()
        };

        Ok((stream, initial_res))
    }
}
