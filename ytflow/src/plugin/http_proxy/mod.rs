pub(crate) mod util;

use std::convert::TryInto;
use std::io::Write;
use std::pin::Pin;
use std::sync::Weak;

use async_trait::async_trait;

use crate::flow::*;

const REQ_BEFORE_ADDR: &'static [u8] = b"CONNECT ";
const REQ_AFTER_ADDR_PART: &'static [u8] = b" HTTP/1.1";
const BASIC_AUTH_HEADER: &'static [u8] = b"\r\nAuthorization: Basic ";

pub struct HttpProxyOutboundFactory {
    req_after_addr: Vec<u8>,
    next: Weak<dyn StreamOutboundFactory>,
}

impl HttpProxyOutboundFactory {
    pub fn new(
        cred: Option<(&'_ [u8], &'_ [u8])>,
        next: Weak<dyn StreamOutboundFactory>,
    ) -> HttpProxyOutboundFactory {
        fn estimate_b64_len(l: usize) -> usize {
            l * 4 / 3 + 4
        }
        let (cred_plain, auth_header) = cred
            .map(|(user, pass)| {
                let mut cred_plain = Vec::with_capacity(user.len() + pass.len() + 1);
                cred_plain.extend_from_slice(user);
                cred_plain.push(b':');
                cred_plain.extend_from_slice(pass);
                (cred_plain, BASIC_AUTH_HEADER)
            })
            .unwrap_or_default();
        let cred_plain_b64_len = estimate_b64_len(cred_plain.len());
        let mut req_after_addr = Vec::with_capacity(
            REQ_AFTER_ADDR_PART.len() + auth_header.len() + cred_plain_b64_len + 4,
        );
        req_after_addr.extend_from_slice(REQ_AFTER_ADDR_PART);
        req_after_addr.extend_from_slice(auth_header);
        {
            // Append credential
            let offset = req_after_addr.len();
            req_after_addr.resize(offset + cred_plain_b64_len, 0);
            let written = base64::encode_config_slice(
                cred_plain,
                base64::STANDARD,
                &mut req_after_addr[offset..],
            );
            req_after_addr.resize(offset + written, 0);
        }
        req_after_addr.extend_from_slice(b"\r\n\r\n");
        HttpProxyOutboundFactory {
            req_after_addr,
            next,
        }
    }
}

#[async_trait]
impl StreamOutboundFactory for HttpProxyOutboundFactory {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<Pin<Box<dyn Stream>>> {
        let outbound_factory = self.next.upgrade().ok_or(FlowError::NoOutbound)?;
        let mut next = {
            let mut req =
                Vec::with_capacity(REQ_BEFORE_ADDR.len() + 261 + self.req_after_addr.len());
            req.extend_from_slice(REQ_BEFORE_ADDR);
            match &context.remote_peer.dest {
                Destination::DomainName(domain) => req.extend_from_slice(domain.as_bytes()),
                Destination::Ip(ip) => write!(&mut req, "{}", ip).unwrap(),
            };
            req.push(b':');
            let mut port_buf = [0u8; 5];
            let port_len = util::format_u16(context.remote_peer.port, &mut port_buf);
            req.extend_from_slice(&port_buf[..port_len]);
            req.extend_from_slice(&self.req_after_addr[..]);
            outbound_factory.create_outbound(context, &req[..]).await?
        };
        {
            let size_hint = crate::get_request_size_boxed!(next)?;
            let res_buf = vec![0; size_hint.with_min_content(512)];
            next.as_mut()
                .commit_rx_buffer(res_buf, 0)
                .map_err(|(_, e)| e)?;
            let mut res_buf = crate::get_rx_buffer_boxed!(next).map_err(|(_, e)| e)?;
            let mut code;
            while {
                let mut res_headers = [httparse::EMPTY_HEADER; 4];
                let mut res = httparse::Response::new(&mut res_headers[..]);
                (
                    res.parse(&res_buf)
                        .map_err(|_| FlowError::UnexpectedData)?
                        .is_partial(),
                    code = res.code,
                )
                    .0
            } {
                let offset = res_buf.len();
                if offset > 1024 {
                    return Err(FlowError::UnexpectedData)?;
                }
                let size_hint = crate::get_request_size_boxed!(next)?.with_min_content(512);
                res_buf.resize(offset + size_hint, 0);
                next.as_mut()
                    .commit_rx_buffer(res_buf, offset)
                    .map_err(|(_, e)| e)?;
                res_buf = crate::get_rx_buffer_boxed!(next).map_err(|(_, e)| e)?;
            }
            code.filter(|c| (200..=299).contains(c))
                .ok_or(FlowError::UnexpectedData)?;
        }
        if let Some(initial_data_size) = initial_data.len().try_into().ok() {
            let (mut tx_buffer, offset) = crate::get_tx_buffer_boxed!(next, initial_data_size)?;
            tx_buffer[offset..].copy_from_slice(initial_data);
            next.as_mut().commit_tx_buffer(tx_buffer)?;
        }
        Ok(next)
    }
}
