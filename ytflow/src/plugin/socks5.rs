use std::sync::{Arc, Weak};

use async_trait::async_trait;

use crate::flow::*;
use crate::plugin::shadowsocks::util::{parse_dest, write_dest};

pub struct Socks5Handler {
    auth_req: Option<Arc<[u8]>>,
    next: Weak<dyn StreamHandler>,
}

pub struct Socks5Outbound {
    auth_req: Option<Buffer>,
    next: Weak<dyn StreamOutboundFactory>,
}

impl Socks5Handler {
    pub fn new(cred: Option<(&[u8], &[u8])>, next: Weak<dyn StreamHandler>) -> Self {
        let auth_req = cred.map(|cred| get_cred_req(cred).into());
        Self { auth_req, next }
    }
}

impl Socks5Outbound {
    pub fn new(cred: Option<(&[u8], &[u8])>, next: Weak<dyn StreamOutboundFactory>) -> Self {
        let auth_req = cred.map(get_cred_req);
        Self { auth_req, next }
    }
}

fn get_cred_req(cred: (&[u8], &[u8])) -> Vec<u8> {
    let mut buf = Vec::with_capacity(cred.0.len() + cred.1.len() + 2);
    buf.push(cred.0.len() as u8);
    buf.extend_from_slice(cred.0);
    buf.push(cred.1.len() as u8);
    buf.extend_from_slice(cred.1);
    buf
}

async fn serve_handshake(
    auth_req: Option<Arc<[u8]>>,
    stream: &mut dyn Stream,
) -> FlowResult<DestinationAddr> {
    let mut reader = StreamReader::new(128);
    let nauth = reader
        .read_exact(stream, 2, |buf| {
            let res = buf[1];
            if buf[0] != 0x05 {
                return Err(FlowError::UnexpectedData);
            }
            Ok(res)
        })
        .await??;
    if nauth == 0 {
        send_response(stream, &[0x05, 0xff]).await?;
        return Err(FlowError::UnexpectedData);
    }
    if let Some(auth_req) = auth_req {
        let auth_method_found = reader
            .read_exact(stream, nauth as usize, |buf| buf.iter().any(|&a| a == 0x02))
            .await?;
        if !auth_method_found {
            send_response(stream, &[0x05, 0xff]).await?;
            return Err(FlowError::UnexpectedData);
        }

        // Read auth req
        let idlen = reader
            .peek_at_least(stream, 1 + 1, |buf| {
                let idlen = buf[1];
                if buf[0] != 0x01 {
                    return Err(FlowError::UnexpectedData);
                }
                Ok(idlen)
            })
            .await?? as usize;
        let pwlen = reader
            .peek_at_least(stream, 1 + 1 + idlen + 1, |buf| {
                let pwlen = buf[1 + 1 + idlen];
                if buf[0] != 0x01 {
                    return Err(FlowError::UnexpectedData);
                }
                Ok(pwlen)
            })
            .await?? as usize;
        let req_match = reader
            .read_exact(stream, 1 + 1 + idlen + 1 + pwlen, |buf| {
                crypto2::mem::constant_time_eq(buf, &*auth_req)
            })
            .await?;
        send_response(stream, if req_match { &[0x01, 0] } else { &[0x01, 0xff] }).await?;
    } else {
        let auth_method_found = reader
            .read_exact(stream, nauth as usize, |buf| buf.iter().any(|&a| a == 0))
            .await?;
        if !auth_method_found {
            send_response(stream, &[0x05, 0xff]).await?;
            return Err(FlowError::UnexpectedData);
        }
    }

    let req_len = match reader
        .peek_at_least(stream, 5, |buf| {
            let dst_len = match buf[3] {
                1 => 4,
                3 => buf[4] + 1,
                4 => 16,
                _ => return Err(FlowError::UnexpectedData),
            } + 6;
            if buf[0] != 0x05 {
                return Err(FlowError::UnexpectedData);
            }
            Ok((buf[1], dst_len as usize))
        })
        .await?
    {
        Ok((cmd, _)) if cmd != 1 => {
            // TCP bind and UDP and is not supported yet
            send_response(stream, &[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(FlowError::UnexpectedData);
        }
        Err(_) => {
            send_response(stream, &[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(FlowError::UnexpectedData);
        }
        Ok((_, len)) => len,
    };
    let dest = reader
        .read_exact(stream, req_len, |buf| parse_dest(buf))
        .await?
        .ok_or(FlowError::UnexpectedData)?;
    send_response(stream, &[0x05, 0, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    Ok(dest)
}

async fn perform_handshake(
    context: Box<FlowContext>,
    auth_req: &Option<Buffer>,
    stream_factory: Arc<dyn StreamOutboundFactory>,
) -> FlowResult<Box<dyn Stream>> {
    let mut reader = StreamReader::new(32);
    let (mut stream, auth_accepted) = if let Some(auth_req) = auth_req {
        let mut stream = stream_factory
            .create_outbound(context.clone(), &[0x05, 0x01, 0x02])
            .await?;
        let auth_accepted = reader
            .read_exact(&mut *stream, 2, |buf| buf == &[0x05, 0x02])
            .await?;
        if !auth_accepted {
            return Err(FlowError::UnexpectedData);
        }
        send_response(&mut *stream, &auth_req).await?;
        let auth_accepted = reader
            .read_exact(&mut *stream, 2, |buf| buf == &[0x01, 0])
            .await?;
        (stream, auth_accepted)
    } else {
        let mut stream = stream_factory
            .create_outbound(context.clone(), &[0x05, 0x01, 0])
            .await?;
        let auth_accepted = reader
            .read_exact(&mut *stream, 2, |buf| buf == &[0x05, 0])
            .await?;
        (stream, auth_accepted)
    };
    if !auth_accepted {
        return Err(FlowError::UnexpectedData);
    }

    let mut req = Vec::with_capacity(300);
    req.extend([0x05, 0x01, 0]);
    write_dest(&mut req, &context);
    send_response(&mut *stream, &req).await?;
    let granted = reader
        .read_exact(&mut *stream, 2, |buf| buf != &[0x05, 0])
        .await?;
    if granted {
        let remaining = reader
            .read_exact(&mut *stream, 4, |buf| {
                Ok(match buf[1] {
                    1 => 4,
                    4 => 16,
                    3 => buf[2] as usize - 1 + 2,
                    _ => return Err(FlowError::UnexpectedData),
                })
            })
            .await??;
        reader.read_exact(&mut *stream, remaining, |_| {}).await?;
        Ok(stream)
    } else {
        Err(FlowError::UnexpectedData)
    }
}

impl StreamHandler for Socks5Handler {
    fn on_stream(&self, mut lower: Box<dyn Stream>, mut context: Box<FlowContext>) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => return,
        };
        let auth_req = self.auth_req.clone();
        tokio::spawn(async move {
            let dest = match serve_handshake(auth_req, &mut *lower).await {
                Ok(dest) => dest,
                Err(_) => return,
            };
            context.remote_peer = dest;
            next.on_stream(lower, context)
        });
    }
}

#[async_trait]
impl StreamOutboundFactory for Socks5Outbound {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<Box<dyn Stream>> {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => return Err(FlowError::UnexpectedData),
        };
        let mut stream = perform_handshake(context, &self.auth_req, next).await?;
        send_response(&mut *stream, initial_data).await?;
        Ok(stream)
    }
}

async fn send_response(lower: &mut dyn Stream, data: &[u8]) -> FlowResult<()> {
    use futures::future::poll_fn;
    let len = match data.len().try_into() {
        Ok(len) => len,
        Err(_) => return Ok(()),
    };
    let mut tx_buf = poll_fn(|cx| lower.poll_tx_buffer(cx, len)).await?;
    tx_buf.extend(data);
    lower.commit_tx_buffer(tx_buf)?;
    poll_fn(|cx| lower.poll_flush_tx(cx)).await
}
