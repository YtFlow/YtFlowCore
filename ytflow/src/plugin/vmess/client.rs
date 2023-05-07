use std::sync::Weak;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use getrandom::getrandom;
use rand::prelude::*;

use super::protocol::header::*;
use super::protocol::header_client::*;
use super::protocol::{body::*, USER_ID_LEN};
use super::stream::VMessClientStream;
use crate::flow::*;

pub struct VMessStreamOutboundFactory {
    // TODO: store cmd_key
    user_id: [u8; USER_ID_LEN],
    next: Weak<dyn StreamOutboundFactory>,
}

impl VMessStreamOutboundFactory {
    pub fn new(user_id: [u8; USER_ID_LEN], next: Weak<dyn StreamOutboundFactory>) -> Self {
        Self { user_id, next }
    }
}

#[async_trait]
impl StreamOutboundFactory for VMessStreamOutboundFactory {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let next = self.next.upgrade().ok_or(FlowError::UnexpectedData)?;
        let mut tx_crypto;
        let rx_size_crypto;
        let header_dec;
        let (stream, initial_res) = {
            let mut req_buf = Vec::with_capacity(AesCfbRequestEnc::REQUIRED_SIZE);
            req_buf.resize(AesCfbRequestEnc::REQUIRED_SIZE, 0);
            let mut request = RequestHeader::default();
            request.ver = 1;
            getrandom(&mut request.data_iv).unwrap();
            getrandom(&mut request.data_key).unwrap();
            request.res_auth = rand::thread_rng().gen();
            request.opt = VMESS_HEADER_OPT_STD | VMESS_HEADER_OPT_SHAKE;
            request.set_padding_len(rand::thread_rng().gen_range(0..=0b1111));
            getrandom(request.padding_mut()).unwrap();
            request.set_encryption(VMESS_HEADER_ENC_NONE);
            request.cmd = VMESS_HEADER_CMD_TCP;
            request.port = context.remote_peer.port;
            request.addr = (&context.remote_peer.host).into();
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let (req_len, dec) = AesCfbRequestEnc::new(timestamp.as_secs(), &self.user_id)
                .encrypt_req(&mut request, &mut req_buf)
                .unwrap();
            header_dec = dec;
            req_buf.truncate(req_len);

            rx_size_crypto = ShakeSizeCrypto::new(&request.derive_res_iv_aes_cfb());

            tx_crypto = NoneClientCryptoTx::new(ShakeSizeCrypto::new(&request.data_iv));
            if !initial_data.is_empty() {
                let (pre_overhead_len, post_overhead_len) =
                    tx_crypto.calculate_overhead(initial_data.len());
                req_buf.reserve(pre_overhead_len + initial_data.len() + post_overhead_len);
                let offset = req_buf.len();
                req_buf.resize(offset + pre_overhead_len, 0);
                req_buf.extend_from_slice(initial_data);
                req_buf.resize(req_buf.len() + post_overhead_len, 0);
                let (pre_overhead, remaining) = req_buf[offset..].split_at_mut(pre_overhead_len);
                let (payload, post_overhead) = remaining.split_at_mut(initial_data.len());
                tx_crypto.seal(pre_overhead, payload, post_overhead)
            }

            next.create_outbound(context, &req_buf).await?
        };

        let reader = StreamReader::new(4096, initial_res);
        Ok((
            Box::new(VMessClientStream {
                lower: stream,
                reader,
                rx_crypto: NoneClientCryptoRx::new(rx_size_crypto, header_dec),
                rx_buf: None,
                tx_crypto,
                tx_chunks: Default::default(),
            }),
            Buffer::new(),
        ))
    }
}
