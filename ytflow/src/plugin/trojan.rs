use std::sync::Weak;

use async_trait::async_trait;

use crate::flow::*;

pub struct TrojanStreamOutboundFactory {
    password_hex: [u8; 56],
    next: Weak<dyn StreamOutboundFactory>,
}

impl TrojanStreamOutboundFactory {
    pub fn new(password: &[u8], next: Weak<dyn StreamOutboundFactory>) -> Self {
        fn nibble_to_hex(n: u8) -> u8 {
            match n {
                0..=9 => n + 48,
                _ => n + 87,
            }
        }
        let hash = crypto2::hash::sha224(password);
        let mut hex = Vec::with_capacity(56);
        for x in hash {
            hex.push(nibble_to_hex(x >> 4));
            hex.push(nibble_to_hex(x & 0x0F));
        }
        Self {
            password_hex: (&*hex).try_into().unwrap(),
            next,
        }
    }
}

#[async_trait]
impl StreamOutboundFactory for TrojanStreamOutboundFactory {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let outbound_factory = self.next.upgrade().ok_or(FlowError::NoOutbound)?;

        let mut tx_handshake = Vec::with_capacity(320 + initial_data.len());
        tx_handshake.extend_from_slice(&self.password_hex);
        tx_handshake.extend_from_slice(b"\r\n\x01");
        super::shadowsocks::util::write_dest(&mut tx_handshake, &context);
        tx_handshake.extend_from_slice(b"\r\n");
        tx_handshake.extend_from_slice(initial_data);

        outbound_factory
            .create_outbound(context, &tx_handshake)
            .await
    }
}
