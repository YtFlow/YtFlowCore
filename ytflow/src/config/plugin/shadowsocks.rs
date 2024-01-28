use serde_bytes::Bytes;

use crate::config::factory::*;
use crate::config::*;
use crate::plugin::shadowsocks::SupportedCipher;

#[allow(dead_code)]
pub struct ShadowsocksFactory<'de> {
    cipher: SupportedCipher,
    password: &'de [u8],
    tcp_next: &'de str,
    udp_next: &'de str,
}

pub fn parse_supported_cipher(input: &[u8]) -> Option<SupportedCipher> {
    Some(match input {
        b"none" | b"plain" => SupportedCipher::None,
        b"rc4" => SupportedCipher::Rc4,
        b"rc4-md5" => SupportedCipher::Rc4Md5,
        b"aes-128-cfb" => SupportedCipher::Aes128Cfb,
        b"aes-192-cfb" => SupportedCipher::Aes192Cfb,
        b"aes-256-cfb" => SupportedCipher::Aes256Cfb,
        b"aes-128-ctr" => SupportedCipher::Aes128Ctr,
        b"aes-192-ctr" => SupportedCipher::Aes192Ctr,
        b"aes-256-ctr" => SupportedCipher::Aes256Ctr,
        b"camellia-128-cfb" => SupportedCipher::Camellia128Cfb,
        b"camellia-192-cfb" => SupportedCipher::Camellia192Cfb,
        b"camellia-256-cfb" => SupportedCipher::Camellia256Cfb,
        b"aes-128-gcm" => SupportedCipher::Aes128Gcm,
        b"aes-256-gcm" => SupportedCipher::Aes256Gcm,
        b"chacha20-ietf" => SupportedCipher::Chacha20Ietf,
        b"chacha20-ietf-poly1305" => SupportedCipher::Chacha20IetfPoly1305,
        b"xchacha20-ietf-poly1305" => SupportedCipher::XChacha20IetfPoly1305,
        _ => return None,
    })
}

impl<'de> ShadowsocksFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { param, name, .. } = plugin;
        #[derive(Deserialize)]
        struct ShadowsocksConfig<'a> {
            method: &'a str,
            password: &'a Bytes,
            tcp_next: &'a str,
            udp_next: &'a str,
        }
        let ShadowsocksConfig {
            method,
            password,
            tcp_next,
            udp_next,
        } = parse_param(name, param)?;
        let cipher =
            parse_supported_cipher(method.as_bytes()).ok_or_else(|| ConfigError::InvalidParam {
                plugin: name.clone(),
                field: "method",
            })?;
        Ok(ParsedPlugin {
            factory: ShadowsocksFactory {
                cipher,
                password,
                tcp_next,
                udp_next,
            },
            requires: vec![
                Descriptor {
                    descriptor: tcp_next,
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: udp_next,
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
            ],
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                Descriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                },
            ],
            resources: vec![],
        })
    }
}

impl<'de> Factory for ShadowsocksFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        use crate::plugin::null::Null;
        use crate::plugin::shadowsocks::factory;

        struct FactoryReceiver<'set, 'de, 'f, 'r> {
            plugin_name: String,
            set: &'set mut PartialPluginSet<'f>,
            tcp_next: &'de str,
            udp_next: &'de str,
            result: &'r mut LoadResult<()>,
        }
        impl<'set, 'de, 'f, 'r> factory::ReceiveFactory for FactoryReceiver<'set, 'de, 'f, 'r> {
            fn receive_factory<F: factory::CreateFactory>(self, factory: F) {
                let tcp_ap = self.plugin_name.clone() + ".tcp";
                let tcp_factory = Arc::new_cyclic(|weak| {
                    self.set
                        .stream_outbounds
                        .insert(tcp_ap.clone(), weak.clone() as _);
                    let tcp_next = self
                        .set
                        .get_or_create_stream_outbound(self.plugin_name.clone(), self.tcp_next)
                        .unwrap_or_else(|e| {
                            *self.result = Err(e);
                            Arc::downgrade(&(Arc::new(Null) as _))
                        });
                    factory.create_stream_factory(tcp_next)
                });
                let udp_ap = self.plugin_name.clone() + ".udp";
                let udp_factory = Arc::new_cyclic(|weak| {
                    self.set
                        .datagram_outbounds
                        .insert(udp_ap.clone(), weak.clone() as _);
                    let udp_next = self
                        .set
                        .get_or_create_datagram_outbound(self.plugin_name, self.udp_next)
                        .unwrap_or_else(|e| {
                            *self.result = Err(e);
                            Arc::downgrade(&(Arc::new(Null) as _))
                        });
                    factory.create_datagram_session_factory(udp_next)
                });
                self.set
                    .fully_constructed
                    .stream_outbounds
                    .insert(tcp_ap, tcp_factory);
                self.set
                    .fully_constructed
                    .datagram_outbounds
                    .insert(udp_ap, udp_factory);
            }
        }
        let mut res = Ok(());
        factory::create_factory(
            self.cipher,
            self.password,
            FactoryReceiver {
                plugin_name: name,
                set,
                tcp_next: self.tcp_next,
                udp_next: self.udp_next,
                result: &mut res,
            },
        );
        if let Err(e) = res {
            set.errors.push(e);
        }
        Ok(())
    }
}
