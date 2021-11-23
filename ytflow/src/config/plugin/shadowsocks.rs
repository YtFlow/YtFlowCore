use crate::config::factory::*;
use crate::config::*;
use crate::plugin::null::Null;
use crate::plugin::shadowsocks::{self, SupportedCipher};

pub struct ShadowsocksFactory<'de> {
    cipher: SupportedCipher,
    password: &'de [u8],
    tcp_next: &'de str,
    udp_next: &'de str,
}

impl<'de> ShadowsocksFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { param, name, .. } = plugin;
        #[derive(Deserialize)]
        struct ShadowsocksConfig<'a> {
            method: &'a [u8],
            password: &'a [u8],
            tcp_next: &'a str,
            udp_next: &'a str,
        }
        let ShadowsocksConfig {
            method,
            password,
            tcp_next,
            udp_next,
        } = parse_param(param).ok_or_else(|| ConfigError::ParseParam(name.to_string()))?;
        let cipher = match method {
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
            _ => {
                return Err(ConfigError::InvalidParam {
                    plugin: name.clone(),
                    field: "method",
                })
            }
        };
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
                    r#type: AccessPointType::StreamOutboundFactory,
                },
                Descriptor {
                    descriptor: udp_next,
                    r#type: AccessPointType::DatagramSessionFactory,
                },
            ],
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::StreamOutboundFactory,
                },
                Descriptor {
                    descriptor: name.to_string() + ".udp",
                    r#type: AccessPointType::DatagramSessionFactory,
                },
            ],
        })
    }
}

impl<'de> Factory for ShadowsocksFactory<'de> {
    fn load(&mut self, name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        let Self {
            cipher,
            password,
            tcp_next,
            udp_next: _,
        } = self;
        struct FactoryReceiver<'set, 'de, 'f, 'r> {
            plugin_name: String,
            set: &'set mut PartialPluginSet<'f>,
            tcp_next: &'de str,
            result: &'r mut LoadResult<()>,
        };
        impl<'set, 'de, 'f, 'r> shadowsocks::ReceiveFactory for FactoryReceiver<'set, 'de, 'f, 'r> {
            fn receive_factory<F: shadowsocks::CreateFactory>(self, factory: F) {
                let tcp_ap = self.plugin_name.clone() + ".tcp";
                let factory = Arc::new_cyclic(|weak| {
                    self.set
                        .stream_outbounds
                        .insert(tcp_ap.clone(), (weak.clone() as _));
                    let tcp_next = self
                        .set
                        .get_or_create_stream_outbound(self.plugin_name, self.tcp_next)
                        .unwrap_or_else(|e| {
                            *self.result = Err(e);
                            Arc::downgrade(&(Arc::new(Null) as _))
                        });
                    factory.create_factory(tcp_next)
                });
                self.set
                    .fully_constructed
                    .stream_outbounds
                    .insert(tcp_ap, factory);
            }
        }
        let mut res = Ok(());
        shadowsocks::create_factory(
            self.cipher,
            self.password,
            FactoryReceiver {
                plugin_name: name,
                set,
                tcp_next,
                result: &mut res,
            },
        );
        if let Err(e) = res {
            set.errors.push(e);
        }
        Ok(())
    }
}
