use crate::config::factory::*;
use crate::config::*;
use crate::plugin::vmess;

fn default_security() -> &'static str {
    "auto"
}

#[derive(Clone, Deserialize)]
pub struct VMessClientConfig<'a> {
    user_id: HumanRepr<uuid::Uuid>,
    #[serde(default)]
    alter_id: u16,
    #[serde(default = "default_security")]
    security: &'a str,
    tcp_next: &'a str,
}

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
pub struct VMessClientFactory<'a> {
    user_id: uuid::Uuid,
    alter_id: u16,
    security: vmess::SupportedSecurity,
    tcp_next: &'a str,
}

impl<'de> VMessClientFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: VMessClientConfig = parse_param(name, param)?;
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        let recommended_security = vmess::SupportedSecurity::Aes128Gcm;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let recommended_security = vmess::SupportedSecurity::Chacha20Poly1305;
        let security = match config.security {
            "none" => vmess::SupportedSecurity::None,
            "auto" => recommended_security,
            "aes-128-cfb" => vmess::SupportedSecurity::Aes128Cfb,
            "aes-128-gcm" => vmess::SupportedSecurity::Aes128Gcm,
            "chacha20-poly1305" => vmess::SupportedSecurity::Chacha20Poly1305,
            _ => {
                return Err(ConfigError::InvalidParam {
                    plugin: name.clone(),
                    field: "security",
                })
            }
        };
        Ok(ParsedPlugin {
            requires: vec![Descriptor {
                descriptor: config.tcp_next,
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
            }],
            provides: vec![
                Descriptor {
                    descriptor: name.to_string() + ".tcp",
                    r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
                },
                // TODO:
                // Descriptor {
                //     descriptor: name.to_string() + ".udp",
                //     r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
                // },
            ],
            factory: VMessClientFactory {
                user_id: config.user_id.inner,
                alter_id: config.alter_id,
                security,
                tcp_next: config.tcp_next,
            },
            resources: vec![],
        })
    }
}

impl<'de> Factory for VMessClientFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        use crate::plugin::null::Null;

        let factory = Arc::new_cyclic(|weak| {
            set.stream_outbounds
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            let tcp_next =
                match set.get_or_create_stream_outbound(plugin_name.clone(), self.tcp_next) {
                    Ok(t) => t,
                    Err(e) => {
                        set.errors.push(e);
                        Arc::downgrade(&(Arc::new(Null) as _))
                    }
                };
            vmess::VMessStreamOutboundFactory::new(
                *self.user_id.as_bytes(),
                self.alter_id,
                self.security,
                tcp_next,
            )
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name + ".tcp", factory);
        Ok(())
    }
}
