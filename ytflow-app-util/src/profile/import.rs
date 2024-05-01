use std::{collections::BTreeSet, str::FromStr};

use cbor4ii::core::Value as CborValue;
use chrono::{DateTime, Local, NaiveDateTime};
use serde::Serialize;
use serde_bytes::ByteBuf;
use thiserror::Error;
use toml_edit::{Datetime as TomlDatetime, Item as TomlItem, Table, Value as TomlValue};

use ytflow::data::Plugin;

use crate::cbor::unescape_cbor_buf;

#[derive(Debug, Error)]
pub enum ParseTomlProfileError {
    #[error("Failed to parse TOML: {0}")]
    TomlError(#[from] toml_edit::TomlError),
    #[error(r#""{0}" is required, but is missing"#)]
    MissingInfo(String),
    #[error(r#"invalid value for field "{0}""#)]
    InvalidValue(String),
    #[error("Invalid entry points")]
    InvalidEntryPoint,
}

pub type ParseTomlProfileResult<T> = Result<T, ParseTomlProfileError>;

#[derive(Debug, Clone, Serialize)]
pub struct ParsedTomlProfile {
    pub permanent_id: Option<[u8; 16]>,
    pub name: Option<String>,
    pub locale: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub plugins: Vec<ParsedTomlPlugin>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParsedTomlPlugin {
    #[serde(flatten)]
    plugin: Plugin,
    is_entry: bool,
}

fn transform_date_time(date_time: &TomlDatetime) -> Option<NaiveDateTime> {
    if date_time.offset.is_some() {
        DateTime::<Local>::from_str(&date_time.to_string())
            .map(|dt| dt.naive_local())
            .ok()
    } else {
        date_time.to_string().parse().ok()
    }
}

fn parse_plugin_param(value: &TomlItem) -> Option<ByteBuf> {
    use TomlValue::*;
    fn try_decode_toml_value(value: &TomlValue) -> Option<CborValue> {
        Some(match value {
            String(s) => CborValue::Text(s.clone().into_value()),
            Integer(i) => CborValue::Integer(i.clone().into_value() as _),
            Float(f) => CborValue::Float(f.clone().into_value()),
            Boolean(b) => CborValue::Bool(b.clone().into_value()),
            Datetime(_) => return None,
            Array(arr) => CborValue::Array(
                arr.iter()
                    .map(try_decode_toml_value)
                    .collect::<Option<_>>()?,
            ),
            InlineTable(t) => {
                if t.get("__toml_repr").and_then(|v| v.as_str()) == Some("null") {
                    return Some(CborValue::Null);
                }
                CborValue::Map(
                    t.iter()
                        .map(|(k, v)| Some((CborValue::Text(k.into()), try_decode_toml_value(v)?)))
                        .collect::<Option<Vec<_>>>()?,
                )
            }
        })
    }
    fn try_decode_toml_item(item: &TomlItem) -> Option<CborValue> {
        Some(match item {
            TomlItem::Value(v) => try_decode_toml_value(v)?,
            TomlItem::Table(t) => CborValue::Map(
                t.iter()
                    .map(|(k, v)| Some((CborValue::Text(k.into()), try_decode_toml_item(v)?)))
                    .collect::<Option<Vec<_>>>()?,
            ),
            TomlItem::ArrayOfTables(a) => CborValue::Array(
                a.iter()
                    .map(|t| {
                        Some(CborValue::Map(
                            t.iter()
                                .map(|(k, v)| {
                                    Some((CborValue::Text(k.into()), try_decode_toml_item(v)?))
                                })
                                .collect::<Option<Vec<_>>>()?,
                        ))
                    })
                    .collect::<Option<Vec<_>>>()?,
            ),
            TomlItem::None => return None,
        })
    }
    let mut value = try_decode_toml_item(value)?;
    unescape_cbor_buf(&mut value).ok()?;
    Some(ByteBuf::from(cbor4ii::serde::to_vec(vec![], &value).ok()?))
}

pub fn parse_profile_toml(toml: &[u8]) -> ParseTomlProfileResult<ParsedTomlProfile> {
    let toml = String::from_utf8_lossy(toml);
    let doc = toml_edit::ImDocument::parse(&*toml)?;
    doc.get("version")
        .ok_or_else(|| ParseTomlProfileError::MissingInfo("version".into()))?
        .as_integer()
        .filter(|v| *v == 1)
        .ok_or_else(|| ParseTomlProfileError::InvalidValue("version".into()))?;

    let profile_table = doc
        .as_table()
        .get("profile")
        .ok_or_else(|| ParseTomlProfileError::MissingInfo("profile".into()))?
        .as_table()
        .ok_or_else(|| ParseTomlProfileError::InvalidValue("profile".into()))?;
    let permanent_id = profile_table
        .get("permanent_id")
        .map(|v| {
            v.as_str()
                .filter(|v| v.len() == 32)
                .ok_or_else(|| ParseTomlProfileError::InvalidValue("permanent_id".into()))
        })
        .transpose()?
        .map(|v| hex::decode(v))
        .transpose()
        .map_err(|_| ParseTomlProfileError::InvalidValue("permanent_id".into()))?
        .map(|v| {
            <[u8; 16]>::try_from(v.as_slice())
                .expect("the 32 bytes permanent_id should be converted to 16 bytes")
        });
    let name = profile_table.get("name").and_then(|v| v.as_str());
    let locale = profile_table.get("locale").and_then(|v| v.as_str());
    let created_at = profile_table
        .get("created_at")
        .and_then(|v| v.as_datetime())
        .and_then(transform_date_time);
    let entry_plugins_array = profile_table
        .get("entry_plugins")
        .ok_or_else(|| ParseTomlProfileError::MissingInfo("entry_plugins".into()))?
        .as_array()
        .ok_or_else(|| ParseTomlProfileError::InvalidValue("entry_plugins".into()))?;
    let mut entry_plugins = entry_plugins_array
        .iter()
        .map(|v| v.as_str())
        .collect::<Option<BTreeSet<&str>>>()
        .ok_or_else(|| ParseTomlProfileError::InvalidValue("entry_plugins".into()))?;

    let empty_plugin_table = Table::default();
    let plugins = doc
        .as_table()
        .get("plugins")
        .map(|v| {
            v.as_table()
                .ok_or_else(|| ParseTomlProfileError::InvalidValue("plugins".into()))
        })
        .transpose()?
        .map(|t| t.iter())
        .unwrap_or(empty_plugin_table.iter())
        .map(|(name, v)| {
            let plugin_table = v
                .as_table()
                .ok_or_else(|| ParseTomlProfileError::InvalidValue(name.into()))?;
            let desc = plugin_table
                .decor()
                .prefix()
                .and_then(|p| Some(unsafe { toml.get_unchecked(p.span()?) }))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.trim_start().strip_prefix('#'))
                .map(|l| l.trim())
                .collect::<Vec<_>>()
                .join("\n");
            let plugin = plugin_table
                .get("plugin")
                .ok_or_else(|| {
                    ParseTomlProfileError::MissingInfo(format!("plugins.{}.plugin", name))
                })?
                .as_str()
                .ok_or_else(|| {
                    ParseTomlProfileError::InvalidValue(format!("plugins.{}.plugin", name))
                })?;
            let plugin_version = plugin_table
                .get("plugin_version")
                .ok_or_else(|| {
                    ParseTomlProfileError::MissingInfo(format!("plugins.{}.plugin_version", name))
                })?
                .as_integer()
                .ok_or_else(|| {
                    ParseTomlProfileError::InvalidValue(format!("plugins.{}.plugin_version", name))
                })? as u16;
            let param = plugin_table.get("param").ok_or_else(|| {
                ParseTomlProfileError::MissingInfo(format!("plugins.{}.param", name))
            })?;
            let param = parse_plugin_param(param).ok_or_else(|| {
                ParseTomlProfileError::InvalidValue(format!("plugins.{}.param", name))
            })?;
            let updated_at = plugin_table
                .get("updated_at")
                .map(|v| {
                    v.as_datetime().ok_or_else(|| {
                        ParseTomlProfileError::InvalidValue(format!("plugins.{}.updated_at", name))
                    })
                })
                .transpose()?
                .and_then(transform_date_time)
                .unwrap_or_else(|| Local::now().naive_local());
            Ok(ParsedTomlPlugin {
                plugin: Plugin {
                    id: Default::default(),
                    name: name.to_owned(),
                    desc: desc.to_owned(),
                    plugin: plugin.to_owned(),
                    plugin_version,
                    param,
                    updated_at,
                },
                is_entry: entry_plugins.remove(name),
            })
        })
        .collect::<ParseTomlProfileResult<Vec<_>>>()?;

    if !entry_plugins.is_empty() {
        return Err(ParseTomlProfileError::InvalidEntryPoint);
    }

    Ok(ParsedTomlProfile {
        permanent_id,
        name: name.map(Into::into),
        locale: locale.map(Into::into),
        created_at,
        plugins,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_profile_toml() {
        let toml = br#"version = 1
[profile]
name = "test"
permanent_id = "fadd694dacc3d1c0ea7cce8077927dc5"
locale = "en-US"
created_at = 2024-04-27T09:43:17.191
entry_plugins = ["socks5-server"]

# SOCKS5 server

[plugins.socks5-server]
plugin = "socks5-server"
plugin_version = 0
param.user = { __byte_repr = "utf8", data = "user" }
param.pass = { __byte_repr = "utf8", data = "pass" }
param.tcp_next = "forwarder.tcp"
param.udp_next = "forwarder.udp"
updated_at = 2024-04-27T09:43:17.191

# Dispatches DNS requests
[plugins.dns-dispatcher]
plugin = "simple-dispatcher"
plugin_version = 0
param.fallback_tcp = "main-forward.tcp"
param.fallback_udp = "main-forward.udp"
param.rules = [{ is_udp = true, src = { ip_ranges = ["0.0.0.0/0"], port_ranges = [{ start = 0, end = 65535 }] }, dst = { ip_ranges = ["11.16.1.1/32"], port_ranges = [{ start = 53, end = 53 }] }, next = "fakeip-dns-server.udp" }]
updated_at = 2024-04-27T09:43:17.191

# Dispatch connections
#

# based on custom rules
[plugins.custom-rule-dispatcher]
plugin = "rule-dispatcher"
plugin_version = 0
param.resolver = "doh-resolver.resolver"
param.source = "dreamacro-geoip"
param.actions.direct = { tcp = "direct-forward.tcp", udp = "direct-forward.udp", resolver = "phy.resolver" }
param.actions.reject = { tcp = "reject.tcp", udp = "reject.udp", resolver = "null.resovler" }
param.rules.cn = "direct"
param.fallback.tcp = "proxy-forward.tcp"
param.fallback.udp = "proxy-forward.udp"
param.fallback.resolver = "fake-ip.resolver"
updated_at = 2024-04-27T09:43:17.191

# null
[plugins.null]
plugin = "null"
plugin_version = 0
param = { __toml_repr = "null" }
updated_at = 2024-04-27T09:43:17.191

"#;
        let parsed = parse_profile_toml(toml).unwrap();
        assert_eq!(parsed.name, Some("test".into()));
        assert_eq!(
            parsed.permanent_id,
            Some([
                0xfa, 0xdd, 0x69, 0x4d, 0xac, 0xc3, 0xd1, 0xc0, 0xea, 0x7c, 0xce, 0x80, 0x77, 0x92,
                0x7d, 0xc5
            ])
        );
        assert_eq!(parsed.locale, Some("en-US".into()));
        assert_eq!(
            parsed.created_at,
            Some("2024-04-27T09:43:17.191".parse().unwrap())
        );
        assert_eq!(parsed.plugins.len(), 4);
        assert!(parsed
            .plugins
            .iter()
            .filter(|p| p.is_entry)
            .map(|p| &*p.plugin.name)
            .eq(["socks5-server"]));

        let socks5_server = parsed
            .plugins
            .iter()
            .find(|p| p.plugin.name == "socks5-server")
            .unwrap();
        assert_eq!(socks5_server.plugin.plugin, "socks5-server");
        assert_eq!(socks5_server.plugin.plugin_version, 0);
        assert_eq!(
            cbor4ii::serde::from_slice::<CborValue>(&socks5_server.plugin.param).unwrap(),
            CborValue::Map(vec![
                (
                    CborValue::Text("user".into()),
                    CborValue::Bytes(b"user".to_vec())
                ),
                (
                    CborValue::Text("pass".into()),
                    CborValue::Bytes(b"pass".to_vec())
                ),
                (
                    CborValue::Text("tcp_next".into()),
                    CborValue::Text("forwarder.tcp".into())
                ),
                (
                    CborValue::Text("udp_next".into()),
                    CborValue::Text("forwarder.udp".into())
                ),
            ])
        );

        let dns_dispatcher = parsed
            .plugins
            .iter()
            .find(|p| p.plugin.name == "dns-dispatcher")
            .unwrap();
        assert_eq!(dns_dispatcher.plugin.plugin, "simple-dispatcher");
        assert_eq!(dns_dispatcher.plugin.plugin_version, 0);
        assert_eq!(
            cbor4ii::serde::from_slice::<CborValue>(&dns_dispatcher.plugin.param).unwrap(),
            CborValue::Map(vec![
                (
                    CborValue::Text("fallback_tcp".into()),
                    CborValue::Text("main-forward.tcp".into())
                ),
                (
                    CborValue::Text("fallback_udp".into()),
                    CborValue::Text("main-forward.udp".into())
                ),
                (
                    CborValue::Text("rules".into()),
                    CborValue::Array(vec![CborValue::Map(vec![
                        (CborValue::Text("is_udp".into()), CborValue::Bool(true)),
                        (
                            CborValue::Text("src".into()),
                            CborValue::Map(vec![
                                (
                                    CborValue::Text("ip_ranges".into()),
                                    CborValue::Array(vec![CborValue::Text("0.0.0.0/0".into())])
                                ),
                                (
                                    CborValue::Text("port_ranges".into()),
                                    CborValue::Array(vec![CborValue::Map(vec![
                                        (CborValue::Text("start".into()), CborValue::Integer(0)),
                                        (CborValue::Text("end".into()), CborValue::Integer(65535)),
                                    ])])
                                ),
                            ])
                        ),
                        (
                            CborValue::Text("dst".into()),
                            CborValue::Map(vec![
                                (
                                    CborValue::Text("ip_ranges".into()),
                                    CborValue::Array(vec![CborValue::Text("11.16.1.1/32".into())])
                                ),
                                (
                                    CborValue::Text("port_ranges".into()),
                                    CborValue::Array(vec![CborValue::Map(vec![
                                        (CborValue::Text("start".into()), CborValue::Integer(53)),
                                        (CborValue::Text("end".into()), CborValue::Integer(53)),
                                    ])])
                                ),
                            ])
                        ),
                        (
                            CborValue::Text("next".into()),
                            CborValue::Text("fakeip-dns-server.udp".into())
                        ),
                    ])])
                ),
            ])
        );

        let custom_rule_dispatcher = parsed
            .plugins
            .iter()
            .find(|p| p.plugin.name == "custom-rule-dispatcher")
            .unwrap();
        assert_eq!(
            custom_rule_dispatcher.plugin.desc,
            "Dispatch connections\n\nbased on custom rules"
        );
        assert_eq!(custom_rule_dispatcher.plugin.plugin, "rule-dispatcher");
        assert_eq!(custom_rule_dispatcher.plugin.plugin_version, 0);
        assert_eq!(
            cbor4ii::serde::from_slice::<CborValue>(&custom_rule_dispatcher.plugin.param).unwrap(),
            CborValue::Map(vec![
                (
                    CborValue::Text("resolver".into()),
                    CborValue::Text("doh-resolver.resolver".into())
                ),
                (
                    CborValue::Text("source".into()),
                    CborValue::Text("dreamacro-geoip".into())
                ),
                (
                    CborValue::Text("actions".into()),
                    CborValue::Map(vec![
                        (
                            CborValue::Text("direct".into()),
                            CborValue::Map(vec![
                                (
                                    CborValue::Text("tcp".into()),
                                    CborValue::Text("direct-forward.tcp".into())
                                ),
                                (
                                    CborValue::Text("udp".into()),
                                    CborValue::Text("direct-forward.udp".into())
                                ),
                                (
                                    CborValue::Text("resolver".into()),
                                    CborValue::Text("phy.resolver".into())
                                ),
                            ])
                        ),
                        (
                            CborValue::Text("reject".into()),
                            CborValue::Map(vec![
                                (
                                    CborValue::Text("tcp".into()),
                                    CborValue::Text("reject.tcp".into())
                                ),
                                (
                                    CborValue::Text("udp".into()),
                                    CborValue::Text("reject.udp".into())
                                ),
                                (
                                    CborValue::Text("resolver".into()),
                                    CborValue::Text("null.resovler".into())
                                ),
                            ])
                        ),
                    ])
                ),
                (
                    CborValue::Text("rules".into()),
                    CborValue::Map(vec![(
                        CborValue::Text("cn".into()),
                        CborValue::Text("direct".into())
                    )])
                ),
                (
                    CborValue::Text("fallback".into()),
                    CborValue::Map(vec![
                        (
                            CborValue::Text("tcp".into()),
                            CborValue::Text("proxy-forward.tcp".into())
                        ),
                        (
                            CborValue::Text("udp".into()),
                            CborValue::Text("proxy-forward.udp".into())
                        ),
                        (
                            CborValue::Text("resolver".into()),
                            CborValue::Text("fake-ip.resolver".into())
                        ),
                    ])
                ),
            ])
        );

        let null = parsed
            .plugins
            .iter()
            .find(|p| p.plugin.name == "null")
            .unwrap();
        assert_eq!(null.plugin.plugin, "null");
        assert_eq!(null.plugin.plugin_version, 0);
        assert_eq!(
            cbor4ii::serde::from_slice::<CborValue>(&null.plugin.param).unwrap(),
            CborValue::Null
        );
    }

    #[test]
    fn test_parse_profile_toml_minimal_profile() {
        let toml = br#"version = 1
[profile]
entry_plugins = []
        "#;
        let parsed = parse_profile_toml(toml).unwrap();
        assert_eq!(parsed.name, None);
        assert_eq!(parsed.permanent_id, None);
        assert_eq!(parsed.locale, None);
        assert_eq!(parsed.created_at, None);
        assert!(parsed.plugins.is_empty());
    }

    #[test]
    fn test_parse_profile_toml_invalid_toml() {
        let toml = br#"version = 1
[profile"#;
        let err = parse_profile_toml(toml).unwrap_err();
        assert!(matches!(err, ParseTomlProfileError::TomlError(_)));
    }

    #[test]
    fn test_parse_profile_toml_missing_info() {
        let cases: [(&[u8], &str); 6] = [
            (b"", "version"),
            (b"version = 1", "profile"),
            (
                br#"version = 1
                [profile]"#,
                "entry_plugins",
            ),
            (
                br#"
                version = 1
                [profile]
                entry_plugins = []
                [plugins.null]
                "#,
                "plugins.null.plugin",
            ),
            (
                br#"
                version = 1
                [profile]
                entry_plugins = []
                [plugins.null]
                plugin = "null"
                "#,
                "plugins.null.plugin_version",
            ),
            (
                br#"
                version = 1
                [profile]
                entry_plugins = []
                [plugins.null]
                plugin = "null"
                plugin_version = 0
                "#,
                "plugins.null.param",
            ),
        ];
        for (toml, missing) in cases {
            let err = parse_profile_toml(toml).unwrap_err();
            match &err {
                ParseTomlProfileError::MissingInfo(m) => assert_eq!(m, missing),
                _ => panic!("{missing}"),
            }
        }
    }

    #[test]
    fn test_parse_profile_toml_invalid_entry_point() {
        let toml = br#"
        version = 1
        [profile]
        name = "test"
        permanent_id = "fadd694dacc3d1c0ea7cce8077927dc5"
        locale = "en-US"
        created_at = 2024-04-27T09:43:17.191
        entry_plugins = ["nya"]

        [plugins.null]
        plugin = "null"
        plugin_version = 0
        param = { __toml_repr = "null" }
        "#;
        let err = parse_profile_toml(toml).unwrap_err();
        assert!(matches!(err, ParseTomlProfileError::InvalidEntryPoint));
    }

    #[test]
    fn test_parse_profile_toml_invalid_value() {
        let cases: [(&[u8], &str); 11] = [
            (br#"version = "aa""#, "version"),
            (
                b"version = 1
                profile = 1",
                "profile",
            ),
            (
                br#"version = 1
                [profile]
                permanent_id = 1
                "#,
                "permanent_id",
            ),
            (
                br#"version = 1
                [profile]
                permanent_id = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
                "#,
                "permanent_id",
            ),
            (
                br#"version = 1
                [profile]
                entry_plugins = 1
                "#,
                "entry_plugins",
            ),
            (
                br#"version = 1
                [profile]
                entry_plugins = [1]
                "#,
                "entry_plugins",
            ),
            (
                br#"version = 1
                plugins = 1
                [profile]
                entry_plugins = []
                "#,
                "plugins",
            ),
            (
                br#"version = 1
                [profile]
                entry_plugins = []
                [plugins.null]
                plugin = 1
                "#,
                "plugins.null.plugin",
            ),
            (
                br#"version = 1
                [profile]
                entry_plugins = []
                [plugins.null]
                plugin = "null"
                plugin_version = "0"
                "#,
                "plugins.null.plugin_version",
            ),
            (
                br#"version = 1
                [profile]
                entry_plugins = []
                [plugins.null]
                plugin = "null"
                plugin_version = 0
                param = 2024-04-27T09:43:17.191
                "#,
                "plugins.null.param",
            ),
            (
                br#"version = 1
                [profile]
                entry_plugins = []
                [plugins.null]
                plugin = "null"
                plugin_version = 0
                param = { __toml_repr = "null", data = "data" }
                updated_at = "aaa"
                "#,
                "plugins.null.updated_at",
            ),
        ];
        for (toml, invalid) in cases {
            let err = parse_profile_toml(toml).expect_err(&format!("{invalid}"));
            match &err {
                ParseTomlProfileError::InvalidValue(i) => assert_eq!(i, invalid),
                e => panic!("{invalid} {e}"),
            }
        }
    }
}
