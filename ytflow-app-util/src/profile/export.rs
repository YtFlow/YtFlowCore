use cbor4ii::core::Value as CborValue;
use chrono::{Datelike, Timelike};
use rusqlite::Error as SqError;
use toml_edit::{
    Date as TomlDate, Datetime as TomlDatetime, DocumentMut, InlineTable, Item as TomlItem, Table,
    Time as TomlTime, Value as TomlValue,
};

use ytflow::data::{Connection as DbConnection, DataResult, ProfileId};

use crate::cbor::escape_cbor_buf;

fn encode_naive_datetime(dt: chrono::NaiveDateTime) -> TomlDatetime {
    TomlDatetime {
        date: Some(TomlDate {
            year: dt.year() as _,
            month: dt.month() as _,
            day: dt.day() as _,
        }),
        time: Some(TomlTime {
            hour: dt.hour() as _,
            minute: dt.minute() as _,
            second: dt.second() as _,
            nanosecond: dt.nanosecond() as _,
        }),
        offset: None,
    }
}

fn encode_cbor_buf(buf: &[u8]) -> TomlValue {
    let Ok(mut doc): Result<CborValue, _> = cbor4ii::serde::from_slice(buf) else {
        return TomlValue::from("!!invalid!!");
    };

    escape_cbor_buf(&mut doc);

    fn try_encode_cbor(val: &CborValue, indent: u32) -> Option<TomlValue> {
        Some(match val {
            CborValue::Null => try_encode_cbor(
                &CborValue::Map(vec![(
                    CborValue::Text("__toml_repr".into()),
                    CborValue::Text("null".into()),
                )]),
                indent + 1,
            )?,
            CborValue::Bool(b) => TomlValue::from(*b),
            CborValue::Integer(i) => TomlValue::from(*i as i64),
            CborValue::Float(f) => TomlValue::from(*f),
            CborValue::Bytes(_) => panic!("bytes in CBOR should have been escaped"),
            CborValue::Text(s) => TomlValue::from(s.as_str()),
            CborValue::Array(v) => TomlValue::Array(
                v.iter()
                    .map(|v| try_encode_cbor(v, indent + 1))
                    .collect::<Option<Vec<_>>>()?
                    .into_iter()
                    .collect(),
            ),
            CborValue::Map(kvs) => {
                let mut table: InlineTable = kvs
                    .iter()
                    .map(|(k, v)| {
                        Some((
                            match k {
                                CborValue::Text(s) => s.as_str(),
                                _ => return None,
                            },
                            try_encode_cbor(v, indent + 1)?,
                        ))
                    })
                    .collect::<Option<Vec<_>>>()?
                    .into_iter()
                    .collect();
                let is_repr = kvs.iter().any(|(k, _)| match k {
                    CborValue::Text(s) => s == "__byte_repr" || s == "__toml_repr",
                    _ => false,
                });
                table.set_dotted(!(is_repr || indent > 2));
                TomlValue::InlineTable(table)
            }
            _ => return None,
        })
    }

    match try_encode_cbor(&doc, 1) {
        Some(val) => val,
        None => "!!invalid!!".to_string().into(),
    }
}

pub fn export_profile_toml(
    profile_id: ProfileId,
    conn: &DbConnection,
) -> DataResult<Option<String>> {
    let profile = ytflow::data::Profile::query_by_id(profile_id.0 as _, conn)?
        .ok_or(SqError::QueryReturnedNoRows)?;
    let entry_plugin_names = ytflow::data::Plugin::query_entry_by_profile(profile_id, conn)?
        .into_iter()
        .map(|p| p.name);
    let plugins = ytflow::data::Plugin::query_all_by_profile(profile_id, conn)?;

    let mut doc = DocumentMut::new();
    doc.insert("version", TomlItem::Value(1i64.into()));

    let metadata_table: Table = [
        ("name", TomlValue::from(profile.name)),
        (
            "permanent_id",
            TomlValue::from(hex::encode(&profile.permanent_id)),
        ),
        ("locale", TomlValue::from(profile.locale)),
        (
            "created_at",
            TomlValue::from(encode_naive_datetime(profile.created_at)),
        ),
        (
            "entry_plugins",
            TomlValue::Array(entry_plugin_names.map(TomlValue::from).collect()),
        ),
    ]
    .into_iter()
    .collect();
    doc.insert("profile", TomlItem::Table(metadata_table));

    let plugin_tables = plugins.into_iter().map(|p| {
        let mut table: Table = [
            ("plugin", TomlValue::from(p.plugin)),
            ("plugin_version", TomlValue::from(p.plugin_version as i64)),
            ("param", encode_cbor_buf(&p.param).into()),
            ("updated_at", encode_naive_datetime(p.updated_at).into()),
        ]
        .into_iter()
        .collect();
        let mut decor = p
            .desc
            .trim()
            .lines()
            .map(|l| {
                if l.is_empty() {
                    "\n#".into()
                } else {
                    format!("\n# {}", l.trim())
                }
            })
            .collect::<Vec<_>>()
            .join("");
        decor.push_str("\n");
        table.decor_mut().set_prefix(decor);
        (p.name, table)
    });
    let mut plugin_table = Table::new();
    plugin_table.set_implicit(true);
    for (key, table) in plugin_tables {
        plugin_table.insert(&key, TomlItem::Table(table));
    }
    doc.insert("plugins", TomlItem::Table(plugin_table));

    let toml_str = doc.to_string();
    Ok(Some(toml_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    use ciborium::cbor;

    use serde_bytes::Bytes;
    use ytflow::data::{Database, Plugin, Profile};

    use crate::cbor::to_cbor;

    #[test]
    fn test_export_profile_toml() {
        let db = Database::connect_temp().unwrap();

        let profile_id = Profile::create("test".into(), "en-US".into(), &db)
            .unwrap()
            .into();

        let socks5_server_id = Plugin::create(
            profile_id,
            "socks5-server".into(),
            "SOCKS5 server".into(),
            "socks5-server".into(),
            0,
            to_cbor(cbor!({
                "user" => Bytes::new(b"user"),
                "pass" => Bytes::new(b"pass"),
                "tcp_next" => "forwarder.tcp",
                "udp_next" => "forwarder.udp",
            }))
            .into_vec(),
            &db,
        )
        .unwrap();
        Plugin::create(
            profile_id,
            "dns-dispatcher".into(),
            "Dispatches DNS requests".into(),
            "simple-dispatcher".into(),
            0,
            to_cbor(cbor!({
              "fallback_tcp" => "main-forward.tcp",
              "fallback_udp" => "main-forward.udp",
              "rules" => [
                {
                  "is_udp" => true,
                  "src" => {
                    "ip_ranges" => ["0.0.0.0/0"],
                    "port_ranges" => [{ "start" => 0, "end" => 65535 }]
                  },
                  "dst" => {
                    "ip_ranges" => ["11.16.1.1/32"],
                    "port_ranges" => [{ "start" => 53, "end" => 53 }]
                  },
                  "next" => "fakeip-dns-server.udp"
                }
              ]
            }))
            .into_vec(),
            &db,
        )
        .unwrap();
        Plugin::create(
            profile_id,
            "custom-rule-dispatcher".into(),
            "Dispatch connections \n\n based on custom rules".into(),
            "rule-dispatcher".into(),
            0,
            to_cbor(cbor!({
              "resolver" => "doh-resolver.resolver",
              "source" => "dreamacro-geoip",
              "actions" => {
                "direct" => {
                  "tcp" => "direct-forward.tcp",
                  "udp" => "direct-forward.udp",
                  "resolver" => "phy.resolver"
                },
                "reject" => {
                  "tcp" => "reject.tcp",
                  "udp" => "reject.udp",
                  "resolver" => "null.resovler"
                }
              },
              "rules" => {
                "cn" => "direct"
              },
              "fallback" => {
                "tcp" => "proxy-forward.tcp",
                "udp" => "proxy-forward.udp",
                "resolver" => "fake-ip.resolver"
              }
            }))
            .to_vec(),
            &db,
        )
        .unwrap();
        Plugin::create(
            profile_id,
            "null".into(),
            "null".into(),
            "null".into(),
            0,
            to_cbor(cbor!(null)).to_vec(),
            &db,
        )
        .unwrap();
        Plugin::create(
            profile_id,
            "invalid".into(),
            "Invalid plugin".into(),
            "socket".into(),
            0,
            vec![],
            &db,
        )
        .unwrap();

        Plugin::set_as_entry(profile_id, socks5_server_id.into(), &db).unwrap();

        db.execute("DROP TRIGGER [yt_plugins_updated]", []).unwrap();
        db.execute(
            "UPDATE `yt_profiles` SET `created_at` = '2024-04-27 09:43:17.191', `permanent_id` = x'fadd694dacc3d1c0ea7cce8077927dc5'",
            [],
        )
        .unwrap();
        db.execute(
            "UPDATE `yt_plugins` SET `updated_at` = '2024-04-27 09:43:17.191'",
            [],
        )
        .unwrap();
        let toml = export_profile_toml(profile_id, &db).unwrap().unwrap();
        assert_eq!(
            toml,
            r#"version = 1

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

# Invalid plugin
[plugins.invalid]
plugin = "socket"
plugin_version = 0
param = "!!invalid!!"
updated_at = 2024-04-27T09:43:17.191
"#,
            "{toml}"
        );
    }
}
