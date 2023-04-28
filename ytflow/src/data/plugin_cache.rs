use cbor4ii::serde::{from_slice, to_vec};
use rusqlite::{params, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};

use super::{DataResult, Database, PluginId};

#[derive(Clone)]
pub struct PluginCache {
    plugin_id: PluginId,
    db: Option<Database>,
}

impl PluginCache {
    pub fn new(plugin_id: PluginId, db: Option<Database>) -> Self {
        Self { plugin_id, db }
    }

    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> DataResult<()> {
        let Some(db) = &self.db else { return Ok(()) };
        let conn = db.connect()?;
        conn.execute(
            "INSERT OR REPLACE INTO `yt_plugin_cache` (`plugin_id`, `key`, `value`) VALUES (?1, ?2, ?3)",
            params![self.plugin_id.0, key, to_vec(vec![], value).unwrap()],
        )?;
        Ok(())
    }
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> DataResult<Option<T>> {
        let Some(db) = &self.db else { return Ok(None) };
        let conn = db.connect()?;
        let ret = conn
            .query_row(
                "SELECT `value` FROM `yt_plugin_cache` WHERE `plugin_id` = ?1 AND `key` = ?2",
                params![self.plugin_id.0, key],
                |row| {
                    let value: Vec<u8> = row.get(0)?;
                    Ok(from_slice::<T>(&value).ok())
                },
            )
            .optional()?
            .flatten();
        Ok(ret)
    }
}
