use chrono::NaiveDateTime;
use rusqlite::{params, Error as SqError, Row};
use serde::Serialize;

use super::*;

pub type PluginId = super::Id<Plugin>;

#[derive(Debug, Clone, Serialize)]
pub struct Plugin {
    pub id: PluginId,
    pub name: String,
    pub desc: String,
    pub plugin: String,
    pub plugin_version: u16,
    pub param: serde_bytes::ByteBuf,
    pub updated_at: NaiveDateTime,
}

fn map_from_row(row: &Row) -> Result<Plugin, SqError> {
    Ok(Plugin {
        id: super::Id(row.get(0)?, Default::default()),
        name: row.get(1)?,
        desc: row.get(2)?,
        plugin: row.get(3)?,
        plugin_version: row.get(4)?,
        param: serde_bytes::ByteBuf::from(row.get::<_, Vec<u8>>(5)?),
        updated_at: row.get(6)?,
    })
}

impl Plugin {
    pub fn query_all_by_profile(
        profile_id: super::ProfileId,
        conn: &super::Connection,
    ) -> DataResult<Vec<Plugin>> {
        let mut stmt = conn.prepare_cached(
            r"SELECT `id`, `name`, `desc`, `plugin`, `plugin_version`, `param`, `updated_at`
            FROM `yt_plugins` WHERE `profile_id` = ? ORDER BY `id` ASC",
        )?;
        let ret = stmt
            .query_and_then([&profile_id.0], map_from_row)?
            .filter_map(|r: Result<Plugin, SqError>| r.ok())
            .collect();
        Ok(ret)
    }
    pub fn query_entry_by_profile(
        profile_id: super::ProfileId,
        conn: &super::Connection,
    ) -> DataResult<Vec<Plugin>> {
        let mut stmt = conn.prepare_cached(
            r"SELECT `id`, `name`, `desc`, `plugin`, `plugin_version`, `param`, `updated_at`
            FROM `yt_profile_entry_plugin` pep
            INNER JOIN `yt_plugins` p ON pep.`plugin_id` = p.`id`
            WHERE pep.`profile_id` = ?
            ORDER BY `id` ASC",
        )?;
        let ret = stmt
            .query_and_then([&profile_id.0], map_from_row)?
            .filter_map(|r: Result<Plugin, SqError>| r.ok())
            .collect();
        Ok(ret)
    }
    pub fn create(
        profile_id: super::ProfileId,
        name: String,
        desc: String,
        plugin: String,
        plugin_version: u16,
        param: Vec<u8>,
        conn: &super::Connection,
    ) -> DataResult<u32> {
        conn.execute(
            "INSERT INTO `yt_plugins` (`profile_id`, `name`, `desc`, `plugin`, `plugin_version`, `param`) VALUES (?, ?, ?, ?, ?, ?)",
            params![profile_id.0, name, desc, plugin, plugin_version, param],
        )?;
        Ok(conn.last_insert_rowid() as _)
    }
    pub fn set_as_entry(
        profile_id: super::ProfileId,
        plugin_id: PluginId,
        conn: &super::Connection,
    ) -> DataResult<()> {
        conn.execute(
            "INSERT INTO `yt_profile_entry_plugin` (`profile_id`, `plugin_id`) VALUES (?, ?)",
            params![profile_id.0, plugin_id.0],
        )?;
        Ok(())
    }
    pub fn unset_as_entry(
        profile_id: super::ProfileId,
        plugin_id: PluginId,
        conn: &super::Connection,
    ) -> DataResult<()> {
        conn.execute(
            "DELETE FROM `yt_profile_entry_plugin` WHERE `profile_id` = ? AND `plugin_id` = ?",
            params![profile_id.0, plugin_id.0],
        )?;
        Ok(())
    }
    pub fn update(
        id: u32,
        profile_id: super::ProfileId,
        name: String,
        desc: String,
        plugin: String,
        plugin_version: u16,
        param: Vec<u8>,
        conn: &super::Connection,
    ) -> DataResult<()> {
        conn.execute(
            "UPDATE `yt_plugins` SET `profile_id` = ?, `name` = ?, `desc` = ?, `plugin` = ?, `plugin_version` = ?, `param` = ? WHERE `id` = ?",
            params![profile_id.0, name, desc, plugin, plugin_version, param, id],
        )?;
        Ok(())
    }
    pub fn delete(id: u32, conn: &super::Connection) -> DataResult<()> {
        conn.execute("DELETE FROM `yt_plugins` WHERE `id` = ?", [id])?;
        Ok(())
    }
}

impl From<Plugin> for crate::config::Plugin {
    fn from(value: Plugin) -> Self {
        Self {
            id: Some(value.id),
            name: value.name,
            plugin: value.plugin,
            plugin_version: value.plugin_version,
            param: value.param.into_vec(),
        }
    }
}
