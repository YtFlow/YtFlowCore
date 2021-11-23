use chrono::NaiveDateTime;
use rusqlite::{Error as SqError, Row};

use super::*;

pub type PluginId = super::Id<Plugin>;

#[derive(Debug, Clone)]
pub struct Plugin {
    pub id: PluginId,
    pub name: String,
    pub desc: String,
    pub plugin: String,
    pub plugin_version: u16,
    pub param: String,
    pub updated_at: NaiveDateTime,
}

fn map_from_row(row: &Row) -> Result<Plugin, SqError> {
    Ok(Plugin {
        id: super::Id(row.get(0)?, Default::default()),
        name: row.get(1)?,
        desc: row.get(2)?,
        plugin: row.get(3)?,
        plugin_version: row.get(4)?,
        param: row.get(5)?,
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
            FROM `yt_plugins` WHERE `profile_id` = ?",
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
            WHERE pep.`profile_id` = ?",
        )?;
        let ret = stmt
            .query_and_then([&profile_id.0], map_from_row)?
            .filter_map(|r: Result<Plugin, SqError>| r.ok())
            .collect();
        Ok(ret)
    }
}
