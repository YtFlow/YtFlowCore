use chrono::NaiveDateTime;
use rusqlite::{params, Error as SqError, OptionalExtension, Row};
use serde::Serialize;

use super::*;

pub type ProxyGroupId = super::Id<ProxyGroup>;

#[derive(Debug, Clone, Serialize)]
pub struct ProxyGroup {
    pub id: ProxyGroupId,
    pub name: String,
    pub r#type: String,
    pub created_at: NaiveDateTime,
}

pub const PROXY_GROUP_TYPE_MANUAL: &'static str = "manual";
pub const PROXY_GROUP_TYPE_SUBSCRIPTION: &'static str = "subscription";

fn map_from_row(row: &Row) -> Result<ProxyGroup, SqError> {
    Ok(ProxyGroup {
        id: super::Id(row.get(0)?, Default::default()),
        name: row.get(1)?,
        r#type: row.get(2)?,
        created_at: row.get(3)?,
    })
}

impl ProxyGroup {
    pub fn query_by_id(id: usize, conn: &super::Connection) -> DataResult<Option<ProxyGroup>> {
        Ok(conn
            .query_row_and_then(
                r"SELECT `id`, `name`, `type`, `created_at`
                FROM `yt_proxy_groups` WHERE `id` = ?",
                &[&id],
                map_from_row,
            )
            .optional()?)
    }
    pub fn query_all(conn: &super::Connection) -> DataResult<Vec<ProxyGroup>> {
        let mut stmt = conn.prepare_cached(
            "SELECT `id`, `name`, `type`, `created_at` FROM `yt_proxy_groups` ORDER BY `id` ASC",
        )?;
        let ret = stmt
            .query_and_then([], map_from_row)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ret)
    }
    pub fn create(name: String, r#type: String, conn: &super::Connection) -> DataResult<u32> {
        conn.execute(
            "INSERT INTO `yt_proxy_groups` (`name`, `type`) VALUES (?, ?)",
            [name, r#type],
        )?;
        Ok(conn.last_insert_rowid() as u32)
    }
    pub fn rename(id: u32, name: String, conn: &super::Connection) -> DataResult<()> {
        conn.execute(
            "UPDATE `yt_proxy_groups` SET `name` = ? WHERE `id` = ?",
            params![name, id],
        )?;
        Ok(())
    }
    pub fn delete(id: u32, conn: &super::Connection) -> DataResult<()> {
        conn.execute("DELETE FROM `yt_proxy_groups` WHERE `id` = ?", [id])?;
        Ok(())
    }
}
