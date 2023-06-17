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

#[derive(Debug, Clone, Serialize)]
pub struct ProxySubscription {
    pub format: String,
    pub url: String,
    pub upload_bytes_used: Option<u64>,
    pub download_bytes_used: Option<u64>,
    pub bytes_total: Option<u64>,
    pub expires_at: Option<String>,
    pub retrieved_at: Option<NaiveDateTime>,
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

fn map_subscription_from_row(row: &Row) -> Result<ProxySubscription, SqError> {
    Ok(ProxySubscription {
        format: row.get(0)?,
        url: row.get(1)?,
        upload_bytes_used: row.get(2)?,
        download_bytes_used: row.get(3)?,
        bytes_total: row.get(4)?,
        expires_at: row.get(5)?,
        retrieved_at: row.get(6)?,
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
    pub fn create_subscription(
        name: String,
        format: String,
        url: String,
        conn: &mut super::Connection,
    ) -> DataResult<u32> {
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO `yt_proxy_groups` (`name`, `type`) VALUES (?, ?)",
            [&name, PROXY_GROUP_TYPE_SUBSCRIPTION],
        )?;
        let proxy_group_id = tx.last_insert_rowid() as u32;
        tx.execute(
            "INSERT INTO `yt_proxy_subscriptions` (`proxy_group_id`, `format`, `url`) VALUES (?, ?, ?)",
            params![proxy_group_id, format, url],
        )?;
        tx.commit()?;
        Ok(proxy_group_id)
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

impl ProxySubscription {
    pub fn query_by_proxy_group_id(
        proxy_group_id: u32,
        conn: &super::Connection,
    ) -> DataResult<ProxySubscription> {
        Ok(conn
            .query_row_and_then(
                r"SELECT `format`, `url`, `upload_bytes_used`, `download_bytes_used`, `bytes_total`, `expires_at`, `retrieved_at`
                FROM `yt_proxy_subscriptions` WHERE `proxy_group_id` = ?",
                &[&proxy_group_id],
                map_subscription_from_row,
            )?)
    }
    pub fn update_retrieved_by_proxy_group_id(
        proxy_group_id: u32,
        upload_bytes_used: Option<u64>,
        download_bytes_used: Option<u64>,
        bytes_total: Option<u64>,
        expires_at: Option<String>,
        conn: &super::Connection,
    ) -> DataResult<()> {
        conn.execute(
            r"UPDATE `yt_proxy_subscriptions` SET
            `upload_bytes_used` = ?,
            `download_bytes_used` = ?,
            `bytes_total` = ?,
            `expires_at` = ?,
            `retrieved_at` = (strftime('%Y-%m-%d %H:%M:%f', 'now'))
            WHERE `proxy_group_id` = ?",
            params![
                upload_bytes_used,
                download_bytes_used,
                bytes_total,
                expires_at,
                proxy_group_id
            ],
        )?;
        Ok(())
    }
}
