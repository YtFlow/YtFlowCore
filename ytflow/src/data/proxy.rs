use chrono::NaiveDateTime;
use itertools::{EitherOrBoth, Itertools};
use rusqlite::{params, Error as SqError, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use super::*;

pub type ProxyId = super::Id<Proxy>;

#[derive(Debug, Clone, Serialize)]
pub struct Proxy {
    pub id: ProxyId,
    pub name: String,
    pub order_num: i32,
    pub proxy: Vec<u8>,
    pub proxy_version: u16,
    pub updated_at: NaiveDateTime,
}

#[derive(Clone, Deserialize)]
pub struct ProxyInput {
    pub name: String,
    pub proxy: serde_bytes::ByteBuf,
    pub proxy_version: u16,
}

fn map_from_row(row: &Row) -> Result<Proxy, SqError> {
    Ok(Proxy {
        id: super::Id(row.get(0)?, Default::default()),
        name: row.get(1)?,
        order_num: row.get(2)?,
        proxy: row.get(3)?,
        proxy_version: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

fn are_proxies_equivalent(old: &Proxy, new: &ProxyInput) -> bool {
    old.name == new.name && old.proxy == *new.proxy && old.proxy_version == new.proxy_version
}

impl Proxy {
    pub fn query_all_by_group(
        proxy_group_id: ProxyGroupId,
        conn: &super::Connection,
    ) -> DataResult<Vec<Proxy>> {
        let mut stmt = conn.prepare_cached(
            r"SELECT `id`, `name`, `order_num`, `proxy`, `proxy_version`, `updated_at`
            FROM `yt_proxies` WHERE `group_id` = ? ORDER BY `order_num` ASC, `id` ASC",
        )?;
        let ret = stmt
            .query_and_then([&proxy_group_id.0], map_from_row)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ret)
    }
    pub fn create(
        group_id: ProxyGroupId,
        name: String,
        proxy: Vec<u8>,
        proxy_version: u16,
        conn: &super::Connection,
    ) -> DataResult<u32> {
        conn.execute(
            "INSERT INTO `yt_proxies` (`group_id`, `name`, `order_num`, `proxy`, `proxy_version`) VALUES (
                ?1,
                ?2,
                (SELECT IFNULL(MAX(`order_num`), 0) + 1 FROM `yt_proxies` WHERE `group_id` = ?1),
                ?3,
                ?4
            )",
            params![&group_id.0, name, proxy, proxy_version],
        )?;
        Ok(conn.last_insert_rowid() as u32)
    }
    pub fn update(
        id: u32,
        name: String,
        proxy: Vec<u8>,
        proxy_version: u16,
        conn: &super::Connection,
    ) -> DataResult<()> {
        conn.execute(
            "UPDATE `yt_proxies` SET `name` = ?, `proxy` = ?, `proxy_version` = ? WHERE `id` = ?",
            params![name, proxy, proxy_version, id],
        )?;
        Ok(())
    }
    pub fn delete(id: u32, conn: &super::Connection) -> DataResult<()> {
        conn.execute("DELETE FROM `yt_proxies` WHERE `id` = ?", [id])?;
        Ok(())
    }
    pub fn reorder(
        group_id: ProxyGroupId,
        range_start_order: i32,
        range_end_order: i32,
        moves: i32,
        conn: &mut super::Connection,
    ) -> DataResult<()> {
        if range_start_order > range_end_order {
            panic!("reordering proxies: range_start_order > range_end_order");
        }
        if moves == 0 {
            return Ok(());
        }

        let tx = conn.transaction()?;

        // Find the maximum ordernum from the group
        let max_ordernum: i32 = tx
            .prepare_cached("SELECT MAX(`order_num`) FROM `yt_proxies` WHERE `group_id` = ?")?
            .query_row([&group_id.0], |row| row.get(0))?;

        // Move the proxies in the range to the end of the group
        let range_offset = max_ordernum - range_start_order + 1;
        tx.prepare_cached("UPDATE `yt_proxies` SET `order_num` = `order_num` + ? WHERE `group_id` = ? AND `order_num` >= ? AND `order_num` <= ?")?
            .execute(params![range_offset, &group_id.0, range_start_order, range_end_order])?;

        // Find the first affected proxy
        let Some(nearest_affected_ordernum): Option<i32> = tx.prepare_cached(if moves > 0 {
            "SELECT `order_num` FROM `yt_proxies` WHERE `group_id` = ?1 AND `order_num` > ?2 ORDER BY `order_num` ASC LIMIT 1"
        } else {
            "SELECT `order_num` FROM `yt_proxies` WHERE `group_id` = ?1 AND `order_num` < ?2 ORDER BY `order_num` DESC LIMIT 1"
        })?
            .query_row(params![&group_id.0, if moves > 0 { range_start_order } else { range_end_order }], |row| row.get(0))
            .optional()? else {
                return Ok(());
            };

        // Move affected proxies to the old position
        let affected_offset = if moves > 0 {
            nearest_affected_ordernum - range_start_order
        } else {
            nearest_affected_ordernum - range_end_order
        };
        tx.prepare_cached(if moves > 0 {
            r"UPDATE `yt_proxies` SET `order_num` = `order_num` - ?1
            WHERE `group_id` = ?2 AND `order_num` IN (
                SELECT `order_num` FROM `yt_proxies` WHERE `group_id` = ?2 AND `order_num` >= ?3 ORDER BY `order_num` ASC LIMIT ?4
            )"
        } else {
            r"UPDATE `yt_proxies` SET `order_num` = `order_num` - ?1
            WHERE `group_id` = ?2 AND `order_num` IN (
                SELECT `order_num` FROM `yt_proxies` WHERE `group_id` = ?2 AND `order_num` <= ?3 ORDER BY `order_num` DESC LIMIT ?4
            )"
        })?
        .execute(params![
            affected_offset,
            &group_id.0,
            nearest_affected_ordernum,
            moves.abs()
        ])?;

        // Move the proxies in the range back to the new position
        tx.prepare_cached("UPDATE `yt_proxies` SET `order_num` = `order_num` - ? WHERE `group_id` = ? AND `order_num` > ?")?
            .execute(params![max_ordernum - nearest_affected_ordernum + 1, &group_id.0, max_ordernum])?;

        tx.commit()?;
        Ok(())
    }

    pub fn batch_update_by_group(
        proxy_group_id: ProxyGroupId,
        new_proxies: Vec<ProxyInput>,
        conn: &mut Connection,
    ) -> DataResult<()> {
        let tx = conn.transaction()?;

        let old_proxies = Self::query_all_by_group(proxy_group_id, &tx)?;
        // Delete all proxies starting from the first proxy that is not in the new list, and then insert all new proxies from that point.
        let mut zipped = old_proxies.iter().zip_longest(new_proxies);
        let mut proxy_to_insert_from = loop {
            let mut proxy_to_insert_from = None;
            let proxy_to_delete_from = match zipped.next() {
                Some(EitherOrBoth::Both(old, new)) if are_proxies_equivalent(old, &new) => continue,
                Some(EitherOrBoth::Both(old, new)) => {
                    proxy_to_insert_from = Some(EitherOrBoth::Right(new));
                    old
                }
                Some(EitherOrBoth::Left(old)) => old,
                o @ None | o @ Some(EitherOrBoth::Right(_)) => break o,
            };

            tx.execute(
                "DELETE FROM `yt_proxies` WHERE `group_id` = ?1 AND (
                `order_num` > ?2 OR
                (`order_num` = ?2 AND `id` >= ?3)
            )",
                params![
                    &proxy_group_id.0,
                    proxy_to_delete_from.order_num,
                    proxy_to_delete_from.id.0
                ],
            )?;
            break proxy_to_insert_from;
        };
        while let Some(EitherOrBoth::Right(new) | EitherOrBoth::Both(_, new)) = proxy_to_insert_from
        {
            Self::create(
                proxy_group_id,
                new.name,
                new.proxy.into_vec(),
                new.proxy_version,
                &tx,
            )?;
            proxy_to_insert_from = zipped.next();
        }

        tx.commit()?;
        Ok(())
    }
}
