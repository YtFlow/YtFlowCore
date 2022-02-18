use chrono::NaiveDateTime;
use rusqlite::{params, Error as SqError, OptionalExtension, Row};
use serde::Serialize;

use super::*;

pub type ProfileId = super::Id<Profile>;

#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    pub id: ProfileId,
    // TODO: uuid
    pub permanent_id: [u8; 16],
    pub name: String,
    pub locale: String,
    pub last_used_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

fn map_from_row(row: &Row) -> Result<Profile, SqError> {
    Ok(Profile {
        id: super::Id(row.get(0)?, Default::default()),
        permanent_id: {
            let row_ref = row.get_ref(1)?;
            *row_ref
                .as_blob()
                .ok()
                .and_then(|b| <&[u8; 16]>::try_from(b).ok())
                .ok_or_else(|| {
                    SqError::InvalidColumnType(1, String::from("permanent_id"), row_ref.data_type())
                })?
        },
        name: row.get(2)?,
        locale: row.get(3)?,
        last_used_at: row.get(4)?,
        created_at: row.get(5)?,
    })
}

impl Profile {
    pub fn query_by_id(id: usize, conn: &super::Connection) -> DataResult<Option<Profile>> {
        Ok(conn
            .query_row_and_then(
                r"SELECT `id`, `permanent_id`, `name`, `locale`, `last_used_at`, `created_at`
                FROM `yt_profiles` WHERE `id` = ?",
                &[&id],
                map_from_row,
            )
            .optional()?)
    }
    pub fn query_all(conn: &super::Connection) -> DataResult<Vec<Profile>> {
        let mut stmt = conn.prepare_cached("SELECT `id`, `permanent_id`, `name`, `locale`, `last_used_at`, `created_at` FROM `yt_profiles`")?;
        let ret = stmt
            .query_and_then([], map_from_row)?
            .filter_map(|r: Result<Profile, SqError>| r.ok())
            .collect();
        Ok(ret)
    }
    pub fn create(name: String, locale: String, conn: &super::Connection) -> DataResult<u32> {
        conn.execute(
            "INSERT INTO `yt_profiles` (`name`, `locale`) VALUES (?, ?)",
            [name, locale],
        )?;
        Ok(conn.last_insert_rowid() as u32)
    }
    pub fn update(
        id: u32,
        name: String,
        locale: String,
        conn: &super::Connection,
    ) -> DataResult<()> {
        conn.execute(
            "UPDATE `yt_profiles` SET `name` = ?, `locale` = ? WHERE `id` = ?",
            params![name, locale, id],
        )?;
        Ok(())
    }
    pub fn delete(id: u32, conn: &super::Connection) -> DataResult<()> {
        conn.execute("DELETE FROM `yt_profiles` WHERE `id` = ?", [id])?;
        Ok(())
    }
}
