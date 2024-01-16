use chrono::NaiveDateTime;
use rusqlite::{params, Error as SqError, OptionalExtension, Row};
use serde::Serialize;

use super::*;

pub type ResourceId = super::Id<Resource>;
pub type ResourceUrlId = super::Id<ResourceUrl>;
pub type ResourceGitHubReleaseId = super::Id<ResourceGitHubRelease>;

#[derive(Debug, Clone, Serialize)]
pub struct Resource {
    pub id: ResourceId,
    pub key: String,
    pub r#type: String,
    pub local_file: String,
    pub remote_type: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceUrl {
    pub id: ResourceUrlId,
    pub url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub retrieved_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceGitHubRelease {
    pub id: ResourceGitHubReleaseId,
    pub github_username: String,
    pub github_repo: String,
    pub asset_name: String,
    pub git_tag: Option<String>,
    pub release_title: Option<String>,
    pub retrieved_at: Option<NaiveDateTime>,
}

fn map_resource_from_row(row: &Row) -> Result<Resource, SqError> {
    Ok(Resource {
        id: super::Id(row.get(0)?, Default::default()),
        key: row.get(1)?,
        r#type: row.get(2)?,
        local_file: row.get(3)?,
        remote_type: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn map_resource_url_from_row(row: &Row) -> Result<ResourceUrl, SqError> {
    Ok(ResourceUrl {
        id: super::Id(row.get(0)?, Default::default()),
        url: row.get(1)?,
        etag: row.get(2)?,
        last_modified: row.get(3)?,
        retrieved_at: row.get(4)?,
    })
}

fn map_resource_github_release_from_row(row: &Row) -> Result<ResourceGitHubRelease, SqError> {
    Ok(ResourceGitHubRelease {
        id: super::Id(row.get(0)?, Default::default()),
        github_username: row.get(1)?,
        github_repo: row.get(2)?,
        asset_name: row.get(3)?,
        git_tag: row.get(4)?,
        release_title: row.get(5)?,
        retrieved_at: row.get(6)?,
    })
}

impl Resource {
    pub fn query_all(conn: &super::Connection) -> DataResult<Vec<Resource>> {
        let mut stmt = conn.prepare_cached(
            "SELECT `id`, `key`, `type`, `local_file`, `remote_type`, `created_at`, `updated_at` 
         FROM `yt_resources` ORDER BY `id` ASC",
        )?;
        let ret = stmt
            .query_and_then([], map_resource_from_row)?
            .filter_map(|r: Result<Resource, SqError>| r.ok())
            .collect();
        Ok(ret)
    }

    pub fn query_by_key(key: &str, conn: &super::Connection) -> DataResult<Option<Resource>> {
        let mut stmt = conn.prepare_cached(
            "SELECT `id`, `key`, `type`, `local_file`, `remote_type`, `created_at`, `updated_at` 
         FROM `yt_resources` WHERE `key` = ?",
        )?;
        let ret = stmt
            .query_and_then(params![key], map_resource_from_row)?
            .next()
            .transpose()?;
        Ok(ret)
    }

    pub fn create_with_url(
        key: String,
        r#type: String,
        local_file: String,
        url: String,
        conn: &mut super::Connection,
    ) -> DataResult<u32> {
        let tx = conn.transaction()?;
        tx.execute(
            r"INSERT INTO `yt_resources` (`key`, `type`, `local_file`, `remote_type`) VALUES (?, ?, ?, ?)",
            params![key, r#type, local_file, "url"],
        )?;
        let resource_id = tx.last_insert_rowid() as u32;
        tx.execute(
            r"INSERT INTO `yt_resources_url` (`resource_id`, `url`) VALUES (?, ?)",
            params![resource_id, url],
        )?;
        tx.commit()?;
        Ok(resource_id)
    }

    pub fn create_with_github_release(
        key: String,
        r#type: String,
        local_file: String,
        github_username: String,
        github_repo: String,
        asset_name: String,
        conn: &mut super::Connection,
    ) -> DataResult<u32> {
        let tx = conn.transaction()?;
        tx.execute(
            r"INSERT INTO `yt_resources` (`key`, `type`, `local_file`, `remote_type`) VALUES (?, ?, ?, ?)",
            params![key, r#type, local_file, "github_release"],
        )?;
        let resource_id = tx.last_insert_rowid() as u32;
        tx.execute(
            r"INSERT INTO `yt_resources_github_release` (`resource_id`, `github_username`, `github_repo`, `asset_name`) VALUES (?, ?, ?, ?)",
            params![resource_id, github_username, github_repo, asset_name],
        )?;
        tx.commit()?;
        Ok(resource_id)
    }

    pub fn delete(id: u32, conn: &super::Connection) -> DataResult<()> {
        conn.execute("DELETE FROM `yt_resources` WHERE `id` = ?", params![id])?;
        Ok(())
    }
}

impl ResourceUrl {
    pub fn query_by_resource_id(
        resource_id: u32,
        conn: &super::Connection,
    ) -> DataResult<Option<ResourceUrl>> {
        Ok(conn
            .query_row_and_then(
                r"SELECT `id`, `url`, `etag`, `last_modified`, `retrieved_at`
                FROM `yt_resources_url` WHERE `resource_id` = ?",
                [&resource_id],
                map_resource_url_from_row,
            )
            .optional()?)
    }
    pub fn update_retrieved_by_resource_id(
        resource_id: u32,
        etag: Option<String>,
        last_modified: Option<String>,
        conn: &super::Connection,
    ) -> DataResult<()> {
        conn.execute(
            r"UPDATE `yt_resources_url` SET `etag` = ?, `last_modified` = ?, `retrieved_at` = (strftime('%Y-%m-%d %H:%M:%f', 'now')) WHERE `resource_id` = ?",
            params![etag, last_modified, resource_id],
        )?;
        Ok(())
    }
}

impl ResourceGitHubRelease {
    pub fn query_by_resource_id(
        resource_id: u32,
        conn: &super::Connection,
    ) -> DataResult<Option<ResourceGitHubRelease>> {
        Ok(conn
            .query_row_and_then(
                r"SELECT `id`, `github_username`, `github_repo`, `asset_name`, `git_tag`, `release_title`, `retrieved_at`
                FROM `yt_resources_github_release` WHERE `resource_id` = ?",
                [&resource_id],
                map_resource_github_release_from_row,
            )
            .optional()?)
    }
    pub fn update_retrieved_by_resource_id(
        resource_id: u32,
        git_tag: String,
        release_title: String,
        conn: &super::Connection,
    ) -> DataResult<()> {
        conn.execute(
            r"UPDATE `yt_resources_github_release` SET `git_tag` = ?, `release_title` = ?, `retrieved_at` = (strftime('%Y-%m-%d %H:%M:%f', 'now'))
            WHERE `resource_id` = ?",
            params![git_tag, release_title, resource_id],
        )?;
        Ok(())
    }
}
