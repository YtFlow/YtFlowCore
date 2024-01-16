use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::future::Future;
use std::sync::Arc;

use thiserror::Error;

use crate::data::{self, Connection};

pub const RESOURCE_TYPE_GEOIP_COUNTRY: &str = "geoip-country";
pub const RESOURCE_TYPE_SURGE_DOMAINSET: &str = "surge-domain-set";
pub const RESOURCE_TYPE_QUANX_FILTER: &str = "quanx-filter";

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("cannot find the resource in the registry")]
    NotFound,
    #[error("IO error")]
    IoError(#[from] std::io::Error),
    #[error("Database error")]
    DataError(#[from] crate::data::DataError),
    #[error("content is requested before the file is loaded")]
    NotLoaded,
    #[error("invalid data")]
    InvalidData,
}

pub type ResourceResult<T> = Result<T, ResourceError>;

#[derive(Clone)]
pub struct ResourceHandle {
    handle: String,
}

#[derive(Clone)]
pub struct ResourceMetadata {
    pub handle: ResourceHandle,
    pub r#type: String,
}

pub trait ResourceRegistry {
    fn query_metadata(&'_ self, key: &str) -> ResourceResult<&'_ ResourceMetadata>;
    fn query_bytes(&self, handle: &ResourceHandle) -> ResourceResult<Arc<[u8]>>;
}

pub trait FileResourceLoader {
    fn load_file(&self, local_name: &str) -> ResourceResult<fs::File>;
}

pub struct EmptyResourceRegistry;

impl ResourceRegistry for EmptyResourceRegistry {
    fn query_metadata(&'_ self, _key: &str) -> ResourceResult<&'_ ResourceMetadata> {
        Err(ResourceError::NotFound)
    }
    fn query_bytes(&self, _handle: &ResourceHandle) -> ResourceResult<Arc<[u8]>> {
        Err(ResourceError::NotFound)
    }
}

pub struct DbFileResourceLoader {
    metadatas: BTreeMap<String, ResourceMetadata>,
    registered_handles_for_bytes: BTreeMap<String, Option<Arc<[u8]>>>,
}

impl DbFileResourceLoader {
    pub fn new_with_required_keys(
        keys: BTreeSet<String>,
        conn: &Connection,
    ) -> ResourceResult<Self> {
        let mut all_resources = data::Resource::query_all(conn)?;
        let metadatas: BTreeMap<_, _> = keys
            .into_iter()
            .filter_map(|k| {
                all_resources.iter_mut().find(|r| r.key == k).map(|r| {
                    (
                        k,
                        ResourceMetadata {
                            handle: ResourceHandle {
                                handle: std::mem::take(&mut r.local_file),
                            },
                            r#type: std::mem::take(&mut r.r#type),
                        },
                    )
                })
            })
            .collect();
        let registered_handles_for_bytes = metadatas
            .values()
            .map(|m| (m.handle.handle.clone(), None))
            .collect();
        Ok(Self {
            metadatas,
            registered_handles_for_bytes,
        })
    }
}

impl DbFileResourceLoader {
    pub fn load_required_files<'a>(
        &'a mut self,
        file_loader: &'a (impl FileResourceLoader + Sync),
    ) -> impl Iterator<Item = impl Future<Output = ResourceResult<()>> + Send + 'a> {
        self.registered_handles_for_bytes
            .iter_mut()
            .filter(|(_, b)| b.is_none())
            .map(move |(handle, bytes)| {
                use tokio::io::AsyncReadExt;
                async move {
                    let mut file = tokio::fs::File::from_std(file_loader.load_file(handle)?);
                    let mut buf = Vec::new();
                    file.read_to_end(&mut buf).await?;
                    *bytes = Some(buf.into());
                    Ok(())
                }
            })
    }
}

impl ResourceRegistry for DbFileResourceLoader {
    fn query_metadata(&'_ self, key: &str) -> ResourceResult<&'_ ResourceMetadata> {
        self.metadatas.get(key).ok_or(ResourceError::NotFound)
    }

    fn query_bytes(&self, handle: &ResourceHandle) -> ResourceResult<Arc<[u8]>> {
        match self
            .registered_handles_for_bytes
            .get(handle.handle.as_str())
        {
            Some(Some(bytes)) => Ok(bytes.clone()),
            Some(None) => Err(ResourceError::NotLoaded),
            None => Err(ResourceError::NotFound),
        }
    }
}
