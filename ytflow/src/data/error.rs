use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataError {
    #[error("cannot migrate")]
    Migration(#[from] refinery::Error),
    #[error("error performing sqlite operations")]
    Database(#[from] rusqlite::Error),
    #[error("field \"{field:?}\" for \"{domain:?}\" is not valid")]
    InvalidData {
        domain: &'static str,
        field: &'static str,
    },
}

pub type DataResult<T> = Result<T, DataError>;
