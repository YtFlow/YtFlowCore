use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataError {
    #[error("cannot migrate")]
    Migration(Box<refinery::Error>),
    #[error("error performing sqlite operations")]
    Database(Box<rusqlite::Error>),
    #[error("field \"{field:?}\" for \"{domain:?}\" is not valid")]
    InvalidData {
        domain: &'static str,
        field: &'static str,
    },
}

impl From<refinery::Error> for DataError {
    fn from(e: refinery::Error) -> Self {
        DataError::Migration(Box::new(e))
    }
}

impl From<rusqlite::Error> for DataError {
    fn from(e: rusqlite::Error) -> Self {
        DataError::Database(Box::new(e))
    }
}

pub type DataResult<T> = Result<T, DataError>;
