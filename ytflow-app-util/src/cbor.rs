use thiserror::Error;

mod json;
mod raw_bytes;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CborUtilError {
    #[error("invalid CBOR or JSON encoding")]
    InvalidEncoding,
    #[error(r#"unexpected field "{0}" in raw byte representation"#)]
    UnexpectedByteReprKey(String),
    #[error("the bytes in {0} representation is invalid")]
    InvalidByteRepr(&'static str),
    #[error("missing data field for raw byte representation")]
    MissingData,
    #[error(r#"unknown byte representation "{0}""#)]
    UnknownByteRepr(String),
}

pub type CborUtilResult<T> = Result<T, CborUtilError>;

pub use json::{cbor_to_json, json_to_cbor};
pub use raw_bytes::{escape_cbor_buf, unescape_cbor_buf};
