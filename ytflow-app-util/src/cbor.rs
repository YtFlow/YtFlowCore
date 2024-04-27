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

pub(crate) fn to_cbor(
    value: Result<ciborium::Value, ciborium::value::Error>,
) -> serde_bytes::ByteBuf {
    let mut buf = Vec::with_capacity(128);
    ciborium::ser::into_writer(&value.expect("cannot encode cbor"), &mut buf)
        .expect("Cannot serialize proxy");
    serde_bytes::ByteBuf::from(buf)
}
