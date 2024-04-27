use serde_bytes::ByteBuf;

pub mod plugins;
pub mod profiles;
pub mod proxy_types;

fn serialize_cbor(val: ciborium::value::Value) -> ByteBuf {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&val, &mut buf).expect("Cannot serialize CBOR");
    ByteBuf::from(buf)
}
