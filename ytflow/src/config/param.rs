use std::io::Cursor;

use serde::Deserialize;

pub(super) fn parse_param<'de, T: Deserialize<'de>, D: AsRef<[u8]>>(data: D) -> Option<T> {
    ciborium::de::from_reader(Cursor::new(data)).ok()
}
