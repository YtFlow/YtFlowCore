use serde::Deserialize;

use super::{ConfigError, ConfigResult};

pub(super) fn parse_param<'de, T: Deserialize<'de>, D: AsRef<[u8]> + 'de>(
    plugin_name: &str,
    data: &'de D,
) -> ConfigResult<T> {
    // TODO: Extract detailed error to identify the fields that contain error
    cbor4ii::serde::from_slice(data.as_ref())
        .map_err(|e| ConfigError::ParseParam(plugin_name.to_string(), e))
}
