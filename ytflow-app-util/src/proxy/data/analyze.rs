use thiserror::Error;

use crate::proxy::Proxy;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AnalyzeError {
    #[error("unknown proxy version")]
    UnknownVersion,
    #[error("invalid JSON, proxy or plugin format")]
    InvalidEncoding,
    #[error(r#"duplicated plugin name "{0}""#)]
    DuplicateName(String),
    #[error(r#"plugin "{0}" required by "{1}" not found"#)]
    PluginNotFound(String, String),
    #[error(r#"unknown access point: "{0}""#)]
    UnknownAccessPoint(String),
    #[error(r#"expect plugin "{0}" to have a UDP access point = {1}, but it does not"#)]
    UnexpectedUdpAccessPoint(String, bool),
    #[error("too complicated")]
    TooComplicated,
    #[error(r#"invalid plugin: "{0}""#)]
    InvalidPlugin(String),
    #[error(r#"unused plugin: "{0}""#)]
    UnusedPlugin(String),
}

pub type AnalyzeResult<T> = Result<T, AnalyzeError>;

pub fn analyze_data_proxy(name: String, proxy: &[u8], version: u16) -> AnalyzeResult<Proxy> {
    if version != 0 {
        return Err(AnalyzeError::UnknownVersion);
    }
    super::v1::analyzer::analyze(name, proxy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_data_proxy_invalid_version() {
        let result = analyze_data_proxy("test".into(), &[], 1);
        assert_eq!(result, Err(AnalyzeError::UnknownVersion));
    }
}
