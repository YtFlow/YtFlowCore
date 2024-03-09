use crate::proxy::Proxy;

pub enum AnalyzeError {}

pub type AnalyzeResult<T> = Result<T, AnalyzeError>;

pub fn analyze_data_proxy(name: String, proxy: &[u8]) -> AnalyzeResult<Proxy> {
    todo!()
}
