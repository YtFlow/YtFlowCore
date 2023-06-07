mod initial_data_extract_stream;
#[cfg(windows)]
mod load_certs_windows;
mod stream;

pub use stream::SslStreamFactory;
