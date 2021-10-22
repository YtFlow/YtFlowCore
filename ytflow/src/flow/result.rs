use thiserror::Error;

#[derive(Debug, Error)]
pub enum FlowError {
    #[error("IO Error")]
    Io(#[from] std::io::Error),
    #[error("End of stream")]
    Eof,
    #[error("Unexpected data received")]
    UnexpectedData,
    #[error("Cannot find a matching outbound")]
    NoOutbound,
}

pub type FlowResult<T> = Result<T, FlowError>;
