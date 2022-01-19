pub struct ConnectError(pub String);

impl From<&'_ str> for ConnectError {
    fn from(error: &str) -> Self {
        ConnectError(error.into())
    }
}
impl From<String> for ConnectError {
    fn from(error: String) -> Self {
        ConnectError(error)
    }
}

impl From<windows::core::Error> for ConnectError {
    fn from(error: windows::core::Error) -> Self {
        ConnectError(format!("{}", error))
    }
}
