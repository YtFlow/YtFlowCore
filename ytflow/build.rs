#[cfg(windows)]
fn windows_main() {
    windows::core::build!(
        Windows::Foundation::EventRegistrationToken,
        Windows::Networking::Connectivity::*,
        Windows::Storage::{ApplicationData, StorageFolder},
    );
}

fn main() {
    #[cfg(windows)]
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        windows_main();
    }
}
