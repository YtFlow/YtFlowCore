#[cfg(windows)]
fn windows_main() {
    windows::core::build!(
        Windows::Foundation::EventRegistrationToken,
        Windows::Networking::Connectivity::*,
        Windows::Security::Cryptography::Certificates::{Certificate, CertificateStores, CertificateQuery},
        Windows::Storage::{ApplicationData, StorageFolder},
        Windows::Storage::Streams::IBuffer,
        Windows::Win32::System::WinRT::IBufferByteAccess,
    );
}

fn main() {
    #[cfg(windows)]
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        windows_main();
    }
}
